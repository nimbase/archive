import std/[unittest, tables, strutils, options]
import archive/types
import archive/io
import archive/files
import archive/formats/sevenz
import archive/registry
import archive

const szCases = "tests/testdata/7z/"

proc szReadAllFrom(data: string; z: Sz;
    ctx: ArchiveContext): OrderedTable[string, string] =
  var bodies = initOrderedTable[string, string]()
  extractSz(z, ctx, openInputString(data)) do (
      c: ArchiveContext; info: FileInfo):
    if info.isRegular():
      bodies[info.nameInArchive] = readAll(info.open())
  bodies

proc szReadAll(path: string; z: Sz; ctx: ArchiveContext):
    OrderedTable[string, string] =
  szReadAllFrom(readFile(path), z, ctx)

suite "7z store":
  test "round trip regular files dirs and symlinks":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "dir", meta: FileMeta(name: "dir", isDir: true),
        data: ""),
      FsEntry(path: "dir/a.txt", meta: FileMeta(name: "a.txt",
        size: 5, isRegular: true), data: "hello"),
      FsEntry(path: "top.txt", meta: FileMeta(name: "top.txt",
        size: 5, isRegular: true), data: "world"),
      FsEntry(path: "empty.txt", meta: FileMeta(name: "empty.txt",
        size: 0, isRegular: true), data: ""),
      FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
        isSymlink: true), data: "", linkTarget: "top.txt"),
    ], ".", "")
    let dst = newOutput()
    archiveSz(Sz(), ctx, dst, files)
    let blob = take(dst)
    check blob.len > 0
    var bodies = initOrderedTable[string, string]()
    var links = initOrderedTable[string, string]()
    var dirs: seq[string] = @[]
    extractSz(Sz(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isDir():
        dirs.add(info.nameInArchive)
      elif info.isSymlink():
        links[info.nameInArchive] = info.linkTarget
      elif info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check bodies["dir/a.txt"] == "hello"
    check bodies["top.txt"] == "world"
    check bodies["empty.txt"] == ""
    check links["link.txt"] == "top.txt"
    check "dir/" in dirs

  test "empty archive round trips":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [], ".", "")
    let dst = newOutput()
    archiveSz(Sz(), ctx, dst, files)
    let blob = take(dst)
    var count = 0
    extractSz(Sz(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      inc count
    check count == 0

  test "identify by name and stream":
    check identifyFormat("a.7z", nil).archival == some(af7z)
    let data = readFile(szCases & "store_plain.7z")
    let res = identifyFormat("a.7z", openInputString(data))
    check res.archival == some(af7z)

  test "store fixture extracts byte identical":
    var ctx: ArchiveContext
    let bodies = szReadAll(szCases & "store_plain.7z", Sz(), ctx)
    check bodies["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    check bodies["sources/random.bin"] ==
      readFile(szCases & "sources/random.bin")

  test "empty fixture walks dirs only":
    var ctx: ArchiveContext
    let data = readFile(szCases & "empty_plain.7z")
    var dirs: seq[string] = @[]
    var count = 0
    extractSz(Sz(), ctx, openInputString(data)) do (
        c: ArchiveContext; info: FileInfo):
      inc count
      if info.isDir():
        dirs.add(info.nameInArchive)
    check count == 2
    check "sources/emptydir/" in dirs
    check "sources/emptydir2/" in dirs

  test "multi-folder fixture walks in order":
    var ctx: ArchiveContext
    let data = readFile(szCases & "solid-1k_plain.7z")
    var names: seq[string] = @[]
    extractSz(Sz(), ctx, openInputString(data)) do (
        c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check names.len == 8
    check names[0] == "sources/docs/"
    check names[1] == "sources/docs/f0.txt"
    check names[7] == "sources/lorem.txt"
    # Content needs the LZMA phase: opening fails explicitly.
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except SzError as e:
      failed = "unsupported" in e.msg
    check failed

  test "corrupt pack byte fails crc":
    var ctx: ArchiveContext
    var data = readFile(szCases & "store_plain.7z")
    data[40] = chr(ord(data[40]) xor 0xFF)
    var failed = false
    try:
      discard szReadAllFrom(data, Sz(), ctx)
    except SzError:
      failed = true
    check failed

suite "7z unsupported and encrypted":
  test "lzma fixture lists but needs decoder on open":
    var ctx: ArchiveContext
    let data = readFile(szCases & "lzma2-solid_plain.7z")
    var count = 0
    extractSz(Sz(), ctx, openInputString(data)) do (
        c: ArchiveContext; info: FileInfo):
      inc count
    check count == 8
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except SzError as e:
      failed = "unsupported" in e.msg
    check failed

  test "delta and bcj fixtures list but need decoder on open":
    var ctx: ArchiveContext
    for f in ["delta.7z", "bcj.7z", "bcj2.7z", "ppmd.7z"]:
      let data = readFile(szCases & f)
      var count = 0
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        inc count
      check count > 0
      var failed = false
      try:
        extractSz(Sz(), ctx, openInputString(data)) do (
            c: ArchiveContext; info: FileInfo):
          if info.isRegular():
            discard readAll(info.open())
      except SzError as e:
        failed = "unsupported" in e.msg
      check failed

  test "packed headers refuse cleanly":
    var ctx: ArchiveContext
    let data = readFile(szCases & "store.7z")
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        discard
    except SzError as e:
      failed = "packed header" in e.msg
    check failed

  test "aes fixture lists but needs password on open":
    var ctx: ArchiveContext
    let data = readFile(szCases & "aes_plainhdr.7z")
    var count = 0
    extractSz(Sz(), ctx, openInputString(data)) do (
        c: ArchiveContext; info: FileInfo):
      inc count
    check count == 2
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except SzError as e:
      failed = "password" in e.msg
    check failed
    # With a password the walk still works; content waits for AES.
    var pwCount = 0
    extractSz(Sz(password: "password"), ctx,
        openInputString(data)) do (
        c: ArchiveContext; info: FileInfo):
      inc pwCount
    check pwCount == 2
    failed = false
    try:
      extractSz(Sz(password: "password"), ctx,
          openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except SzError as e:
      failed = "AES" in e.msg
    check failed

  test "header-encrypted fixture refuses cleanly":
    var ctx: ArchiveContext
    let data = readFile(szCases & "aes_hdr.7z")
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        discard
    except SzError as e:
      failed = "packed header" in e.msg or "password" in e.msg
    check failed

suite "7z registry":
  test "archive and extract through dispatch":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "t.txt", meta: FileMeta(name: "t.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveFormat(af7z, ctx, dst, files)
    var back = ""
    extractFormat(af7z, ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        back = readAll(info.open())
    check back == "abc"
