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

  test "multi-folder fixture extracts byte identical":
    var ctx: ArchiveContext
    let bodies = szReadAll(szCases & "solid-1k_plain.7z", Sz(), ctx)
    check bodies["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    for i in 0 ..< 6:
      check bodies["sources/docs/f" & $i & ".txt"] ==
        readFile(szCases & "sources/docs/f" & $i & ".txt")

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

suite "7z lzma/lzma2":
  test "lzma2 solid extracts byte identical":
    var ctx: ArchiveContext
    let bodies = szReadAll(szCases & "lzma2-solid_plain.7z", Sz(), ctx)
    check bodies["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    for i in 0 ..< 6:
      check bodies["sources/docs/f" & $i & ".txt"] ==
        readFile(szCases & "sources/docs/f" & $i & ".txt")

  test "packed headers extract byte identical":
    var ctx: ArchiveContext
    for f in ["store.7z", "lzma2-solid.7z", "solid-1k.7z",
        "lzma-nosolid.7z", "lzma-solid.7z"]:
      let bodies = szReadAll(szCases & f, Sz(), ctx)
      check bodies.len > 0
    let s = szReadAll(szCases & "store.7z", Sz(), ctx)
    check s["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    check s["sources/random.bin"] ==
      readFile(szCases & "sources/random.bin")
    let lz = szReadAll(szCases & "lzma2-solid.7z", Sz(), ctx)
    check lz["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    for i in 0 ..< 6:
      check lz["sources/docs/f" & $i & ".txt"] ==
        readFile(szCases & "sources/docs/f" & $i & ".txt")

  test "delta and bcj extract byte identical":
    var ctx: ArchiveContext
    let dd = szReadAll(szCases & "delta.7z", Sz(), ctx)
    check dd["sources/random.bin"] ==
      readFile(szCases & "sources/random.bin")
    let bb = szReadAll(szCases & "bcj.7z", Sz(), ctx)
    check bb["sources/x86.bin"] ==
      readFile(szCases & "sources/x86.bin")

  test "bcj2 and ppmd refuse cleanly":
    var ctx: ArchiveContext
    for f in ["bcj2.7z", "ppmd.7z"]:
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

suite "7z encrypted":
  test "aes content decrypts with password":
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
    let bodies = szReadAll(szCases & "aes_plainhdr.7z",
      Sz(password: "password"), ctx)
    check bodies["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    check bodies["sources/docs/f0.txt"] ==
      readFile(szCases & "sources/docs/f0.txt")
    let packed = szReadAll(szCases & "aes.7z",
      Sz(password: "password"), ctx)
    check packed["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")

  test "header-encrypted needs password then decrypts":
    var ctx: ArchiveContext
    let data = readFile(szCases & "aes_hdr.7z")
    var failed = false
    try:
      extractSz(Sz(), ctx, openInputString(data)) do (
          c: ArchiveContext; info: FileInfo):
        discard
    except SzError as e:
      failed = "password" in e.msg
    check failed
    let bodies = szReadAll(szCases & "aes_hdr.7z",
      Sz(password: "password"), ctx)
    check bodies["sources/lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    for i in 0 ..< 6:
      check bodies["sources/docs/f" & $i & ".txt"] ==
        readFile(szCases & "sources/docs/f" & $i & ".txt")

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

suite "7z lzma2-solid write":
  test "round trip files dirs symlinks and empty":
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
      FsEntry(path: "lorem.txt", meta: FileMeta(name: "lorem.txt",
        size: 11400, isRegular: true),
        data: readFile(szCases & "sources/lorem.txt")),
    ], ".", "")
    let dst = newOutput()
    archiveSz(Sz(meth: 1), ctx, dst, files)
    let blob = take(dst)
    check blob.len > 0
    # solid must beat the raw total on repetitive text
    check blob.len < 11400 + 10
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
    check bodies["lorem.txt"] ==
      readFile(szCases & "sources/lorem.txt")
    check links["link.txt"] == "top.txt"
    check "dir/" in dirs

  test "incompressible data round trips":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "random.bin", meta: FileMeta(name: "random.bin",
        size: 6000, isRegular: true),
        data: readFile(szCases & "sources/random.bin")),
    ], ".", "")
    let dst = newOutput()
    archiveSz(Sz(meth: 1), ctx, dst, files)
    let bodies = szReadAllFrom(take(dst), Sz(), ctx)
    check bodies["random.bin"] ==
      readFile(szCases & "sources/random.bin")

  test "multi-chunk solid round trips":
    var ctx: ArchiveContext
    var big = ""
    for i in 0 ..< 50:
      big &= readFile(szCases & "sources/docs/f0.txt")
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt",
        size: big.len, isRegular: true), data: big),
    ], ".", "")
    let dst = newOutput()
    archiveSz(Sz(meth: 1), ctx, dst, files)
    let bodies = szReadAllFrom(take(dst), Sz(), ctx)
    check bodies["big.txt"] == big

  test "unknown write method refused":
    var ctx: ArchiveContext
    let dst = newOutput()
    var failed = false
    try:
      archiveSz(Sz(meth: 9), ctx, dst, @[])
    except SzError:
      failed = true
    check failed
