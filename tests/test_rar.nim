import std/[unittest, tables, strutils, options]
from std/os import joinPath, getTempDir, removeFile
import archive/types
import archive/io
import archive/files
import archive/crc32
import archive/formats/rar
import archive/vfs
import archive

suite "rar5 store":
  test "round trip regular files and dirs":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "dir", meta: FileMeta(name: "dir", isDir: true),
        data: ""),
      FsEntry(path: "dir/a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "top.txt", meta: FileMeta(name: "top.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    let blob = take(dst)
    check blob.len > 8
    check blob[0 .. 7] == rar5Magic
    var seen: seq[string] = @[]
    var bodies = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      seen.add(info.nameInArchive)
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check("dir" in seen)
    check("dir/a.txt" in seen)
    check("top.txt" in seen)
    check(bodies["dir/a.txt"] == "hello")
    check(bodies["top.txt"] == "world")

  test "symlink round trip":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "real.txt", meta: FileMeta(name: "real.txt", size: 4,
        isRegular: true), data: "data"),
      FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
        isSymlink: true), data: "", linkTarget: "real.txt"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var links = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isSymlink():
        links[info.nameInArchive] = info.linkTarget
    check(links["link.txt"] == "real.txt")

  test "empty files and empty archive":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "empty.txt", meta: FileMeta(name: "empty.txt", size: 0,
        isRegular: true), data: ""),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var got = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        got[info.nameInArchive] = readAll(info.open())
    check(got["empty.txt"] == "")
    # empty archive lists nothing
    let dst2 = newOutput()
    archiveRar(Rar(), ctx, dst2, @[])
    var n = 0
    extractRar(Rar(), ctx, toInput(dst2)) do (
        c: ArchiveContext; info: FileInfo):
      inc n
    check n == 0

  test "high-level archiveData/extractFile":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "alpha"),
    ], ".", "")
    let blob = archiveData(afRar, files, ctx)
    let path = joinPath(getTempDir(), "nim_arc_rar_hl.rar")
    writeFile(path, blob)
    try:
      var names: seq[string] = @[]
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
        names.add(info.nameInArchive), ctx)
      check names == @["a.txt"]
      check listEntries(path) == @["a.txt"]
      for p, e in walkFs(path):
        check p == "a.txt"
    finally:
      removeFile(path)

  test "bad signature and truncation fail":
    var ctx: ArchiveContext
    expect(ArchiveError):
      extractRar(Rar(), ctx, openInputString("not a rar")) do (
          c: ArchiveContext; info: FileInfo):
        discard
    var ctx2: ArchiveContext
    let files = filesFromEntries(ctx2, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx2, dst, files)
    let blob = take(dst)
    expect(ArchiveError):
      extractRar(Rar(), ctx2,
        openInputString(blob[0 ..< blob.len div 2])) do (
          c: ArchiveContext; info: FileInfo):
        discard

  test "header crc mismatch fails":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var blob = take(dst)
    # corrupt a byte inside the first file header (past MARK+MAIN)
    blob[20] = chr(ord(blob[20]) xor 0xFF)
    expect(ArchiveError):
      extractRar(Rar(), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        discard

  test "unsupported method lists but fails on open":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var blob = take(dst)
    # Patch CompInfo method 0 -> 1 (m1). Value 128 needs a 2-byte vint
    # (0x80 0x01), so splice it in and grow the header size by one.
    let at = blob.find("a.txt")
    check at > 6
    let compPos = at - 3
    check ord(blob[compPos]) == 0
    blob = blob[0 ..< compPos] & "\x80\x01" & blob[compPos + 1 .. ^1]
    check ord(blob[20]) < 127 # hsize stays 1 byte
    blob[20] = chr(ord(blob[20]) + 1)
    # Recompute the file header CRC (header at offset 16: CRC + hsize + body).
    let fhCrcAt = 16
    var hsVal = 0'u64
    var hsLen = 0
    var shift = 0
    while true:
      let b = ord(blob[20 + hsLen]).uint64
      hsVal += (b and 0x7F) shl shift
      inc hsLen
      shift += 7
      if (b and 0x80) == 0: break
    let crcStart = 20
    let crcEnd = crcStart + hsLen + int(hsVal)
    var crc = crc32Update(0xFFFFFFFF'u32,
      unsafeAddr blob[crcStart], crcEnd - crcStart) xor 0xFFFFFFFF'u32
    blob[fhCrcAt] = chr(int(crc and 0xFF))
    blob[fhCrcAt + 1] = chr(int((crc shr 8) and 0xFF))
    blob[fhCrcAt + 2] = chr(int((crc shr 16) and 0xFF))
    blob[fhCrcAt + 3] = chr(int((crc shr 24) and 0xFF))
    # Walk lists the entry (meta available without decoding) ...
    var names: seq[string] = @[]
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check names == @["a.txt"]
    # ... but opening content fails with a clear method error.
    var opened = false
    try:
      extractRar(Rar(), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except ArchiveError as e:
      opened = true
      check "unsupported compression method" in e.msg
    check opened

  test "unpacked cap enforced on open":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt", size: 100,
        isRegular: true), data: "x".repeat(100)),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    let blob = take(dst)
    var ctxCap = ArchiveContext(maxRarUnpackedBytes: 10)
    expect(ArchiveError):
      extractRar(Rar(), ctxCap, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
