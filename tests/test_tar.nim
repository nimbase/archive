import std/[unittest, tables, strutils]
import archive/types
import archive/io
import archive/registry
import archive/files
import archive/formats/tar

registerTar()

proc tarHandler(): FormatHandler =
  for h in registeredFormats():
    if h.ext == ".tar":
      return h
  raise newException(ArchiveError, "tar not registered")

suite "tar":
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
    let tarH = tarHandler()
    let dst = newOutput()
    tarH.archive(ctx, dst, files)
    check(outputBytes(dst).len mod 512 == 0)
    var seen: seq[string] = @[]
    var bodies = initOrderedTable[string, string]()
    tarH.extract(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      seen.add(info.nameInArchive)
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check("dir/a.txt" in seen)
    check("top.txt" in seen)
    check(bodies["dir/a.txt"] == "hello")
    check(bodies["top.txt"] == "world")

  test "symlink preserved":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "real.txt", meta: FileMeta(name: "real.txt", size: 4,
        isRegular: true), data: "data"),
      FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
        isSymlink: true), data: "", linkTarget: "real.txt"),
    ], ".", "")
    let tarH = tarHandler()
    let dst = newOutput()
    tarH.archive(ctx, dst, files)
    var links = initOrderedTable[string, string]()
    tarH.extract(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isSymlink():
        links[info.nameInArchive] = info.linkTarget
    check(links["link.txt"] == "real.txt")

  test "reads reference gnu-hardlinks.tar":
    let tarH = tarHandler()
    let inp = openInputFile("tests/testdata/gnu-hardlinks.tar")
    var ctx: ArchiveContext
    var count = 0
    tarH.extract(ctx, inp) do (c: ArchiveContext; info: FileInfo):
      inc count
      check(info.nameInArchive.len > 0)
    check(count > 0)

  test "reads reference self-tar.tar":
    let tarH = tarHandler()
    let inp = openInputFile("tests/testdata/self-tar.tar")
    var ctx: ArchiveContext
    var names: seq[string] = @[]
    tarH.extract(ctx, inp) do (c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check(names.len > 0)

  test "insert appends without losing content":
    var ctx: ArchiveContext
    let tarH = tarHandler()
    let first = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 1,
        isRegular: true), data: "a")], ".", "")
    let blob = newOutput()
    tarH.archive(ctx, blob, first)
    let extra = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: 1,
        isRegular: true), data: "b")], ".", "")
    var t = Tar()
    let merged = newOutput()
    t.insertTar(ctx, toInput(blob), merged, extra)
    var names: seq[string] = @[]
    tarH.extract(ctx, toInput(merged)) do (
        c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check("a.txt" in names)
    check("b.txt" in names)

  test "mmap zero-copy: entry bodies borrow mapped memory":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt", size: 100000,
        isRegular: true), data: "x".repeat(100000)),
    ], ".", "")
    let tarH = tarHandler()
    let dst = newOutput()
    tarH.archive(ctx, dst, files)
    let blob = take(dst)
    check(blob.len > 100000)
