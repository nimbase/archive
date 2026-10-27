import std/[unittest, tables]
import archive/types
import archive/io
import archive/files
import archive/formats/zip


proc zipOpts(): Zip =
  Zip()

suite "zip":
  test "round trip files":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "sub/b.txt", meta: FileMeta(name: "b.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    discard zipOpts()  # opts value; dispatch is static
    let dst = newOutput()
    archiveZip(zipOpts(), ctx, dst, files)
    check(outputBytes(dst).len > 0)
    var bodies = initOrderedTable[string, string]()
    extractZip(zipOpts(), ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["a.txt"] == "hello")
    check(bodies["sub/b.txt"] == "world")

  test "reads reference test.zip":
    discard zipOpts()  # opts value; dispatch is static
    let inp = openInputFile("tests/testdata/test.zip")
    var ctx: ArchiveContext
    var names: seq[string] = @[]
    extractZip(zipOpts(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check(names.len > 0)

  test "reads reference unordered.zip fully":
    discard zipOpts()  # opts value; dispatch is static
    let inp = openInputFile("tests/testdata/unordered.zip")
    var ctx: ArchiveContext
    var count = 0
    extractZip(zipOpts(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      inc count
      check(info.nameInArchive.len > 0)
    check(count > 0)

  test "reads reference symlinks.zip":
    discard zipOpts()  # opts value; dispatch is static
    let inp = openInputFile("tests/testdata/symlinks.zip")
    var ctx: ArchiveContext
    var count = 0
    extractZip(zipOpts(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      inc count
    check(count > 0)

  test "reads system zip fixture":
    discard zipOpts()  # opts value; dispatch is static
    let inp = openInputFile("tests/testdata/interop.zip")
    let want = openInputFile("tests/testdata/interop.txt")
    var ctx: ArchiveContext
    var bodies = initOrderedTable[string, string]()
    extractZip(zipOpts(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["interop.txt"] == readAll(want))

  test "insert replaces entries":
    var ctx: ArchiveContext
    discard zipOpts()  # opts value; dispatch is static
    let first = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 1,
        isRegular: true), data: "1"),
      FsEntry(path: "keep.txt", meta: FileMeta(name: "keep.txt", size: 1,
        isRegular: true), data: "k"),
    ], ".", "")
    let blob = newOutput()
    archiveZip(zipOpts(), ctx, blob, first)
    let extra = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 1,
        isRegular: true), data: "2"),
    ], ".", "")
    var z = Zip()
    let merged = newOutput()
    z.insertZip(ctx, toInput(blob), merged, extra)
    var bodies = initOrderedTable[string, string]()
    extractZip(zipOpts(), ctx, toInput(merged)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["a.txt"] == "2")
    check(bodies["keep.txt"] == "k")
