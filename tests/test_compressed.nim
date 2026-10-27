import std/[unittest, tables]
import archive/types
import archive/io
import archive/registry
import archive/files
import archive
import archive/formats/tar
import archive/formats/gz
import archive/formats/lz4
import archive/formats/bz2
import archive/formats/brotli

registerTar()
registerGz()
registerLz4()
registerBz2()
registerBrotli()


proc sampleFiles(ctx: ArchiveContext): seq[FileInfo] =
  filesFromEntries(ctx, FromFSOptions(), [
    FsEntry(path: "docs/readme.txt", meta: FileMeta(name: "readme.txt",
      size: 13, isRegular: true), data: "hello archive"),
    FsEntry(path: "bin/run", meta: FileMeta(name: "run", size: 6,
      isRegular: true), data: "binary"),
  ], ".", "")

suite "compressed archives":
  test "tar.gz round trip via CompressedArchive":
    var ctx: ArchiveContext
    let files = sampleFiles(ctx)
    let ca = compressedArchive(fmtTar, fmtGz)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    check(outputBytes(dst).len > 0)
    var bodies = initOrderedTable[string, string]()
    ca.extractFrom(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["docs/readme.txt"] == "hello archive")
    check(bodies["bin/run"] == "binary")

  test "tar.br round trip via CompressedArchive":
    var ctx: ArchiveContext
    let files = sampleFiles(ctx)
    let ca = compressedArchive(fmtTar, fmtBrotli)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    check(outputBytes(dst).len > 0)
    var bodies = initOrderedTable[string, string]()
    ca.extractFrom(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["docs/readme.txt"] == "hello archive")
    check(bodies["bin/run"] == "binary")

  test "identify tar.br by filename and stream":
    var ctx: ArchiveContext
    let files = sampleFiles(ctx)
    let ca = compressedArchive(fmtTar, fmtBrotli)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    let res = identifyFormat("backup.tar.br", toInput(dst))
    check(res.compressed != nil)
    check(res.compressed.compression.ext == ".br")
    check(res.compressed.extraction.ext == ".tar")
    let bare = identifyFormat("backup.tar.br", openInputString("x"))
    # Filename alone matches both layers (Go parity: name matches count
    # even when the stream is garbage).
    check(bare.compressed != nil)
    check(bare.compressed.compression.ext == ".br")

  test "tar.lz4 round trip via CompressedArchive":
    var ctx: ArchiveContext
    let files = sampleFiles(ctx)
    let ca = compressedArchive(fmtTar, fmtLz4)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    check(outputBytes(dst).len > 0)
    let res = identifyFormat("backup.tar.lz4", toInput(dst))
    check(res.compressed != nil)
    check(res.compressed.compression.ext == ".lz4")
    check(res.compressed.extraction.ext == ".tar")
    var bodies = initOrderedTable[string, string]()
    ca.extractFrom(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["docs/readme.txt"] == "hello archive")
    check(bodies["bin/run"] == "binary")

  test "tar.bz2 round trip via CompressedArchive":
    var ctx: ArchiveContext
    let files = sampleFiles(ctx)
    let ca = compressedArchive(fmtTar, fmtBz2)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    check(outputBytes(dst).len > 0)
    let res = identifyFormat("backup.tar.bz2", toInput(dst))
    check(res.compressed != nil)
    check(res.compressed.compression.ext == ".bz2")
    check(res.compressed.extraction.ext == ".tar")
    var bodies = initOrderedTable[string, string]()
    ca.extractFrom(ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["docs/readme.txt"] == "hello archive")
    check(bodies["bin/run"] == "binary")
