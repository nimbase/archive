import std/[unittest, strutils, options, tables]
from std/os import getTempDir, joinPath, createDir, getFileSize, removeFile,
  removeDir
import archive/types
import archive/io
import archive/registry
import archive/files
import archive
import archive/bz2f
import archive/formats/tar
import archive/formats/zip
import archive/formats/gz
import archive/formats/zlib
import archive/formats/lz4
import archive/formats/bz2
import archive/formats/brotli

registerTar()
registerZip()
registerGz()
registerZlib()
registerLz4()
registerBz2()
registerBrotli()

suite "enum registry":
  test "handler by enum matches handler by string":
    for fmt in [fmtTar, fmtZip, fmtGz, fmtZlib, fmtLz4, fmtBz2, fmtBrotli]:
      check(handler(fmt) == handlerFor(formatExt[fmt]))
      check(handler(fmt).ext == formatExt[fmt])
      check(handler(fmt).mediaType == formatMediaType[fmt])
      check(handler(fmt).kinds == formatKinds[fmt])

  test "tables are canonical":
    check(formatExt[fmtTar] == ".tar")
    check(formatExt[fmtZlib] == ".zz")
    check(formatMediaType[fmtGz] == "application/gzip")
    check(fkCompression in formatKinds[fmtBz2])
    check(formatKinds[fmtTar] == {fkArchival, fkExtraction})

  test "formatForExt normalizes":
    check(formatForExt(".GZ") == fmtGz)
    check(formatForExt("tar") == fmtTar)
    check(formatForExt(".bz2") == fmtBz2)

  test "unknown lookups raise":
    expect(ArchiveError):
      discard handlerFor(".nope")
    expect(ArchiveError):
      discard formatForExt(".nope")

  test "compressedArchive validates kinds":
    let ca = compressedArchive(fmtTar, fmtGz)
    check(ca.extension == ".tar.gz")
    expect(ArchiveError):
      discard compressedArchive(fmtGz, fmtGz)
    expect(ArchiveError):
      discard compressedArchive(fmtTar, fmtTar)

suite "high-level api":
  test "compress round trip per format":
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    for fmt in [fmtGz, fmtZlib, fmtLz4, fmtBz2, fmtBrotli]:
      check(decompress(fmt, compress(fmt, payload)) == payload)

  test "compress honors level":
    check(compress(fmtGz, "hello", 1)[0 .. 1] == "\x1f\x8b")
    check(compress(fmtBz2, "hello", 9)[0 .. 3] == "BZh9")
    expect(Bz2Error):
      discard compress(fmtBz2, "x", 10)

  test "compress rejects archival formats":
    expect(ArchiveError):
      discard compress(fmtTar, "x")
    expect(ArchiveError):
      discard decompress(fmtZip, "x")

  test "file round trip":
    let dir = getTempDir()
    for fmt in [fmtGz, fmtZlib, fmtLz4, fmtBz2, fmtBrotli]:
      let src = joinPath(dir, "api_src.txt")
      let enc = joinPath(dir, "api_enc" & formatExt[fmt])
      let back = joinPath(dir, "api_back.txt")
      writeFile(src, "file payload ".repeat(50))
      compressFile(fmt, src, enc)
      check(getFileSize(enc) > 0)
      decompressFile(fmt, enc, back)
      check(readFile(back) == "file payload ".repeat(50))

  test "archiveDir and extractAll round trip":
    let dir = joinPath(getTempDir(), "api_tree")
    removeDir(dir) # stale outputs from older test revisions
    createDir(joinPath(dir, "sub"))
    writeFile(joinPath(dir, "a.txt"), "alpha")
    writeFile(joinPath(dir, "sub", "b.txt"), "beta")
    removeFile(joinPath(getTempDir(), "api_out.tar.gz"))
    let blob = joinPath(getTempDir(), "api_out.tar.gz")
    var ctx: ArchiveContext
    archiveDir(fmtTar, dir, blob, "root", compression = some(fmtGz))
    let entries = extractAll(blob, ctx)
    check(entries.len == 2)
    let names = listEntries(blob, ctx)
    check(names.len >= 2) # + directory entries
    check("root/a.txt" in names)
    check("root/sub/b.txt" in names)

  test "archiveData without compression":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "x.txt", meta: FileMeta(name: "x.txt", size: 1,
        isRegular: true), data: "x"),
    ], ".", "")
    let blob = archiveData(fmtTar, files, ctx)
    check(blob.len > 0)
    let back = archiveData(fmtTar, files, ctx, some(fmtBz2))
    check(back[0 .. 3] == "BZh6")

  test "extractFile dispatches identify":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "n.txt", meta: FileMeta(name: "n.txt", size: 4,
        isRegular: true), data: "note"),
    ], ".", "")
    let path = joinPath(getTempDir(), "api_extract.tar")
    archiveToFile(fmtTar, files, path, ctx)
    var bodies = initOrderedTable[string, string]()
    extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open()), ctx)
    check(bodies["n.txt"] == "note")

  test "extractFile rejects compression-only":
    let dir = getTempDir()
    let src = joinPath(dir, "api_plain.txt")
    let path = joinPath(dir, "api_only.gz")
    writeFile(src, "just some bytes")
    compressFile(fmtGz, src, path)
    expect(ArchiveError):
      var ctx: ArchiveContext
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
        discard, ctx)
