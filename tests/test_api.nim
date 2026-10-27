import std/[unittest, strutils, options, tables, sequtils]
from std/os import getTempDir, joinPath, createDir, getFileSize, removeFile,
  removeDir, dirExists, symlinkExists
import archive/types
import archive/io
import archive/registry
import archive/files
import archive
import archive/bz2f

suite "static format dispatch":
  test "enums carry their own extensions":
    check($afTar == ".tar")
    check($cfZlib == ".zz")
    check($cfBrotli == ".br")
    for fmt in CompressionFormat:
      check(($fmt).len > 1) # exhaustive iteration compiles
    for fmt in ArchiveFormat:
      check(($fmt).len > 1)

  test "media types derive from each enum":
    check(mediaTypeOf(cfGz) == mtGz)
    check($mediaTypeOf(cfBz2) == "application/x-bzip2")
    check(mediaTypeOf(afTar) == mtTar)
    check($mediaTypeOf(afZip) == "application/zip")

  test "extension lookups normalize":
    check(compressionForExt(".GZ") == cfGz)
    check(archiveForExt("tar") == afTar)
    check(compressionForExt(".bz2") == cfBz2)

  test "unknown extensions raise":
    expect(ArchiveError):
      discard compressionForExt(".nope")
    expect(ArchiveError):
      discard archiveForExt(".gz") # wrong side of the split

  test "pairs compose without validation calls":
    # types enforce valid combinations: no compressedArchive() needed,
    # and cross-type misuse cannot compile (see negative check below)
    let ca = CompressedArchive(archival: afTar, compression: cfGz)
    check(ca.extension == ".tar.gz")
    check($ca.mediaTypeOf() == "application/gzip")

  test "matchFormat agrees with identify":
    var ctx: ArchiveContext
    check(matchFormat(afTar, "x.tar", nil).byName)
    check(not matchFormat(afZip, "x.tar", nil).matched())

suite "high-level api":
  test "compress round trip per format":
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    for fmt in [cfGz, cfZlib, cfLz4, cfBz2, cfBrotli]:
      check(decompress(fmt, compress(fmt, payload)) == payload)

  test "compress honors level":
    check(compress(cfGz, "hello", 1)[0 .. 1] == "\x1f\x8b")
    check(compress(cfBz2, "hello", 9)[0 .. 3] == "BZh9")
    expect(Bz2Error):
      discard compress(cfBz2, "x", 10)

  # NOTE: compress(afTar, x) and decompress(afZip, x) do not compile:
  # archival and compression formats are distinct types. Verified by
  # hand (nim reports a type mismatch); it cannot be a runtime test.

  test "file round trip":
    let dir = getTempDir()
    for fmt in [cfGz, cfZlib, cfLz4, cfBz2, cfBrotli]:
      let src = joinPath(dir, "api_src.txt")
      let enc = joinPath(dir, "api_enc" & $fmt)
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
    archiveDir(afTar, dir, blob, "root", compression = some(cfGz))
    let entries = toSeq(extractAll(blob, ctx))
    check(entries.len == 2)
    let names = listEntries(blob, ctx)
    check(names.len >= 2) # + directory entries
    check("root/a.txt" in names)
    check("root/sub/b.txt" in names)

  test "archivePaths round trip from disk paths":
    let dir = joinPath(getTempDir(), "api_paths")
    removeDir(dir)
    createDir(joinPath(dir, "sub"))
    writeFile(joinPath(dir, "a.txt"), "alpha")
    writeFile(joinPath(dir, "sub", "b.txt"), "beta")
    var ctx: ArchiveContext
    # plain paths are stored as given (relative to cwd here)
    let blob = archivePaths(afTar, @[
      joinPath(dir, "a.txt"), joinPath(dir, "sub", "b.txt")], ctx)
    check(blob.len > 0)
    let tpath = joinPath(getTempDir(), "api_paths.tar")
    writeFile(tpath, blob)
    let names = listEntries(tpath, ctx)
    check(joinPath(dir, "a.txt") in names)
    check(joinPath(dir, "sub", "b.txt") in names)
    # explicit pairs rename entries on the way in, plus compression
    let renamed = archivePaths(afTar,
      @[(joinPath(dir, "a.txt"), "root/renamed.txt")], ctx,
      compression = some(cfGz))
    check(renamed[0 .. 1] == "\x1f\x8b")
    let rpath = joinPath(getTempDir(), "api_paths_renamed.tar.gz")
    writeFile(rpath, renamed)
    check(listEntries(rpath, ctx) == @["root/renamed.txt"])

  test "archivePaths missing path raises":
    var ctx: ArchiveContext
    expect(ArchiveError):
      discard archivePaths(afTar, @[joinPath(getTempDir(),
        "does-not-exist.txt")], ctx)

  test "archiveData without compression":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "x.txt", meta: FileMeta(name: "x.txt", size: 1,
        isRegular: true), data: "x"),
    ], ".", "")
    let blob = archiveData(afTar, files, ctx)
    check(blob.len > 0)
    let back = archiveData(afTar, files, ctx, some(cfBz2))
    check(back[0 .. 3] == "BZh6")

  test "progress reports entries on archive and extract":
    var ticks: seq[ProgressInfo] = @[]
    var ctx = ArchiveContext(progress: proc(info: ProgressInfo) =
      ticks.add(info))
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    let blob = archiveData(afTar, files, ctx)
    check(blob.len > 0)
    check(ticks.len == 2)
    check(ticks[0].path == "a.txt")
    check(ticks[0].index == 0)
    check(ticks[0].total == 2)
    check(ticks[0].size == 5)
    check(ticks[1].path == "b.txt")
    check(ticks[1].index == 1)
    ticks.setLen(0)
    let tpath = joinPath(getTempDir(), "api_progress.tar")
    writeFile(tpath, blob)
    for e in extractAll(tpath, ctx):
      discard e
    check(ticks.len == 2)
    check(ticks[0].path == "a.txt")
    check(ticks[0].total == -1) # streaming extract: total unknown
    check(ticks[1].index == 1)

  test "progress can abort via the cancelled flag":
    var stop = false
    var ctx = ArchiveContext(cancelled: addr stop,
      progress: proc(info: ProgressInfo) =
        stop = true) # abort from inside the callback
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    expect(ArchiveError):
      discard archiveData(afTar, files, ctx)

  test "extractFile dispatches identify":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "n.txt", meta: FileMeta(name: "n.txt", size: 4,
        isRegular: true), data: "note"),
    ], ".", "")
    let path = joinPath(getTempDir(), "api_extract.tar")
    archiveToFile(afTar, files, path, ctx)
    var bodies = initOrderedTable[string, string]()
    extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open()), ctx)
    check(bodies["n.txt"] == "note")

  test "extractFile to directory writes tree":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "sub", meta: FileMeta(name: "sub", isDir: true),
        data: ""),
      FsEntry(path: "sub/b.txt", meta: FileMeta(name: "b.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    let src = joinPath(getTempDir(), "api_todir.tar")
    archiveToFile(afTar, files, src, ctx)
    let dst = joinPath(getTempDir(), "api_todir_out")
    removeDir(dst)
    extractFile(src, dst)
    check(readFile(joinPath(dst, "a.txt")) == "hello")
    check(readFile(joinPath(dst, "sub", "b.txt")) == "world")
    check(dirExists(joinPath(dst, "sub")))

  test "safeDestPath rejects escapes":
    check(safeDestPath("out", "a/b.txt") ==
      joinPath("out", joinPath("a", "b.txt")))
    expect(ArchiveError):
      discard safeDestPath("out", "../evil.txt")
    expect(ArchiveError):
      discard safeDestPath("out", "/abs.txt")

  test "extractFile to directory rejects escaping entries":
    var ctx: ArchiveContext
    let evil = FileInfo(meta: FileMeta(name: "evil.txt", size: 1,
      isRegular: true), nameInArchive: "../evil.txt",
      open: stringOpener("x"))
    let src = joinPath(getTempDir(), "api_evil.tar")
    archiveToFile(afTar, @[evil], src, ctx)
    expect(ArchiveError):
      extractFile(src, joinPath(getTempDir(), "api_evil_out"))

  when not defined(windows):
    test "extractFile to directory recreates symlinks":
      var ctx: ArchiveContext
      let files = filesFromEntries(ctx, FromFSOptions(), [
        FsEntry(path: "real.txt", meta: FileMeta(name: "real.txt", size: 4,
          isRegular: true), data: "data"),
        FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
          isSymlink: true), data: "", linkTarget: "real.txt"),
      ], ".", "")
      let src = joinPath(getTempDir(), "api_link.tar")
      archiveToFile(afTar, files, src, ctx)
      let dst = joinPath(getTempDir(), "api_link_out")
      removeDir(dst)
      extractFile(src, dst)
      check(readFile(joinPath(dst, "real.txt")) == "data")
      check(symlinkExists(joinPath(dst, "link.txt")))

  test "extractFile rejects compression-only":
    let dir = getTempDir()
    let src = joinPath(dir, "api_plain.txt")
    let path = joinPath(dir, "api_only.gz")
    writeFile(src, "just some bytes")
    compressFile(cfGz, src, path)
    expect(ArchiveError):
      var ctx: ArchiveContext
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
        discard, ctx)
