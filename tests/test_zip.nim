import std/[unittest, tables, strutils]
import buffalo
from std/os import getTempDir, joinPath, removeDir, removeFile
import archive
import archive/types
import archive/io
import archive/files
import archive/flate
import archive/crc32
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

  test "reads data-descriptor fixture (streaming writers)":
    # produced by a non-seekable zipfile stream: local sizes/CRC are
    # zeroed with a trailing descriptor, so only the central directory
    # carries true values. Mirrors macOS Archive Utility output.
    discard zipOpts()  # opts value; dispatch is static
    let inp = openInputFile("tests/testdata/datadesc.zip")
    var ctx: ArchiveContext
    var bodies = initOrderedTable[string, string]()
    extractZip(zipOpts(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check(bodies["hello.txt"] == "Hello, data descriptors! ".repeat(40))
    check(bodies["dir/nested.bin"].len == 5000)
    check(bodies["dir/nested.bin"][0] == '\0')
    check(bodies["dir/nested.bin"][1] == chr(37))

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

  test "extractFile to directory streams stored and deflated zips":
    # Plain zips take the bounded streaming fast path
    # (extractZipToDirStreaming): pooled 64KB chunk + 96KB window,
    # no per-entry allocation. Both methods must round-trip.
    var ctx: ArchiveContext
    var lorem = newString(120_000)
    const phrase = "lorem ipsum dolor sit amet. "
    for i in 0 ..< lorem.len:
      lorem[i] = phrase[i mod phrase.len]
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt",
        size: lorem.len, isRegular: true), data: lorem),
    ], ".", "")
    for (tag, z) in [("store", Zip()), ("deflate", Zip(compression: 8))]:
      let blob = newOutput()
      archiveZip(z, ctx, blob, files)
      let src = joinPath(getTempDir(), "zip_stream_" & tag & ".zip")
      writeFile(src, take(blob))
      let outd = joinPath(getTempDir(), "zip_stream_" & tag & "_out")
      removeDir(outd)
      extractFile(src, outd)
      check(readFile(joinPath(outd, "a.txt")) == "hello")
      check(readFile(joinPath(outd, "big.txt")) == lorem)
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "pooled io helpers stage spans without allocation":
    # Foundation for reuse in hot loops: spans stage into a caller-owned
    # pool (no string alloc), and `toOpenArray()` feeds `writeOpenArray`
    # as an immediate arg inside `withBorrow` (the borrow-safe pattern).
    var pool = initPool(byte, 64, 1024)
    let inp = openInputString("hello world")
    check(readSpanIntoPooled(inp, pool, 5) == 5)
    check(pool.toString() == "hello")
    check(readSpanIntoPooled(inp, pool, 6) == 6)
    check(pool.toString() == " world")
    let dst = newOutput()
    dst.writeOpenArray(pool.toOpenArray())
    check(take(dst) == " world")
    check(pool.cap == 64) # small staging never grew the pool
    # The borrow-to-fill pattern: `toOpenArray()` as an immediate arg
    # inside `withBorrow` (allowed by the escape rules), copied out at
    # once so nothing escapes the scope.
    var fill = initPool(byte, 64, 1024)
    let dst2 = newOutput()
    withBorrow(fill, b):
      b.copyFrom(" world")
      dst2.writeOpenArray(b.toOpenArray())
    check(take(dst2) == " world")

  test "pooled stored streaming matches string version":
    var data = newString(200_000)
    for i in 0 ..< data.len:
      data[i] = chr(i and 0xFF)
    let src = joinPath(getTempDir(), "zip_pool_src.bin")
    let dstA = joinPath(getTempDir(), "zip_pool_a.bin")
    let dstB = joinPath(getTempDir(), "zip_pool_b.bin")
    writeFile(src, data)
    let crc = crc32Checksum(data)
    var rf = open(src, fmRead)
    var wf = open(dstA, fmWrite)
    var sbuf = newString(0)
    try:
      streamStoredRangeToFile(rf, wf, sbuf, data.len, data.len, crc, "t")
    finally:
      close(rf)
      close(wf)
    var pool = initPool(byte, StreamChunkSize, MaxScratchCap)
    rf = open(src, fmRead)
    wf = open(dstB, fmWrite)
    try:
      streamStoredRangeToFilePooled(rf, wf, pool, data.len, data.len,
        crc, "t")
    finally:
      close(rf)
      close(wf)
    check(readFile(dstA) == data)
    check(readFile(dstB) == data)
    check(pool.cap == StreamChunkSize) # reused, never grew
    try: removeFile(src) except OSError: discard
    try: removeFile(dstA) except OSError: discard
    try: removeFile(dstB) except OSError: discard

  test "pooled inflate range matches string version":
    var data = newString(300_000)
    for i in 0 ..< data.len:
      data[i] = chr((i div 7) and 0xFF)
    let comp = deflateFixed(data)
    check(comp.len > 0)
    check(comp.len < data.len)
    let src = joinPath(getTempDir(), "zip_pool_def.bin")
    let dstA = joinPath(getTempDir(), "zip_pool_def_a.bin")
    let dstB = joinPath(getTempDir(), "zip_pool_def_b.bin")
    writeFile(src, comp)
    let wantCrc = crc32Checksum(data)
    var rf = open(src, fmRead)
    var wf = open(dstA, fmWrite)
    let scratchA = newOutput(StreamBufCap)
    var sbuf = newString(0)
    var resA: tuple[bytes: int, crc: uint32]
    try:
      resA = inflateFileRange(rf, comp.len, wf, scratchA, sbuf)
    finally:
      close(rf)
      close(wf)
    var pool = initPool(byte, StreamChunkSize, MaxScratchCap)
    rf = open(src, fmRead)
    wf = open(dstB, fmWrite)
    let scratchB = newOutput(StreamBufCap)
    var resB: tuple[bytes: int, crc: uint32]
    try:
      resB = inflateFileRangePooled(rf, comp.len, wf, scratchB, pool)
    finally:
      close(rf)
      close(wf)
    check(resA == resB)
    check(resA.bytes == data.len)
    check(resA.crc == wantCrc)
    check(readFile(dstA) == data)
    check(readFile(dstB) == data)
    check(pool.cap == StreamChunkSize) # reused, never grew
    try: removeFile(src) except OSError: discard
    try: removeFile(dstA) except OSError: discard
    try: removeFile(dstB) except OSError: discard
