import std/[unittest, options, sequtils]
from std/os import getTempDir, joinPath, removeFile, removeDir
import archive/types
import archive/files
import archive

var doneChan {.global.}: Channel[bool]
  ## Cross-thread result pipe. The only shared state in the suite — and
  ## the point: nothing in the library needs anything like this.

proc payload(seed, n: int): string =
  ## Per-thread input built locally, so threads share no heap objects.
  result = newString(n)
  var x = (0x9E3779B9'u32 + seed.uint32 * 0x85EBCA6B'u32)
  for i in 0 ..< n:
    x = x * 1664525'u32 + 1013904223'u32
    result[i] = char((x shr 16) and 0x7F)

proc workCompress(seed: int) {.thread.} =
  var ok = true
  let data = payload(seed, 20000)
  for fmt in [cfGz, cfZlib, cfLz4, cfBz2]:
    if decompress(fmt, compress(fmt, data, level = 1)) != data:
      ok = false
  doneChan.send(ok)

proc workArchive(seed: int) {.thread.} =
  var ok = true
  try:
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "w" & $seed & ".txt", meta: FileMeta(
        name: "w" & $seed & ".txt", size: 20000, isRegular: true),
        data: payload(seed, 20000)),
    ], ".", "")
    let path = joinPath(getTempDir(), "threads_" & $seed & ".tar.gz")
    try:
      archiveFile(afTar, files, path, ctx, compression = some(cfGz))
      let back = toSeq(extractAll(path, ctx))
      if back.len != 1 or back[0].data != payload(seed, 20000):
        ok = false
      let outdir = joinPath(getTempDir(), "threads_dir_" & $seed)
      try:
        extractFile(path, outdir)
        if readFile(joinPath(outdir, "w" & $seed & ".txt")) !=
            payload(seed, 20000):
          ok = false
      finally:
        try: removeDir(outdir)
        except CatchableError: discard
    finally:
      try: removeFile(path)
      except CatchableError: discard
  except CatchableError:
    ok = false
  doneChan.send(ok)

suite "threads":
  test "parallel compress, archive and extract":
    doneChan.open()
    var workers: array[8, Thread[int]]
    for i in 0 ..< 4:
      createThread(workers[i], workCompress, 1000 + i)
      createThread(workers[4 + i], workArchive, 2000 + i)
    for _ in 0 ..< 8:
      check(doneChan.recv())
    for w in workers.mitems:
      joinThread(w)
