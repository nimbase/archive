## Archive benchmarks: wall time + memory for compress/decompress and
## archive/extract across formats.
##
## Not part of `clue test` (timing is not asserted). Build and run:
##   clue build tests/bench/bench.nim --out:/tmp/bench && /tmp/bench [quick|full]
## quick (default): ~4 MB text, ~1 MB random, ~120 files. full: 8x corpora.
##
## Columns: in/out KB, ratio%, encode ms + MB/s, decode ms + MB/s,
## heap delta KB (Nim heap around the timed op). Process peak RSS is
## printed per section (ru_maxrss high-water mark) and at the end.
## Round trips are verified byte-identical; mismatch raises.

import std/[strformat, strutils, random, options, tables, times]
from std/os import paramCount, paramStr, getTempDir, createDir, removeFile,
  removeDir, getFileSize, `/`
import std/posix
import archive
import archive/io
import archive/files
import archive/formats/tar
import archive/formats/zip
import archive/formats/rar
import archive/formats/sevenz

let scaleFull = paramCount() >= 1 and paramStr(1) == "full"
let reps = if scaleFull: 3 else: 2

let textSize = if scaleFull: 32 * 1024 * 1024 else: 4 * 1024 * 1024
let randSize = if scaleFull: 8 * 1024 * 1024 else: 1 * 1024 * 1024
let fileCount = if scaleFull: 600 else: 120
let rarTextSize = if scaleFull: 2 * 1024 * 1024 else: 1 * 1024 * 1024

# ---------- corpora (deterministic) ----------

proc makeText(n: int): string =
  ## Compressible prose-like data with cross-buffer repetition.
  const phrase = "lorem ipsum dolor sit amet, consectetur adipiscing elit. "
  result = newString(n)
  var i = 0
  var k = 0
  while i < n:
    let chunk = phrase & "section " & $k & ". "
    for c in chunk:
      if i >= n: break
      result[i] = c
      inc i
    inc k

proc makeRandom(n: int): string =
  var rng = initRand(1234)
  result = newString(n)
  for i in 0 ..< n:
    result[i] = chr(rng.rand(255))

proc makeEntries(count: int): seq[FsEntry] =
  ## Mixed small files: text-heavy with some incompressible ones.
  var rng = initRand(99)
  for i in 0 ..< count:
    let size = 4 * 1024 + rng.rand(48 * 1024)
    var d = newString(size)
    if i mod 5 == 4:
      for j in 0 ..< size: d[j] = chr(rng.rand(255))
    else:
      let w = "file " & $i & " content line. "
      for j in 0 ..< size: d[j] = w[j mod w.len]
    let p = "docs/f" & $i & ".txt"
    result.add(FsEntry(path: p,
      meta: FileMeta(name: p, size: d.len, isRegular: true), data: d))

# ---------- measurement ----------

proc rssKb(): int64 =
  var ru: Rusage
  if getrusage(RUSAGE_SELF, addr ru) != 0'i32:
    return -1
  when defined(macosx):
    int64(ru.ru_maxrss) div 1024 # macOS reports bytes
  else:
    int64(ru.ru_maxrss) # Linux reports KB

template timed(reps: int, body: untyped): float =
  ## Min wall time in ms over `reps` runs of body.
  var best = high(float)
  for _ in 1 .. reps:
    let t0 = epochTime()
    body
    let dt = (epochTime() - t0) * 1000.0
    if dt < best: best = dt
  best

proc heapDeltaKb(body: proc()) : int64 =
  GC_fullCollect()
  let before = getOccupiedMem()
  body()
  (getOccupiedMem() - before) div 1024

proc mbps(bytes: int, ms: float): float =
  if ms <= 0: 0.0 else: bytes.float / 1e6 / (ms / 1e3)

proc row(op, data: string; inB, outB: int; encMs, decMs: float;
    heapKb: int64) =
  let ratio = if inB == 0: 0.0 else: outB.float / inB.float * 100.0
  echo &"{op:<12}{data:<10}{inB div 1024:>9}{outB div 1024:>9}" &
    &"{ratio:>7.1f}%{encMs:>10.1f}{mbps(inB, encMs):>9.1f}" &
    &"{decMs:>10.1f}{mbps(inB, decMs):>9.1f}{heapKb:>10}"

proc header() =
  echo &"scale={(if scaleFull: \"full\" else: \"quick\")} reps={reps} rss_start={rssKb()}KB"
  echo &"{\"op\":<12}{\"data\":<10}{\"inKB\":>9}{\"outKB\":>9}" &
    &"{\"ratio\":>8}{\"enc_ms\":>10}{\"encMB/s\":>9}" &
    &"{\"dec_ms\":>10}{\"decMB/s\":>9}{\"heapdKB\":>10}"

proc section(name: string) =
  echo &"--- {name} (rss={rssKb()}KB) ---"

# ---------- one-shot compress/decompress ----------

proc benchCodec(cf: CompressionFormat, label, data: string) =
  var enc = ""
  let encMs = timed(reps): enc = compress(cf, data)
  doAssert enc.len > 0, "empty encode: " & label
  var dec = ""
  let decMs = timed(reps): dec = decompress(cf, enc)
  doAssert dec == data, "round-trip mismatch: " & label
  let hd = heapDeltaKb(proc() = discard compress(cf, data))
  row("compress", label, data.len, enc.len, encMs, decMs, hd)

# ---------- archives ----------

proc collectBodies(op: string; ctx: ArchiveContext; inp: Input;
    want: seq[FsEntry]): int =
  ## Extract with the matching per-format walk; asserts every body,
  ## returns total body bytes.
  var expect = initOrderedTable[string, string]()
  for f in want: expect[f.path] = f.data
  var seen = 0
  case op
  of "tar":
    extractTar(Tar(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        let b = readAll(info.open())
        doAssert b == expect[info.nameInArchive], "tar body: " & info.nameInArchive
        seen += b.len
  of "zip-store", "zip-deflate":
    let z = if op == "zip-deflate": Zip(compression: 8) else: Zip()
    extractZip(z, ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        let b = readAll(info.open())
        doAssert b == expect[info.nameInArchive], "zip body: " & info.nameInArchive
        seen += b.len
  of "tar.gz":
    let ca = CompressedArchive(archival: afTar, compression: cfGz)
    ca.extractFrom(ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        let b = readAll(info.open())
        doAssert b == expect[info.nameInArchive], "tar.gz body: " & info.nameInArchive
        seen += b.len
  of "rar-store", "rar-m1", "rar-m3":
    let m = if op == "rar-m1": 1 elif op == "rar-m3": 3 else: 0
    extractRar(Rar(meth: m), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        let b = readAll(info.open())
        doAssert b == expect[info.nameInArchive], "rar body: " & info.nameInArchive
        seen += b.len
  of "7z-store", "7z-solid":
    extractSz(Sz(), ctx, inp) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        let b = readAll(info.open())
        doAssert b == expect[info.nameInArchive], "7z body: " & info.nameInArchive
        seen += b.len
  else:
    doAssert false, "unknown op: " & op
  seen

proc benchArchive(op, label: string; files: seq[FileInfo];
    want: seq[FsEntry];
    doArchive: proc(c: ArchiveContext; dst: Output)) =
  var ctx: ArchiveContext
  var blob = ""
  let encMs = timed(reps):
    let dst = newOutput()
    doArchive(ctx, dst)
    blob = take(dst)
  doAssert blob.len > 0, "empty archive: " & label
  var total = 0
  let decMs = timed(reps):
    total = collectBodies(op, ctx, openInputString(blob), want)
  doAssert total > 0, "nothing extracted: " & label
  var inBytes = 0
  for f in want: inBytes += f.data.len
  let hd = heapDeltaKb(proc() =
    let dst = newOutput()
    doArchive(ctx, dst))
  row(op, label, inBytes, blob.len, encMs, decMs, hd)

proc main() =
  header()
  let text = makeText(textSize)
  let rnd = makeRandom(randSize)
  let entries = makeEntries(fileCount)
  let rarText = makeText(rarTextSize)

  section("one-shot compress/decompress (default level)")
  for (cf, label) in [(cfGz, "gz"), (cfZlib, "zlib"), (cfLz4, "lz4"),
      (cfBz2, "bz2"), (cfBrotli, "br")]:
    benchCodec(cf, label & "/text", text)
  for (cf, label) in [(cfGz, "gz"), (cfZlib, "zlib"), (cfLz4, "lz4"),
      (cfBz2, "bz2"), (cfBrotli, "br")]:
    benchCodec(cf, label & "/rand", rnd)

  section("archive/extract many small files")
  var ctx: ArchiveContext
  let files = filesFromEntries(ctx, FromFSOptions(), entries, ".", "")
  benchArchive("tar", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) = archiveTar(Tar(), c, dst, files))
  benchArchive("zip-store", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) =
      archiveZip(Zip(), c, dst, files))
  benchArchive("zip-deflate", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) =
      archiveZip(Zip(compression: 8), c, dst, files))
  benchArchive("tar.gz", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) =
      CompressedArchive(archival: afTar, compression: cfGz).archiveTo(c,
        dst, files))
  benchArchive("7z-store", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) =
      archiveSz(Sz(meth: 0), c, dst, files))
  benchArchive("7z-solid", "files", files, entries,
    proc(c: ArchiveContext; dst: Output) =
      archiveSz(Sz(meth: 1), c, dst, files))

  section("archive/extract single text (rar)")
  var rctx: ArchiveContext
  let rarEntries = @[FsEntry(path: "big.txt",
    meta: FileMeta(name: "big.txt", size: rarText.len, isRegular: true),
    data: rarText)]
  let rarFiles = filesFromEntries(rctx, FromFSOptions(), rarEntries, ".", "")
  benchArchive("rar-store", "text", rarFiles, rarEntries,
    proc(c: ArchiveContext; dst: Output) =
      archiveRar(Rar(meth: 0), c, dst, rarFiles))
  benchArchive("rar-m1", "text", rarFiles, rarEntries,
    proc(c: ArchiveContext; dst: Output) =
      archiveRar(Rar(meth: 1), c, dst, rarFiles))
  benchArchive("rar-m3", "text", rarFiles, rarEntries,
    proc(c: ArchiveContext; dst: Output) =
      archiveRar(Rar(meth: 3), c, dst, rarFiles))

  section("archive/extract single text (7z)")
  benchArchive("7z-store", "text", rarFiles, rarEntries,
    proc(c: ArchiveContext; dst: Output) =
      archiveSz(Sz(meth: 0), c, dst, rarFiles))
  benchArchive("7z-solid", "text", rarFiles, rarEntries,
    proc(c: ArchiveContext; dst: Output) =
      archiveSz(Sz(meth: 1), c, dst, rarFiles))

  section("file streaming (bounded memory)")
  let tmp = getTempDir() / "bench_archive"
  createDir(tmp)
  try:
    writeFile(tmp / "in.bin", text)
    var gzMs = 0.0
    gzMs = timed(reps): compressFile(cfGz, tmp / "in.bin", tmp / "in.bin.gz")
    var unMs = 0.0
    unMs = timed(reps):
      decompressFile(cfGz, tmp / "in.bin.gz", tmp / "out.bin")
    doAssert readFile(tmp / "out.bin") == text, "stream round trip"
    let gzLen = getFileSize(tmp / "in.bin.gz")
    GC_fullCollect()
    let h0 = getOccupiedMem()
    compressFile(cfGz, tmp / "in.bin", tmp / "in.bin.gz")
    let hd = (getOccupiedMem() - h0) div 1024
    row("stream-gz", "textfile", text.len, gzLen.int, gzMs, unMs, hd)
  finally:
    try: removeFile(tmp / "in.bin") except OSError: discard
    try: removeFile(tmp / "in.bin.gz") except OSError: discard
    try: removeFile(tmp / "out.bin") except OSError: discard
    try: removeDir(tmp) except OSError: discard

  echo &"rss_end={rssKb()}KB"

main()
