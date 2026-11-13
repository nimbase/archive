# Benchmarks

Runnable bench for speed + memory across formats. Not part of `clue test`
(timing is not asserted); round trips are verified byte-identical, so a
mismatch fails the run.

```bash
clue build tests/bench/bench.nim --out:/tmp/bench && /tmp/bench [quick|full]
```

- `quick` (default): ~4 MB text, ~1 MB random, ~120 files, 2 reps.
- `full`: 8x corpora, 3 reps (bzip2/rar-m3 dominate runtime).

What it measures:

- One-shot `compress`/`decompress` per `CompressionFormat` (default level)
  on text-like and incompressible input: ratio, encode/decode ms + MB/s.
- `archiveTar`/`archiveZip`/`CompressedArchive(tar.gz)`/`archiveRar`/
  `archiveSz` plus matching extract walks over many small files and
  single text: container overhead, per-file codec cost, solid-group RAR
  (`m1`/`m3`), STORE + LZMA2-solid 7z (`meth 0`/`1`).
- File streaming (`compressFile`/`decompressFile`) on a temp file to show
  bounded memory vs the one-shot path.

Memory columns: `heapdKB` is the Nim-heap delta around one timed op
(`GC_fullCollect` before sampling); `rss=` lines are the process
`ru_maxrss` high-water mark (monotonic by definition — compare the
streaming section against the one-shot sections, not within a row).
