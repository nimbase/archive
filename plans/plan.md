# archive — Unified Nim library for archives + compression

Port of `references/archives` (mholt/archives, Go) to idiomatic Nim.
Reference: `/Users/georgelemon/Development/nimbase/references/archives`
Brotli backend: `/Users/georgelemon/Development/nimbase/ports/nbrotli` (pure Nim, hard require).
Codecs (deflate/gzip/zip/tar/crc32) are implemented in this package by
porting Go `compress/flate`, `compress/gzip`, `archive/zip`,
`archive/tar`, `hash/crc32` — no third-party compression deps.

## Goals

- Single API for compress/decompress, create/extract, walk virtual file systems
  across tar, zip, gz, brotli (+ later bz2, xz, zstd, rar/7z read-only).
- Format detection by filename AND by magic bytes (`Identify`) via indexed
  peeks; inputs are never consumed or copied.
- `CompressedArchive` composition (e.g. tar.gz, tar.br): outer compression
  layer + inner archive layer.
- Virtual FS: uniform read over dirs, plain files, compressed files, archives,
  compressed archives (`FileSystem` dispatch + `ArchiveFS` + `DeepFS`).

## Non-goals for v1

- rar / 7z support (deferred to Phase 4, likely needs C bindings or new ports).
- Multithreaded gzip (pgzip equivalent), async archiver channels.
- Real brotli encoder (q=1..11). nbrotli encode is store-only for now.
- Streaming (constant-memory) compress/decompress. The one-shot Into
  model buffers whole members; inputs stream from mmap without copies
  but outputs materialize.

## Module layout

```
src/archive.nim            # gated stub: importing it is a compile error;
                             # import the specific module you need instead
                             # (full re-export only under -d:build_docs)
src/archive/
  types.nim                # FileInfo, FileMeta, MatchResult, ArchiveError, SkipDir/SkipAll
  simd.nim                 # AVX2/SSE4.2 kernels + silicon self-test (feature "nimsimd")
  io.nim                   # Input (mmap/string zero-copy cursor), Output (reusable buffer), Span
  registry.nim             # FormatKind, FormatHandler, registerFormat, Identify
  files.nim                # filesFromDisk, filesFromFs, name mapping, symlink guard
  crc32.nim                # IEEE CRC-32 (scalar table + hw dispatch)
  flate.nim                # DEFLATE inflate/deflate over Input/Output
  gzipf.nim                # gzip framing over Input/Output
  zlibf.nim                # zlib framing (RFC 1950) + Adler-32 over Input/Output
  zipfile.nim              # zip reader/writer over Input/Output
  vfs.nim                  # FileFs, DirFs, ArchiveFs, DeepFs, TopDir helpers
  formats/
    tar.nim
    zip.nim
    gz.nim
    brotli.nim             # wraps nbrotli (hard require)
    zlib.nim               # extension ".zz" (Go parity), own zlibf backend
    # phase 3: bz2.nim, xz.nim, zstd.nim, lz4.nim, sz.nim, lzip.nim, minlz.nim
    # phase 4: rar.nim, sevenz.nim (read-only)
tests/
  test_identify.nim
  test_tar.nim
  test_zip.nim
  test_flate.nim
  test_codecs.nim
  test_compressed.nim
  test_vfs.nim
```

## Key design decisions

- I/O: `Input` read cursors + `Output` reusable buffers (replaces Go
  `io.Reader/Writer/Seeker` AND Nim `streams`). No `streams` anywhere.
  File inputs memory-map via `std/memfiles` (zero-copy, no read
  syscalls); in-memory inputs share strings (no copies). `Output`
  buffers are caller-owned and reusable across calls (`reset` keeps
  capacity). Borrowed `Span` views never outlive their parent.
- Cancellation: no `context.Context`. Check an optional `cancelled: ptr bool`
  at loop heads; abort with `ArchiveError` if set. Keep signatures simple.
- Errors: Nim exceptions (`ArchiveError`, `NoMatchError`), not Go-style tuples.
- Registry: `Table[string, FormatHandler]` keyed by lowercased extension without
  dot. Each handler stores `ext`, `mediaType`, `kinds: set[FormatKind]`,
  plus `doMatch`, `compressInto`, `decompressInto`, `archive`, `extract`
  closures over Input/Output.
- `FileInfo`: object with `nameInArchive`, `linkTarget`, `size`, `mode`,
  `modTime`, `isDir`, `header: ref object` passthrough,
  `open: proc(): Input` (zero-copy for mapped entries).
- Brotli stream sniffing: brotli has no fixed magic, so `match` by name is
  strong, by stream is a bounded trial decode (`initDecoder` + `decodeSome`
  on peeked prefix). Never consume caller stream.
- `ArchiveFS.readDir` indexing: first `readDir` walks the whole archive once and
  builds `contents: Table[string, FileMeta]` + `dirs: Table[string, seq[DirEntry]]`
  with implicit dir synthesis, mirroring Go's amortization for tar.

## Brotli integration (nbrotli, hard require)

`archive.nimble`: `requires "nbrotli >= 0.1.1"`.

- Fields: `quality: 0..11`, `windowBits: 10..24` stored for future real encoder,
  currently mapped to `compressStore(data, wbits)`.
- Decode: full coverage via nbrotli (`q=0..11`, large window 10..30, lazy ring).
- Encode: store-only. Document that output is larger than reference `brotli -q 11`
  but decodable by reference CLI. Round-trip tests assert decode(encode(x)) == x
  and CLI interop on decode only.
- `decompressInto`/`compressInto`: one-shot over Input/Output
  (input copied once into nbrotli; output written straight into the
  caller's buffer). Surface `BrotliError` as `ArchiveError`.

## Build order

- Phase 0: scaffolding — DONE. Placeholder modules replaced, `types` +
  `registry` + `Identify` implemented, reference fixtures vendored to
  `tests/testdata`.
- Phase 1 (MVP): DONE. tar (own ustar/pax) + zip (own zipfile, no zippy) +
  gz (own gzipf/flate, no zippy) + brotli (nbrotli backend),
  `CompressedArchive`, `archive`/`extract` with handler, `insert` for tar
  and zip rewrite, `filesFromDisk`, `FileSystem` dispatch, `ArchiveFS`
  with indexed `readDir`. 7 suites pass via `clue test`, zero warnings.
  Bidirectional system interop verified: our gzip/zip outputs open with
  system `gzip`/`unzip`, and system-created fixtures (dynamic Huffman,
  deflate) decode with our readers.
- Phase 2 (I/O + SIMD): DONE. `std/streams` eliminated: `io.nim` core
  (`Input` over memfiles, reusable `Output`, borrowed `Span`), own
  flate/gzip/zip/tar on pointers, no zippy dependency. `simd.nim`
  (feature "nimsimd", nbrotli pattern): AVX2 copies, AVX2 match-length,
  SSE4.2 CRC32, all gated by a runtime silicon self-test (a VM here
  mistranslates crc32 to Castagnoli: check value E3069283 vs CBF43926).
  7 suites pass with and without the feature; system `gzip`/`unzip`
  interop re-verified both ways.
- Phase 3: bz2, xz, zstd, lz4, sz/s2, lzip, minlz (same approach: port Go
  framing + algorithms, no third-party Nim deps). zlib (.zz) DONE:
  `zlibf.nim` (RFC 1950 framing over own flate + scalar Adler-32 with
  NMAX chunking) + `formats/zlib.nim` (Go-parity ".zz" extension,
  procedural header validation covering Go's 32-entry table, level-mapped
  headers 78 01 / 78 9C / 78 DA). 7 new tests in test_codecs (round
  trips, all-byte-values, levels, python-zlib fixture interop both
  directions, corrupt/bad-checksum raises) plus tar.zz CompressedArchive
  round trip + identify. Full suite green scalar and --features:nimsimd.
- Phase 4: rar, 7z read-only (likely needs C bindings or new ports).

## Nim porting notes (learned)

- Runtime ref-object type tests use `of`, not `is` (`is` is static).
  `newRewindReader` misdetected every seekable stream until fixed.
- Nim `ref object` types need explicit `of RootObj` to participate in
  ref conversions (bare `ref object` does not convert to RootRef).
- `out` is a reserved keyword: writer/buffer params are named `dst`.
- Hardware intrinsics must be runtime-validated, not just
  compile-gated: this machine's crc32 computes Castagnoli. Gate all
  SIMD kernels behind a check-value self-test with scalar fallback.
- Closures created in a loop share the captured slot: all per-file
  `open` closures served the last file's data until replaced with
  `stringOpener`/`fileOpener` factories in `types.nim`.
- Go `Identify` semantics kept: unknown inner stream yields the outer
  compression format alone, `CompressedArchive` only on double match.

## Test strategy

- `clue test` runs all `tests/test_*.nim` (scalar default); SIMD path via manual `nim -d:features.archive.nimsimd` run since `clue test` has no --features flag in v0.3.7.
- Reuse `references/archives/testdata` where license permits; otherwise vendor a
  small subset of fixtures (tar, zip, gz, br, tar.gz, tar.br).
- Cases: identify by name, by magic, combined; round trips; selective extract;
  symlink preservation; empty dir handling; tar.br end-to-end; VFS walk with skip.
- Validate `*.br` fixtures against reference `brotli` CLI where available.
