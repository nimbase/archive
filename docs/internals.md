# Internals

This page covers `src/archive/crc32.nim` plus cross-cutting runtime rules (threading, buffering, checksums). Plain markdown, no generator required.

## CRC32 (src/archive/crc32.nim)

IEEE CRC-32 ported from Go `hash/crc32`. Polynomial `0xEDB88320`, table-driven scalar.

- `crc32Update` is the portable scalar path.
- `crc32Checksum` uses init `0xFFFFFFFF` with final xor.

Used by gzip trailer checks, zip entry CRCs, and streaming flush helpers.

## Threading

Every proc is safe to call from any thread. There is no shared state, no global registry, no lazy statics. `ArchiveContext` is per call. `reportProgress` runs synchronously on the caller thread.

See `tests/test_threads.nim` for the threading smoke test.

## Buffering and memory bounds

- One-shot string APIs (`compress`, `decompress`, `archiveData`) hold full contents by design.
- File-to-file decompression (`decompressFileInto`) uses fixed buffers and never holds full contents, except Brotli which keeps the one-shot path.
- Plain-zip `extractFile(path, outPath)` streams with a bounded pool (64 KB input + 96 KB window, 1 MB cap). Other formats use the generic handler; tar is already zero-copy via borrowed spans.
- `Output` reuse: pass the same `Output` across calls and `reset` it. `resetBounded` trims pools that grew past `MaxScratchCap` (1 MB).
- `releaseSpanPages` is best-effort page release after bulk file writes; never raises.

## Checksum and corruption policy

- Per-entry CRCs and stream checksums are verified on every decode; corrupt inputs raise descriptive errors, not silent truncation.
- gzip: CRC32 + ISIZE; zlib: Adler-32 + header checks; lz4: header checksum, per-block xxHash32 when flagged, content checksum; bzip2: per-block CRC plus combined stream CRC; zip: per-entry CRC plus size checks; encrypted blobs: Poly1305 MAC per chunk plus header checks.
- Partial file outputs are deleted on failure in `encryptFile` / `decryptFile` and `gzipDecompressFile` paths.
- Zip-slip is rejected centrally by `safeDestPath` (absolute paths and `..` components raise `ArchiveError`).
