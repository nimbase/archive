# archive docs

This directory documents the `nimbase/archive` Nim package: a unified library for archives and single-file compression with a zero-copy I/O core.

## Who this is for

- Humans learning the public API: start at `getting-started.md`.
- LLMs implementing features or fixing bugs: use this index plus the per-module pages as ground truth for proc signatures, ownership rules, and error behavior. Each page names its source file, e.g. `src/archive/io.nim`.

## Map

- `getting-started.md` - install, first compress/archive/extract round trip.
- `high-level-api.md` - one-shots in `src/archive.nim`: `compress`, `archiveDir`, `extractFile`, `extractAll`, `listEntries`, encrypted variants.
- `io.md` - zero-copy core in `src/archive/io.nim`: `Input`, `Output`, `Span`, reuse and lifetime rules.
- `types.md` - shared types in `src/archive/types.nim`: `FileInfo`, `ArchiveContext`, `CompressionFormat`, `ArchiveFormat`, errors, progress/cancel.
- `registry.md` - dispatch and detection in `src/archive/registry.nim`: `identify`, `CompressedArchive`, `EncryptedArchive`.
- `files.md` - building file lists in `src/archive/files.nim`: `filesFromDisk`, `filesFromEntries`.
- `vfs.md` - virtual filesystem in `src/archive/vfs.nim`: `fileSystem`, `walkFs`, `openArchive`, DeepFS helpers.
- `formats-tar-zip.md` - `src/archive/formats/tar.nim`, `src/archive/formats/zip.nim`, `src/archive/zipfile.nim`.
- `formats-compression.md` - `src/archive/formats/gz.nim`, `zlib.nim`, `lz4.nim`, `bz2.nim`, `brotli.nim` and backends `gzipf`, `zlibf`, `lz4f`, `bz2f`, `flate`.
- `crypt.md` - encrypted blobs and archives in `src/archive/crypt.nim`.
- `internals.md` - `crc32.nim`, threading, buffering, checksum policy.
- `examples.md` - walkthrough of `examples/*.nim` (RAR example excluded).
- `limitations-roadmap.md` - what is missing or partial.
- `rar-stub.md` - placeholder. RAR implementation is owned by another agent and intentionally not documented here.

## Conventions used in these docs

- Headers name the source: `### compressInto (src/archive/registry.nim)`.
- Code snippets are runnable Nim and follow `examples/` style: `import archive` first, then specific `import archive/io` etc. only when needed.
- API tables list `proc | inputs -> outputs | errors`.
- Ownership is explicit: if a proc returns a `Span` or `Input` borrowing another object, the docs say how long the parent must live.
- Errors: `ArchiveError` is the base. Codec errors (`ZlibError`, `Lz4Error`, `Bz2Error`, `ZipError`, `CryptoError`) propagate unwrapped unless stated. `NoMatchError` means identification found nothing.

## RAR scope

Ignore `src/archive/formats/rar.nim`, `rarcodec.nim`, `rarenc.nim`, `rarcrypt.nim`, `tests/test_rar.nim`, `examples/rar.nim` in this pass. Where RAR appears in shared enums (`afRar`, `mtRar`), it is noted but not detailed.
