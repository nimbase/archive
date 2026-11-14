# Limitations and roadmap

Source of truth is `README.md` roadmap plus the notes below. RAR is excluded here; see `rar-stub.md`.

## Done

- tar (ustar/pax, symlinks, hardlinks, insert/append).
- zip (deflate/store, insert/replace).
- gzip (`.gz`), zlib (`.zz`), lz4 (`.lz4`), bzip2 (`.bz2`).
- Brotli (`.br`) via `nbrotli`: decode full, store-only encode (SIMD-accelerated internally).
- `identify` by name and magic bytes, `CompressedArchive` tar.gz-style composition.
- Virtual filesystem (`DirFS`, `ArchiveFS`, `DeepFS`, path helpers).
- Encrypted archives via `nimcypher` (XChaCha20-Poly1305 chunked AEAD, whole-blob envelope).

## Partial or missing

- xz (`.xz`, LZMA2 framing + range coder): not implemented.
- zstd (`.zst`): not implemented.
- snappy/s2 (`.sz`/`.s2`): not implemented.
- lzip (`.lz`), minlz (`.mz`): not implemented.
- 7z read/write: needs new port; public-domain LZMA SDK reference.
- Brotli encode is store-only; output decodes correctly but is larger than quality-compressed output. File decode holds full contents (no true streaming).
- `extractAll` collects `(name, data)` pairs before yielding; not truly lazy.
- `EncryptedArchive` and `CompressedArchive` use temp buffers; they are not streaming compositions.
- Hardlink tar entries (`typeflag '1'`) are neither dir/symlink/regular and are skipped by the default `extractFile(path, outPath)` loop.
- Zip64, multi-disk archives, and encrypted zip entries are rejected explicitly.

## Interop

Tested both directions against system `gzip` / `unzip`, `bzip2`, `lz4`, and CPython `zlib` / `bz2`. See `tests/test_codecs.nim`, `tests/test_tar.nim`, `tests/test_zip.nim`, `tests/test_compressed.nim`, `tests/testdata/` fixtures.
