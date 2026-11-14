# Single-file compression (formats + backends)

All codecs share dispatch in `src/archive/registry.nim:98-139` (`compressInto`, `decompressInto`, `decompressFileInto`). `level 0` means codec default. Under the hood gzip/zlib ride `src/archive/flate.nim` (`deflateInto`, `inflateStreamPtr`, `inflateInto`, `inflateFileMember`, `inflateFileMemberGeneric`).

## gzip, cfGz (.gz)

Wrapper `src/archive/formats/gz.nim:15` (`Gz{compressionLevel, disableMultistream, multithreaded}`). Backend `src/archive/gzipf.nim`. Magic `1f 8b`.

| proc | notes |
| ---- | ----- |
| `gzipCompressInto(inp, out, level=6)` (gzipf.nim:19) / `gzipCompress(data, level=6)` | level only selects XFL byte; deflate path has no level |
| `gzipDecompressInto(inp, out, multistream=true)` (gzipf.nim:51) / `gzipDecompress` | concatenated members; `disableMultistream` exists only on `Gz` |
| `gzipDecompressFile(src, dst)` (gzipf.nim:133) | bounded (64 KB in + 96 KB window), deletes partial output on error |
| `openGzReader` (formats/gz.nim:35) | reader frontend |

Checks: CRC32 IEEE plus ISIZE LE trailer. File path verifies the same.

## zlib, cfZlib (.zz)

Wrapper `src/archive/formats/zlib.nim:15` (`Zlib{compressionLevel}`). Backend `src/archive/zlibf.nim`. Headers `78 01 / 78 9C / 78 DA` by level.

| proc | notes |
| ---- | ----- |
| `zlibCompressInto(inp, dst, level=6)` (zlibf.nim:79) | `0` maps to default `78 9C`; only `==1` / `>=9` special-cased |
| `zlibDecompressInto(inp, dst)` (zlibf.nim:100) / `zlibDecompress` | single stream |
| `zlibDecompressFile(src, dst)` (zlibf.nim:148) | bounded via `inflateFileMemberGeneric` + Adler |
| `openZlibReader` (formats/zlib.nim:31) | reader frontend |

Checks: `isValidZlibHeader` (CM=8, CINFO<=7, no FDICT, FCHECK), Adler-32 BE trailer.

## lz4, cfLz4 (.lz4)

Wrapper `src/archive/formats/lz4.nim:15` (`Lz4{compressionLevel}` parity-only). Backend `src/archive/lz4f.nim`. Frame magic `04 22 4D 18` LE; skippable `184D2A50..5F`.

| proc | notes |
| ---- | ----- |
| `lz4CompressInto(inp, dst, level=0)` (lz4f.nim:229) | level ignored, always fast path; FLG `0x64` / BD `0x40` (independent 64 KB blocks, content checksum, no content size) |
| `lz4DecompressInto(inp, dst)` (lz4f.nim:275) | concatenated frames, skippable skipped; rejects version != 01, reserved flags, dictionaries |
| `lz4DecompressFile(src, dst)` (lz4f.nim:556) | bounded (64 KB in + 128 KB window, token streaming) |
| `openLz4Reader` (formats/lz4.nim:32) | reader frontend |

Checks: header checksum, per-block xxHash32 when flagged, content-size match, content xxHash32.

## bzip2, cfBz2 (.bz2)

Wrapper `src/archive/formats/bz2.nim:15` (`Bz2{compressionLevel}`; `0 -> 6`, `1..9` = 100k..900k bytes per block). Backend `src/archive/bz2f.nim`. Magic `"BZh"+digit`.

| proc | notes |
| ---- | ----- |
| `bz2CompressInto(inp, dst, level=6)` (bz2f.nim:669) | validates `1..9` after `0 -> 6` |
| `bz2DecompressInto(inp, dst)` (bz2f.nim:815) | concatenated streams |
| `bz2DecompressFile(src, dst)` (bz2f.nim:1051) | bounded (64 KB in + up to 900 KB reused per-block scratch) |
| `openBz2Reader` (formats/bz2.nim:31) | reader frontend |

Checks: per-block CRC plus rotated combined stream CRC. Rejects randomized blocks and bzip1.

## brotli, cfBrotli (.br)

Wrapper `src/archive/formats/brotli.nim:21` (`Brotli{quality 0..11, windowBits 10..24}`, `defaultBrotli = quality 11 / wbits 16`). Backend is `nbrotli` (hard require).

| proc | notes |
| ---- | ----- |
| `brotliCompressInto(inp, dst, wbits=16)` (brotli.nim:110) | store-only encode via `compressStore`; `quality` stored but unused; output is reference-decodable but larger |
| `brotliDecompressInto(inp, dst)` (brotli.nim:89) | full decode via `nbrotli.decompress`; wraps `BrotliError.code` into `ArchiveError` |
| `openBrotliReader` (brotli.nim:127) | reader frontend |

Limitations:

- Registry drops `level` for Brotli (`registry.nim:109`).
- No true streaming file decode: `decompressFileInto(cfBrotli)` is one-shot file read, decode, write (holds full contents).
- Detection has no magic: trial-decode up to 1 KB plus non-brotli exclusion plus first-byte heuristic; probed last in `identify`.
