# Dispatch and identification (src/archive/registry.nim)

No registry, no globals. `CompressionFormat` and `ArchiveFormat` dispatch statically. Safe to call from any thread. Inputs are zero-copy cursors: matching only peeks indexed spans, no rewind buffering is needed.

## Result types

```nim
IdentifyResult* = object
  archival*: Option[ArchiveFormat]
  compression*: Option[CompressionFormat]
CompressedArchive* = object
  archival*: ArchiveFormat
  compression*: CompressionFormat
EncryptedArchive* = object
  archival*: ArchiveFormat
  compression*: Option[CompressionFormat]  # keyless descriptor, secrets flow per call
```

Compression-only result means use the decompress path, not the archive path.

## Extension helpers (src/archive/registry.nim:49-71)

| proc | behavior |
| ---- | -------- |
| `extension(c: CompressedArchive)` | e.g. `.tar.gz` |
| `mediaTypeOf(c: CompressedArchive)` | outer compression MIME |
| `baseName(filename)` | after last `/`, backslash-normalized |
| `compressionForExt(ext)` | case-insensitive, dot-optional; raises `ArchiveError` when unknown |
| `archiveForExt(ext)` | same for archives |

## Codec dispatch (src/archive/registry.nim:98-139)

```nim
proc compressInto*(fmt: CompressionFormat; inp: Input; dst: Output; level = 0)
proc decompressInto*(fmt: CompressionFormat; inp: Input; dst: Output)
proc decompressFileInto*(fmt: CompressionFormat; srcPath, dstPath: string)
```

- `level 0` is codec default (gz/zlib/bz2 default 6; lz4/brotli ignore level).
- Codec errors propagate with their own type.
- `decompressFileInto` uses bounded file-to-file buffers except Brotli, which stays full-buffer (upstream `nbrotli` has no streaming entry point).

## Archive dispatch (src/archive/registry.nim:141-150)

```nim
proc archiveFormat*(fmt: ArchiveFormat; ctx: ArchiveContext; dst: Output; files: seq[FileInfo])
proc extractFormat*(fmt: ArchiveFormat; ctx: ArchiveContext; inp: Input; handle: FileHandler)
```

Default settings. For custom tar/zip settings use `archiveTar` / `archiveZip` directly. Propagates `ArchiveError` and cancel.

## Composition (src/archive/registry.nim:159-217)

```nim
proc archiveTo*(c: CompressedArchive; ctx; dst; files; level = 0)
proc extractFrom*(c: CompressedArchive; ctx; inp; handle: FileHandler)
proc archiveTo*(e: EncryptedArchive; ctx; dst; files; key: Key32; level = 0; chunkSize = encChunkDefault)
proc archiveTo*(e: EncryptedArchive; ctx; dst; files; password: string; ...)
proc extractFrom*(e: EncryptedArchive; ctx; inp; handle; key: Key32)
proc extractFrom*(e: EncryptedArchive; ctx; inp; handle; password: string)
```

- `CompressedArchive` archives to a temp `Output` then compresses; extraction decompresses to temp then extracts.
- `EncryptedArchive` is archive, optionally compress, then encrypt; extraction is decrypt, optional decompress, then extract. Raises `CryptoError` and archive errors.

## Identification (src/archive/registry.nim:229-317)

```nim
proc matchFormat*(fmt: CompressionFormat; filename: string; inp: Input): MatchResult
proc matchFormat*(fmt: ArchiveFormat; filename: string; inp: Input): MatchResult
proc matchOne*(fmt: CompressionFormat; filename: string; inp, inner: Input): MatchResult
proc matchOne*(fmt: ArchiveFormat; filename: string; inp, inner: Input): MatchResult
proc identify*(ctx: ArchiveContext; filename: string; inp: Input = nil): IdentifyResult
proc identifyFormat*(filename: string; inp: Input = nil): IdentifyResult
```

- `inp` may be nil for name-only matching.
- `matchOne` treats `"."` as `""`, uses `inner` when non-nil else peeks `inp` with position save/restore; never consumes.
- `identify` picks the most specific match, never consumes `inp`, probes compression (Brotli last), reuses one decompression for inner archive matching, demotes phantom stream-only layers that fail to decode, honors `cancelled`.
- Raises `NoMatchError` when nothing matches, `ArchiveError` on matcher failure.
