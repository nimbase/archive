# High-level API (src/archive.nim)

Single entry point for one-shot compression, archiving, extraction, listing, and encrypted archives. Re-exports `archive/registry` and `archive/types`. For custom archive settings call `archiveTar` / `archiveZip` directly (see `formats-tar-zip.md`).

## Compression one-shots

### compress / decompress (src/archive.nim:30,36)

```nim
proc compress*(fmt: CompressionFormat; data: string; level = 0): string
proc decompress*(fmt: CompressionFormat; data: string): string
```

Fresh-string compress/decompress. `level 0` means codec default. `compress` allocates `len/2+32` upfront; `decompress` grows as needed. Codec errors propagate with their own type.

```nim
let enc = compress(cfBz2, payload, level = 9)
assert decompress(cfBz2, enc) == payload
```

### compressFile / decompressFile (src/archive.nim:42,52)

```nim
proc compressFile*(fmt: CompressionFormat; srcPath, dstPath: string; level = 0)
proc decompressFile*(fmt: CompressionFormat; srcPath, dstPath: string)
```

File to file. Input is memory-mapped. `decompressFile` delegates to bounded `decompressFileInto` (fixed buffers, never full contents) except Brotli which keeps the one-shot path (upstream `nbrotli` limitation).

## Archives

| proc | inputs -> outputs | notes |
| ---- | ----------------- | ----- |
| `archiveData` (src/archive.nim:60) | `(archival, files, ctx, compression) -> string` | blob, optional outer `some(cfGz)` etc. |
| `archiveFile` (src/archive.nim:73) | `(archival, files, path, ...) -> void` | `archiveData` + `writeFile`. |
| `archiveDir` (src/archive.nim:78) | `(archival, srcDir, dstPath, rootInArchive, ctx, compression, followSymlinks) -> void` | `filesFromDisk` lazily, then `archiveFile`. |
| `archivePaths` pairs (src/archive.nim:87) | `(archival, [(disk, archive)], ...) -> string` | scattered inputs, explicit rename. |
| `archivePaths` plain (src/archive.nim:98) | `(archival, [paths], ...) -> string` | stores names as given. |

```nim
let blob = archivePaths(afTar, @["notes.txt", "src/main.nim"])
let renamed = archivePaths(afTar, @[("run.sh", "bin/run")],
  compression = some(cfGz))
```

In-memory entries need `archive/files`:

```nim
import archive/files
var ctx: ArchiveContext
let entries = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
    isRegular: true), data: "hello"),
], ".", "")
archiveFile(afZip, entries, "out.zip", ctx)
archiveFile(afTar, entries, "out.tar.gz", ctx, compression = some(cfGz))
```

## Extraction

### extractIdentified (src/archive.nim:111)

```nim
proc extractIdentified*(res: IdentifyResult; ctx: ArchiveContext;
  inp: Input; handle: FileHandler)
```

Dispatches an `identify` result. Raises `ArchiveError` for compression-only results (use `decompressFile`), `NoMatchError` when empty.

### identifyPath (src/archive.nim:127)

```nim
proc identifyPath*(path: string): IdentifyResult
```

Identify by filename plus magic bytes. Opens and closes its own mmap.

### extractFile + extractAll (src/archive.nim:233,248,367,413,418,431)

```nim
proc extractFile*(path: string; handle: FileHandler; ctx: ArchiveContext)
proc extractFile*(path: string; handle: FileHandler)
proc extractFile*(path, outPath: string; ctx: ArchiveContext)
proc extractFile*(path, outPath: string)
iterator extractAll*(path: string; ctx: ArchiveContext): ArchiveEntry
iterator extractAll*(path: string): ArchiveEntry
```

- Callback form opens the file twice (identify then extract) because probing may advance the cursor.
- Encrypted input raises `ArchiveError`; use `decryptExtract` / `decryptFile`.
- Dir form creates the tree (parents included), recreates symlinks, skips hardlinks/devices, validates every name with `safeDestPath`.
- Plain zip uses a bounded streaming fast path; other formats use the generic handler (tar is already zero-copy via borrowed spans).
- `extractAll` collects `(name, data)` pairs first then yields; it is not truly lazy.

```nim
import archive/io
for name in listEntries("out.tar.gz"):
  echo name
extractFile("out.tar.gz", proc(c: ArchiveContext; info: FileInfo) =
  if info.isRegular() and info.nameInArchive.endsWith(".txt"):
    echo(info.nameInArchive & ": " & $readAll(info.open()).len))
```

### safeDestPath (src/archive.nim:253)

```nim
proc safeDestPath*(outPath, name: string): string
```

Joins entry name onto destination, rejecting zip-slip (absolute paths, `..` components) with `ArchiveError`. Exported so custom loops can share the guard.

## Encrypted archives

```nim
proc encryptArchive*(archival: ArchiveFormat; files: seq[FileInfo];
  key: Key32; ctx = ArchiveContext(); compression = none(CompressionFormat);
  level = 0; chunkSize = encChunkDefault): string
proc encryptArchive*(archival; files; password: string; ...): string
proc decryptExtract*(inp: Input; key/password; ctx; handle: FileHandler)
proc decryptExtract*(path: string; key/password; ctx; handle: FileHandler)
proc decryptExtract*(path: string; key/password; handle: FileHandler)
```

Archive, optionally compress, then encrypt to a blob; decrypt reverses to a temp buffer then dispatches via `identify`. Password variant uses fresh salt + Argon2id per message. See `crypt.md` for framing and key handling.
