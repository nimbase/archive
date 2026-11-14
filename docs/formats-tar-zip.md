# tar and zip (src/archive/formats/tar.nim, zip.nim, src/archive/zipfile.nim)

## tar (src/archive/formats/tar.nim:1-482)

`tarBlockSize = 512`. `TarFormat = tfAuto, tfUstar, tfPax, tfGnu` selects only the long-name strategy.

```nim
Tar* = object
  format*, numericUidGid*, continueOnError*, uid*, gid*: int-like/bool fields
  uname*, gname*: string
  hasUid*, hasGid*: bool
```

`extension(t: Tar) = afTar`, `mediaType(t: Tar) = mtTar`.

### Writing

`writeFileToArchive(t, dst, f)` (tar.nim:266):

- Maps `isDir -> '5'` size 0 mode `0755`; `isSymlink -> '2'` plus `linkTarget`; regular with non-empty `linkTarget -> '1'` hardlink; else `'0'`. Honors `numericUidGid`, `hasUid/hasGid`, `uname/gname`.
- ustar header is one 512-byte block with `ustar` magic, octal fields, checksum. Names over 100 bytes split at the last `/` (prefix up to 155, suffix up to 100).
- pax: when unsplittable and `format != tfGnu`, emits a `pax_extended_header` type `'x'` with `path=<name>` first.
- Non-regular entries stop after the header. Bodies stream in 1 MB `readSpan` chunks plus zero pad to 512.
- Errors: `ArchiveError("file <name>: open: ..." / "short read")`.

`archiveTar(t, ctx, dst, files)` (tar.nim:298): loops with cancel check and progress, wraps per-file errors as `ArchiveError("file ...")`, skips when `continueOnError` unless cancelled, terminates with 1024 zero bytes.

### Extraction

`extractTar(t, ctx, inp, handle)` (tar.nim:339) is zero-copy: header via `readSpan(512)`, body via borrowed `readSpan(n)` with `viewOpener(data, inp)` keeping `inp` alive.

- Zero blocks are skipped (tolerates trailing pad). `parseHeader` verifies checksum else `ArchiveError("bad tar checksum")`. Octal or base-256 sizes supported (overflow saturates to `high(int64)`).
- pax `'g'` global headers are dropped; `'x'` headers override the next `path` / `linkpath`; GNU `'L'` / `'K'` longname/longlink bodies apply similarly.
- Body exists only for `typeflag == '0'` with `n > 0`, else empty span. Truncation raises `ArchiveError("truncated tar entry: ...")`.
- Mapping: `'5'` dir, `'2'` symlink, `'0'` regular. Hardlink `'1'` is none of those and is skipped by the default `extractFile(path, outPath)` loop.
- `SkipAll` breaks, `SkipDir` on a dir adds to `skipDirs`. Handler errors become `ArchiveError("handling file: ...")`. `continueOnError` skips bad headers.

### Matching and insert

- `matchTar(filename, inp)` (tar.nim:430): `byName` when any dot-part equals `tar`; `byStream` when `peek(512)` parses.
- `insertTar(t, ctx, inp, dst, files)` (tar.nim:443): copy-through with allocation-free spans. `g/x/L/K` records are copied verbatim; regular/dir/symlink/hardlink entries are re-emitted (normalizes framing); then appends `files`. Corrupt input fails fast. Caller writes `dst` back; no in-place rewrite.

## zip frontend (src/archive/formats/zip.nim:1-219)

```nim
Zip* = object
  selectiveCompression*: bool
  compression*: int  # 8 = deflate default, 0 = store
  continueOnError*: bool
```

`extension = afZip`, `mediaType = mtZip`. `matchZip` checks `.zip` by name and `PK\x03\x04, PK\x05\x06, PK\x07\x08` by stream.

Deflate/store policy: `selectiveCompression` plus `compressedExts` avoids double-compressing already-compressed suffixes; `compression == 0` forces store. Symlinks become `ZipEntry(isSymlink, linkTarget, data = linkTarget, store = true, mode = 0o120777)` (target as content, Go-compatible). Dirs get trailing `/` and mode `0755`; regular files default `0644` and borrow `peek(fr, remaining)` truncated to `f.size`.

- `archiveZip(z, ctx, dst, files)` (zip.nim:83): per-file errors as `ArchiveError("file ..." / "zip create: ...")`.
- `extractZip(z, ctx, inp, handle)` (zip.nim:131): `openZip` else `ArchiveError("zip open: ...")`; symlink detection from mode bits; `SkipAll` / `SkipDir` supported; handler errors as `ArchiveError("handling file: ...")` or skipped with `continueOnError`.
- `insertZip(z, ctx, inp, dst, files)` (zip.nim:170): Go `Zip.Insert` port. Dedups by name (last wins), replacements overwrite the same archive name, originals keep order then appends. Regular entries use `store = compression == 0` (ignores `selectiveCompression` here). Errors as `ArchiveError("file ...: open: ..." / "zip rewrite: ...")`.

## zipfile backend (src/archive/zipfile.nim:1-448)

```nim
ZipError* = object of CatchableError
ZipEntry* = object
  name*, data*: string
  raw*: Span; keep*: RootRef
  meth*: int; expectCrc*: uint32; expectLen*: int
  isDir*, isSymlink*: bool; linkTarget*: string
  store*: bool; modTime*: Time; mode*: int
ZipReader* = object
  files*: seq[ZipEntry]
```

Read entries from `openZip` are metadata-only: `raw` is borrowed stored/compressed bytes, `keep` is the source `Input`. Write entries use owned `data` or stored spans.

- `openZip(inp)` (zipfile.nim:273): finds EOCD backwards (64 KB comment), rejects multi-disk, Zip64-by-accident, encrypted entries, and methods other than store/deflate. Tolerates data descriptors (local sizes ignored, central values used). `isDir` from trailing `/`; `isSymlink` from `extAttr` mode bits; default mode `0644`. Zero-copy `spanAt(dataStart, compSize)`, no inflate here.
- `entryContent(e)` (zipfile.nim:57): materializes full entry; deflated entries inflate with size and CRC checks (`size mismatch`, `checksum mismatch`, `deflate error in <name>`). For large to-disk use `writeEntryToFile`.
- `writeEntryToFile(e, f, scratch)` (zipfile.nim:100): bounded streaming to file; rejects dirs/symlinks; stored copies chunked, deflated inflates in 96 KB windows via reused `scratch`; verifies bytes and CRC.
- `streamStoredRangeToFilePooled` / `streamDeflatedRangeToFilePooled` (zipfile.nim:188-255): `File -> File` bounded paths used by the `extractZipToDirStreaming` fast path in `src/archive.nim:269`. The 64 KB input chunk lives in a caller-owned buffalo pool (capped at `MaxScratchCap`); `rf` must be positioned at the range start; exactly `compLen` is consumed. The older `var string` twins just above are kept for compatibility.
- `writeZip(entries, dst)` (zipfile.nim:354): streams into reusable `dst`; empty/symlink/dir entries are always stored; otherwise `deflateInto` via reused 64 KB scratch plus CRC32. Writes local headers (UTF-8, DOS time), central directory (`made by Unix 2.0`, mode-derived `extAttr`), and EOCD.
