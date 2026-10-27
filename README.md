<p align="center">
  Unified Nim library for creating/extracting archives and compress/decompress files<br>
  SIMD-accelerated, zero-copy I/O core, walk virtual file system<br>
  Supporting `.tar`, `.zip`, `.gz`, `.zz`, `.lz4`, `.bz2`, `.br`
</p>

<p align="center">
  <code>clue install archive</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/archive/">API reference</a><br>
  <img src="https://github.com/nimbase/archive/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/archive/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- Archive and compress across tar, zip, gzip, zlib (.zz), lz4, bzip2 and brotli with one uniform API
- `Format` enum instead of extension strings: `handler(fmtBz2)`, `compress(fmtGz, data)`; typos are compile errors, ext/media-type tables are canonical
- High-level one-shots: `compress`/`decompress` (strings, files, buffers), `archiveDir`/`archiveData`, auto-identifying `extractFile`/`extractAll`/`listEntries`
- Own DEFLATE/gzip/zip/tar/crc32 ports from Go stdlib: no C bindings, no zippy dependency, brotli via [pkg/nbrotli](https://github.com/nimbase/nbrotli)
- Zero-copy I/O core: memory-mapped inputs, caller-reused output buffers, borrowed spans; no `streams` anywhere
- Format detection by filename and magic bytes without consuming input, plus tar.gz-style two-layer composition
- Virtual filesystem with uniform reads over dirs, files, archives and compressed archives
- Optional `nimsimd` feature (AVX2 copies, match finding, SSE4.2 CRC32) behind a runtime silicon self-test
- Per-block CRCs and stream checksums verified on every decode; corrupt inputs raise descriptive errors
- Interop-tested both directions against system `gzip`/`unzip`, `bzip2`, `lz4` and CPython `zlib`/`bz2`

## Examples
High-level API first (`import archive` + specific modules for types);
zero-copy `Input`/`Output` plumbing is still there when you need it:

```nim
import std/[options, strutils]
import archive
registerDefaults()

# one-shot compression with per-call level (0 = codec default)
let enc = compress(fmtBz2, "hello ".repeat(100), level = 9)
assert decompress(fmtBz2, enc) == "hello ".repeat(100)

# directory -> backup.tar.gz -> read back (files memory-mapped lazily,
# nothing is read up front)
var ctx: ArchiveContext
archiveDir(fmtTar, "my-docs", "backup.tar.gz", "docs",
  compression = some(fmtGz))
for e in extractAll("backup.tar.gz", ctx):
  if e.name.endsWith(".txt"):
    echo e.name, ": ", e.data.len, " bytes"
```

Same work with reusable buffers instead of fresh strings:

```nim
import archive/io
let dst = newOutput()
compressInto(fmtGz, openInputString("hello ".repeat(100)), dst)
let back = newOutput()
decompressInto(fmtGz, toInput(dst), back)
assert take(back) == "hello ".repeat(100)
```

Browse an archive through the virtual filesystem:

```nim
import archive/vfs
var ctx: ArchiveContext
let fsys = fileSystem(ctx, "archive.tar", nil)
for e in readDirFs(fsys, "."):
  echo e.name
let r = openArchive(fsys, "readme.txt")
echo readAll(r.inp)
```

## Roadmap
- [x] tar (ustar/pax, symlinks, hardlinks, insert/append)
- [x] zip (deflate/store, insert/replace)
- [x] gzip (.gz), zlib (.zz), lz4 (.lz4), bzip2 (.bz2)
- [x] brotli (.br) via `nbrotli` (decode full, store-only encode)
- [x] `Identify` by name and magic bytes, `CompressedArchive` composition (tar.gz, tar.bz2, ...)
- [x] Virtual filesystem (DirFS, ArchiveFS, DeepFS, path helpers)
- [x] SIMD acceleration behind the `nimsimd` feature with silicon self-test
- [ ] xz (.xz, LZMA2 framing + range coder)
- [ ] zstd (.zst)
- [ ] snappy/s2 (.sz/.s2, own port)
- [ ] lzip (.lz), minlz (.mz)
- [ ] rar / 7z read-only (likely needs C bindings or new ports)


This is a port of [mholt/archives](https://github.com/mholt/archives) (Go)

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/archive/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/archive/fork)

### 🎩 License
MIT license | Nim Community.
