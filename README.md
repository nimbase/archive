<p align="center">
  Unified Nim library for archives and compression, ported from <code>mholt/archives</code> (Go)<br>
</p>

<p align="center">
  <code>clue install archive</code>
</p>

<p align="center">
  Requires Nim >= 2.2.10 and <code>nbrotli</code>; optional <code>nimsimd</code> feature for AVX2/SSE4.2 acceleration<br>
  <a href="https://nimbase.github.io/archive/">API reference</a><br>
  <img src="https://github.com/nimbase/archive/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/archive/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- Archive and compress across tar, zip, gzip, zlib (.zz), lz4, bzip2 and brotli with one uniform API.
- Own DEFLATE/gzip/zip/tar/crc32 ports from Go stdlib: no C bindings, no zippy dependency, brotli via `nbrotli`.
- Zero-copy I/O core: memory-mapped inputs, caller-reused output buffers, borrowed spans; no `streams` anywhere.
- Format detection by filename and magic bytes without consuming input, plus tar.gz-style two-layer composition.
- Virtual filesystem with uniform reads over dirs, files, archives and compressed archives.
- Optional `nimsimd` feature (AVX2 copies, match finding, SSE4.2 CRC32) behind a runtime silicon self-test.
- Per-block CRCs and stream checksums verified on every decode; corrupt inputs raise descriptive errors.
- Interop-tested both directions against system gzip/unzip, bzip2, lz4 and CPython zlib/bz2.

## Examples
Import the specific modules you need (`import archive` alone is a compile-time error by design):

```nim
import archive/types
import archive/io
import archive/registry
import archive/files
import archive/formats/tar
import archive/formats/gz

registerTar()
registerGz()

proc handler(ext: string): FormatHandler =
  for h in registeredFormats():
    if h.ext == ext: return h
  raise newException(ArchiveError, "not registered: " & ext)
```

Create `backup.tar.gz` from a directory (files are memory-mapped lazily, nothing is read up front):

```nim
var ctx: ArchiveContext
let files = filesFromDisk(ctx, FromDiskOptions(), [("my-docs", "docs")])
let ca = CompressedArchive(archival: handler(".tar"),
  extraction: handler(".tar"), compression: handler(".gz"))
let dst = newOutput()
ca.archiveTo(ctx, dst, files)
writeFile("backup.tar.gz", take(dst))
```

Identify a stream and extract selectively:

```nim
var ctx: ArchiveContext
let inp = openInputFile("backup.tar.gz")
let res = identifyFormat("backup.tar.gz", inp)
res.compressed.extractFrom(ctx, inp) do (c: ArchiveContext; info: FileInfo):
  if info.isRegular() and info.nameInArchive.endsWith(".nim"):
    echo info.nameInArchive, ": ", readAll(info.open()).len, " bytes"
```

One-shot compression with a reusable buffer:

```nim
import archive/formats/bz2
registerBz2()
let dst = newOutput()
handler(".bz2").compress(openInputString("hello ".repeat(100)), dst)
let back = newOutput()
handler(".bz2").decompress(toInput(dst), back)
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

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/archive/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/archive/fork)

### 🎩 License
MIT license | Nim Community.
