# Getting started

## Install

Requires Nim >= 2.2.10, plus `nbrotli` and `nimcypher`.

```bash
clue install archive
```

`examples/nim.cfg` sets `path:"../src"`, so examples build without install:

```bash
clue build examples/compress.nim --out:/tmp/compress && /tmp/compress
```

## Imports

High-level API first (covers types and dispatch):

```nim
import archive
```

Add low-level modules only when needed:

```nim
import archive/io      # Input/Output plumbing
import archive/files   # filesFromEntries, FsEntry
import archive/vfs     # fileSystem, walkFs
import archive/crypt   # encryptFile, decryptFile
```

Nothing is re-exported except `archive/registry` and `archive/types` from `archive`. No global registry exists. Every proc is safe to call from any thread; there is no shared state.

## First round trips

One-shot compression (level 0 = codec default):

```nim
import archive
let enc = compress(cfBz2, "hello ".repeat(100), level = 9)
assert decompress(cfBz2, enc) == "hello ".repeat(100)
```

Directory to `tar.gz` and back (files are memory-mapped lazily, internal context unless you pass one):

```nim
import std/options
import archive
archiveDir(afTar, "my-docs", "backup.tar.gz", "docs",
  compression = some(cfGz))
for e in extractAll("backup.tar.gz"):
  echo e.name, ": ", e.data.len
```

Extract to disk with zip-slip protection built in:

```nim
import archive
extractFile("backup.tar.gz", "restored")
```

See `examples.md` for the full runnable set: `compress.nim`, `archive_dir.nim`, `inspect.nim`, `encrypt.nim`, `vfs_walk.nim`.
