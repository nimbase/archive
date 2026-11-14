# Shared types (src/archive/types.nim)

Core types ported from `mholt/archives`. Go uses `io/fs.FileInfo` and `io.Reader`; here file metadata is explicit and I/O uses `archive/io` (`Input` / `Output` over memfiles). Re-exported by `import archive`.

## Errors

```nim
ArchiveError* = object of CatchableError  # base for all archive failures
NoMatchError* = object of ArchiveError    # identify found nothing
SkipDir* = object of ArchiveError         # raise from FileHandler to skip a dir
SkipAll* = object of ArchiveError         # raise from FileHandler to stop walk
```

## File metadata

```nim
FileMode* = distinct int
FileMeta* = object
  name*: string       # base name, not full archive path
  size*: int64
  mode*: int          # raw Unix mode bits (permissions + file type)
  modTime*: Time
  isDir*: bool
  isSymlink*: bool
  isRegular*: bool
FileInfo* = object
  meta*: FileMeta
  header*: RootRef          # format-specific header, nil when creating
  nameInArchive*: string   # slash-separated
  linkTarget*: string
  open*: proc(): Input {.closure.}  # content opener
```

Helpers (`src/archive/types.nim:155-161,202-212`):

- `isDir / isSymlink / isRegular(f)` project `meta`.
- `size / name / mode / modTime(f)` project `meta`.
- `stringOpener(data)` returns a fresh zero-copy opener per call (avoids loop-capture bug).
- `fileOpener(path)` returns an opener that mmaps on each `open()`.
- `viewOpener(s, keep)` borrows a span and retains `keep`.
- `noAttrMeta(m)` zeroes `modTime` and masks `mode` to dir/symlink/perm bits.
- `baseNameV(path)` is `/`-split basename, platform independent.
- `ModeDir = 0o040000`, `ModeSymlink = 0o120000`, `ModePermMask = 0o7777` (src/archive/types.nim:147-150).

## Formats

```nim
CompressionFormat* = enum
  cfGz = ".gz"
  cfZlib = ".zz"
  cfLz4 = ".lz4"
  cfBz2 = ".bz2"
  cfBrotli = ".br"
ArchiveFormat* = enum
  afTar = ".tar"
  afZip = ".zip"
  afRar = ".rar"   # out of scope for this docs pass, see rar-stub.md
MediaType* = enum
  mtTar, mtZip, mtRar, mtGz, mtZlib, mtLz4, mtBz2, mtBrotli
```

`$fmt` is the canonical extension. Passing an archive to `decompress` fails at compile time; there is no runtime registry. `mediaTypeOf` maps each format to its `MediaType` (src/archive/types.nim:80-90).

## Context, progress, cancel

```nim
ProgressInfo* = object
  path*: string
  index*: int
  total*: int   # -1 when unknown
  size*: int64  # -1 when unknown
ProgressCallback* = proc(info: ProgressInfo) {.closure.}
FileHandler* = proc(ctx: ArchiveContext; info: FileInfo) {.closure.}
ArchiveContext* = object
  cancelled*: ptr bool
  progress*: ProgressCallback
  maxRarDictBytes*: int       # RAR-only, 64 MB default
  maxRarUnpackedBytes*: int64 # RAR-only, 4 GB default
```

- `cancelled(ctx)` is nil-safe. `checkCancelled(ctx)` raises `ArchiveError` if set (src/archive/types.nim:163-166).
- `reportProgress(ctx, path, index, total, size)` is a no-op when `progress` is nil; calls run synchronously on the caller thread (src/archive/types.nim:170).
- `MatchResult = object(byName, byStream: bool)` with `matched(mr) = byName or byStream`.

## Builder options

```nim
FromDiskOptions* = object
  followSymlinks*: bool
  clearAttributes*: bool
FromFSOptions* = object
  followSymlinks*: bool
  clearAttributes*: bool
ArchiveAsyncJob* = object
  file*: FileInfo
  result*: proc(err: string) {.closure.}  # "" = success
```

See `files.md` for how the options affect `filesFromDisk` / `filesFromEntries`.
