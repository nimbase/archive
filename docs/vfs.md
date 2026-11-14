# Virtual filesystem (src/archive/vfs.nim)

Uniform reads over dirs, files, archives, and compressed archives. Symlinks are listed, never followed.

## Model

There are no distinct `DirFS` / `ArchiveFS` types. One discriminated `Fs` covers all cases; `DeepFs` caches nested filesystems for paths containing archives.

```nim
FsKind* = enum fkFile, fkDir, fkArchive
DirEntry* = object
  name*: string
  isDir*: bool
  meta*: FileMeta
Fs* = ref object
  case kind*: FsKind
  of fkFile: filePath*: string; fileComp*: Option[CompressionFormat]
  of fkDir: dirPath*: string
  of fkArchive: archData*: Input; archFormat*: ArchiveFormat;
    archComp*: Option[CompressionFormat]; prefix*: string;
    actx*: ArchiveContext; contents*: Table[string, FileMeta];
    dirs*: Table[string, seq[DirEntry]]; indexed*: bool
DeepFs* = ref object
  root*: string; ctx*: ArchiveContext; inners*: Table[string, Fs]
```

## Paths

- `isValidFsPath(name)` (src/archive/vfs.nim:48): false for empty, NUL, leading/trailing `/`, or `""` / `"."` / `".."` segments; `"."` itself is valid.
- `checkFsName(name, op)` raises `ArchiveError` on invalid paths.
- `joinPrefix(prefix, name)` scopes sub-filesystems; `cleanArchiveName(n)` lexically normalizes (`"."` skipped, `".."` pops, empty becomes `"."`).
- `pathWithoutTopDir(p)` strips up to the first `/`.

## Dir and file reads

| proc | behavior |
| ---- | -------- |
| `statPath(p)` (vfs.nim:66) | lstat wrapper, fixed mode `0644` |
| `openFileFs(fsys, name)` (vfs.nim:77) | `fkFile` only; allows `"."` / basename / full path; decompresses via `decompressInto` when `fileComp` is set |
| `statFileFs(fsys)` (vfs.nim:92) | `statPath(filePath)` |
| `dirFullPath(fsys, name)` (vfs.nim:98) | `fkDir` only; `"."` maps to `dirPath` |
| `readDirFs(fsys, name)` (vfs.nim:105) | one level: `walkDir` for dirs, single entry for files, index lookup for archives |
| `readDirArchive(fsys, name)` (vfs.nim:208) | lazy `indexArchive`; raises when path is a file |
| `openArchive(fsys, name)` (vfs.nim:219) | dir returns `(nil, meta, entries)`; file re-scans for content span and returns `(Input, meta, @[])`; decompresses to temp `Input` first when `archComp` is set |
| `walkArchive(fsys, visit)` (vfs.nim:263) | sorted-by-key walk over the archive index |
| `walkFs(fsys, root=".")` iterator (vfs.nim:276) | recursive sorted pre-order over any kind; file root yields just it |

## fileSystem and walkFs shorthands

```nim
proc fileSystem*(ctx: ArchiveContext; filename: string; inp: Input = nil): Fs
iterator walkFs*(fsys: Fs; root = "."): tuple[path: string; entry: DirEntry]
iterator walkFs*(path: string; root = "."): tuple[path: string; entry: DirEntry]
proc listEntries*(fsys: Fs; root = "."): seq[string]  # in src/archive.nim:451
```

Filename-only `fileSystem` (src/archive/vfs.nim:329):

- Dir on disk (not symlink) becomes `fkDir`.
- Otherwise `identify` by name plus mmap: archival becomes `fkArchive`, compression-only becomes `fkFile` with `fileComp`, no match becomes plain `fkFile`.
- Encrypted blobs raise `ArchiveError("encrypted archive, use decryptExtract/decryptFile: ...")`.

Input-driven `fileSystem` (`inp != nil`, `filename` is a hint):

- Archival becomes `fkArchive` over `inp`.
- Compression-only without a filename raises `ArchiveError`.
- Unmatched input without a filename-backed file raises `ArchiveError`.

```nim
import archive/vfs
let fsys = fileSystem(ctx, "out.tar.gz", nil)
for path, e in walkFs(fsys):
  echo (if e.isDir: "dir  " else: "file ") & path
for path, e in walkFs("out.tar.gz"):
  echo path
```

## DeepFS: paths through archives

Helpers for `real/path inner/path` addressing (src/archive/vfs.nim:388-456):

- `archiveExtensions`: known suffix list.
- `pathIsArchive(path)`: case-insensitive suffix match.
- `pathContainsArchive(path)`: suffix plus `/` substring.
- `splitArchivePath(path)`: first `/`-separated component with an archive suffix splits to `(realPath, inner)`; no hit returns `(path, "")`.
- `getInnerFs(d, realPath)`: cached `fileSystem`; nil on `CatchableError`.
- `deepOpen(d, name)`: archive-inner file returns `(Input, meta)`; archive-inner dir raises `ArchiveError("open ...: is a directory")`, otherwise opens the real file.
