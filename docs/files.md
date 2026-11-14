# Building file lists (src/archive/files.nim)

Turns disk trees or in-memory entries into `seq[FileInfo]` ready for `archiveData` / `archiveFile` / `encryptArchive`.

## FsEntry (src/archive/files.nim:148)

```nim
FsEntry* = object
  path*: string
  meta*: FileMeta
  data*: string      # regular file content
  linkTarget*: string
```

`data` is for regular files; empty for dirs/symlinks.

## Path helpers

### metaForPath (src/archive/files.nim:12)

```nim
proc metaForPath*(path: string): FileMeta
```

`lstat` mapping (`followSymlink=false`): `name` is last path part, `size`/`modTime` from `getFileInfo`, `isDir` for dirs, `isSymlink` for link-to-dir/file, `isRegular` for files. Modes: dir `ModeDir|0755`, symlink `ModeSymlink|0777`, else `0644`. Raises `OSError` when missing.

### trimTopDir (src/archive/files.nim:25)

Strips the first forward-slash component: `"a/b" -> "b"`, `"a" -> ""`. Pure string op.

### nameOnDiskToNameInArchive (src/archive/files.nim:42)

```nim
proc nameOnDiskToNameInArchive*(nameOnDisk, rootOnDisk, rootInArchive: string; separator: char): string
```

Maps a disk path to a slash-separated archive name. Handles trailing-separator roots, empty `"."` roots, and backslash normalization. No errors.

### followSymlink (src/archive/files.nim:65)

```nim
proc followSymlink*(filename: string; maxDepth = 40): tuple[path: string; meta: FileMeta]
```

Resolves a symlink chain via `expandSymlink`, joining relative targets with `parentDir`. Returns the first non-symlink. Raises `ArchiveError` on loops or depth overflow.

## filesFromDisk (src/archive/files.nim:85)

```nim
proc filesFromDisk*(ctx: ArchiveContext; opts: FromDiskOptions;
  filenames: openArray[(string, string)]): seq[FileInfo]
```

Input is `(rootOnDisk, rootInArchive)` pairs. Nothing is read up front; `open` is `fileOpener(path)` (lazy mmap), except synthetic root-dir entries use `stringOpener("")`.

Behavior:

- Dir root (and not a symlink): `walkDirRec` with files, dirs, and both symlink kinds. Each entry maps via `nameOnDiskToNameInArchive`. Empty dir names are skipped.
- Symlink entries: when `followSymlinks` is true, resolve and either recurse (dir) or use resolved meta; otherwise keep `linkTarget = expandSymlink`.
- `clearAttributes` applies `noAttrMeta`.
- The root dir itself is added when `rootInArchive` is non-empty without trailing separator and not a duplicate.
- File/symlink root: single `FileInfo` with the same symlink and attribute handling.

Errors: `ArchiveError("not found: ...")`, cancel, symlink loop/depth.

## filesFromEntries (src/archive/files.nim:154)

```nim
proc filesFromEntries*(ctx: ArchiveContext; opts: FromFSOptions;
  entries: openArray[FsEntry]; rootOnFs, rootInArchive: string): seq[FileInfo]
```

In-memory variant. Maps `e.path` the same way, skips empty dir names, applies `clearAttributes`, sets `open = stringOpener(e.data)` and `linkTarget = e.linkTarget`. `followSymlinks` is unused here. Only error is cancel.

```nim
import archive/files
let entries = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
    isRegular: true), data: "hello"),
], ".", "")
```
