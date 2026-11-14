# Examples (examples/*.nim)

`examples/nim.cfg` sets `path:"../src"`, so no install is needed. Build with `clue build <file> --out:/tmp/<name>`.

## compress.nim

One-shot compression over all codecs plus file round trip.

```nim
import archive
for fmt in [cfGz, cfZlib, cfLz4, cfBz2, cfBrotli]:
  let enc = compress(fmt, payload)
  assert decompress(fmt, enc) == payload
compressFile(cfGz, src, enc)
decompressFile(cfGz, enc, back)
```

Also demonstrates corrupt-input handling: decompressing non-gzip bytes raises the codec error.

## archive_dir.nim

Directory to `tar.gz` and back:

```nim
import archive
archiveDir(afTar, demo, blob, "backup", compression = some(cfGz))
for e in extractAll(blob, ctx):
  echo e.name, ": ", e.data.len
```

Files are memory-mapped lazily; nothing is read up front.

## inspect.nim

In-memory entries to zip, then list and selectively extract:

```nim
import archive
import archive/files
import archive/io
let entries = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
    isRegular: true), data: "hello"),
], ".", "")
archiveFile(afZip, entries, path, ctx)
for name in listEntries(path, ctx):
  echo "entry: ", name
extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
  if info.isRegular():
    echo readAll(info.open())), ctx)
```

Shows `listEntries` peeking at names without decompressing contents, and lazy `info.open()` bodies inside the callback.

## encrypt.nim

Password file encryption, encrypted `tar.gz` archive, and raw-key bytes:

```nim
import archive/crypt
encryptFile("secret.txt", "secret.txt.enc", "correct horse")
decryptFile("secret.txt.enc", "secret_back.txt", "correct horse")
let blob = encryptArchive(afTar, flist, "correct horse", ctx,
  compression = some(cfGz))
decryptExtract("backup.tar.gz.enc", "correct horse", ctx,
  proc(c: ArchiveContext; info: FileInfo) =
    names.add(info.nameInArchive))
```

## vfs_walk.nim

One filesystem over dirs and archives:

```nim
import archive/vfs
let fsys = fileSystem(ctx, target, nil)
if fsys.kind == fkDir:
  for e in readDirFs(fsys, "."): echo e.name
else:
  walkArchive(fsys) do (path: string; e: DirEntry):
    echo path
for path, e in walkFs("../tests/testdata/self-tar.tar"):
  echo path
```

Covers `fileSystem` auto-detect, `readDirFs` for dirs, sorted `walkArchive`, recursive `walkFs`, and the path one-liner form.
