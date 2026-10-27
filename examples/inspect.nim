## Describe files in code, write a zip, then inspect and
## selectively extract it.
## Run: `clue build examples/inspect.nim --out:/tmp/inspect && /tmp/inspect`

import std/strutils
from std/os import getTempDir, joinPath
import archive
import archive/files      # filesFromEntries, FsEntry
import archive/io         # readAll, openInputString, ...

var ctx: ArchiveContext
# entries pair an on-disk path with its path inside the archive;
# here both live in memory via the data field
let entries = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
    isRegular: true), data: "hello"),
  FsEntry(path: "sub/b.txt", meta: FileMeta(name: "b.txt", size: 5,
    isRegular: true), data: "world"),
], ".", "")

let path = joinPath(getTempDir(), "inspect_demo.zip")
archiveToFile(afZip, entries, path, ctx)
echo "wrote ", path

# peek at entry paths without decompressing contents
for name in listEntries(path, ctx):
  echo "entry: ", name

# the callback runs once per entry: filter inside it, read bodies lazily
extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
  if info.isRegular() and info.nameInArchive.endsWith(".txt"):
    echo(info.nameInArchive & " -> " & readAll(info.open())), ctx)
