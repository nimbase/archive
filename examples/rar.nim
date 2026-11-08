## RAR 5.0/7.0 archives: clean-room container + Unpack50/70 LZ decoder.
## Writes stored (method 0) entries; reads stored and compressed
## (m1..m5, solid groups, DELTA/E8/E8E9/ARM filters). Run from this
## directory:
##   `clue build examples/rar.nim --out:/tmp/rar && (cd examples && /tmp/rar)`

import archive
import archive/files

var ctx: ArchiveContext

# write: regular files, dirs, symlinks — all stored (method 0)
let flist = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "hello.txt", meta: FileMeta(name: "hello.txt", size: 5,
    isRegular: true), data: "hello"),
  FsEntry(path: "sub", meta: FileMeta(name: "sub", isDir: true), data: ""),
  FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
    isSymlink: true), data: "", linkTarget: "hello.txt"),
], ".", "")
let blob = archiveData(afRar, flist, ctx)
writeFile("hello.rar", blob)
echo "wrote ", blob.len, " bytes"

# read back: list, then extract
echo "entries: ", listEntries("hello.rar")
extractFile("hello.rar", proc(c: ArchiveContext; info: FileInfo) =
  if info.isRegular():
    echo info.nameInArchive, ": ", readAll(info.open()))
extractFile("hello.rar", "hello_out")
echo "extracted to hello_out/"

# caps are per-call: refuse dictionaries above the budget before allocating
var tight = ArchiveContext(maxRarDictBytes: 1024)
try:
  extractFile("hello.rar", proc(c: ArchiveContext; info: FileInfo) =
    discard, tight)
  echo "store entries ignore the dict cap (no dictionary involved)"
except ArchiveError as e:
  echo "capped: ", e.msg
