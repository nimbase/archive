## RAR 5.0/7.0 archives: clean-room container + Unpack50/70 LZ codec.
## Writes stored (method 0) or compressed (methods m1..m5, encoder picks
## STORE per file when packing gains nothing); reads stored and
## compressed (solid groups, DELTA/E8/E8E9/ARM filters). Run from this
## directory:
##   `clue build examples/rar.nim --out:/tmp/rar && (cd examples && /tmp/rar)`

import std/strutils
import archive
import archive/files

var ctx: ArchiveContext

# write: regular files, dirs, symlinks — stored by default
let flist = filesFromEntries(ctx, FromFSOptions(), [
  FsEntry(path: "hello.txt", meta: FileMeta(name: "hello.txt", size: 5,
    isRegular: true), data: "hello"),
  FsEntry(path: "sub", meta: FileMeta(name: "sub", isDir: true), data: ""),
  FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
    isSymlink: true), data: "", linkTarget: "hello.txt"),
  FsEntry(path: "repeat.txt", meta: FileMeta(name: "repeat.txt", size: 900,
    isRegular: true), data: "lorem ipsum ".repeat(75)),
], ".", "")
let blob = archiveData(afRar, flist, ctx)
writeFile("hello.rar", blob)
echo "wrote ", blob.len, " bytes"

# same content compressed: method selects effort (m1..m5), per-file
# STORE fallback keeps incompressible entries small
import archive/formats/rar as rarfmt
let cblob = block:
  let dst = newOutput()
  archiveRar(rarfmt.Rar(meth: 3), ctx, dst, flist)
  take(dst)
writeFile("hello_c.rar", cblob)
echo "compressed: ", cblob.len, " bytes"

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
