## RAR 5.0/7.0 archives: clean-room container + Unpack50/70 LZ codec.
## Writes stored (method 0) or compressed (m1..m5, per-file STORE fallback,
## opt-in E8E9/DELTA/ARM filters, Unpack70 via algoVer 1); reads stored and
## compressed (solid groups, filters), per-file + header AES-256-CBC
## encryption, and multivolume sets. Run from this directory:
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

# encrypted + filtered + multivolume + Unpack70 in one go (small lg2 for speed)
let eblob = block:
  let dst = newOutput()
  archiveRar(rarfmt.Rar(meth: 3, password: "hunter2", kdfLg2: 4,
    useFilters: true, algoVer: 1), ctx, dst, flist)
  take(dst)
writeFile("hello_e.rar", eblob)
echo "encrypted+filtered+v1: ", eblob.len, " bytes"
var eback = ""
extractRar(rarfmt.Rar(password: "hunter2"), ctx, openInputString(eblob)) do (
    c: ArchiveContext; info: FileInfo):
  if info.isRegular() and info.nameInArchive == "repeat.txt":
    eback = readAll(info.open())
echo "encrypted roundtrip ok: ", eback == "lorem ipsum ".repeat(75)
let vols = archiveRarVolumes(rarfmt.Rar(meth: 1), ctx, flist, 1024)
echo "multivolume parts: ", vols.len
var vinps: seq[Input] = @[]
for v in vols:
  vinps.add(openInputString(v))
var vnames: seq[string] = @[]
extractRarVolumes(rarfmt.Rar(), ctx, vinps) do (
    c: ArchiveContext; info: FileInfo):
  vnames.add(info.nameInArchive)
echo "multivolume entries: ", vnames

# caps are per-call: refuse dictionaries above the budget before allocating
var tight = ArchiveContext(maxRarDictBytes: 1024)
try:
  extractFile("hello.rar", proc(c: ArchiveContext; info: FileInfo) =
    discard, tight)
  echo "store entries ignore the dict cap (no dictionary involved)"
except ArchiveError as e:
  echo "capped: ", e.msg
