## One virtual filesystem over dirs, archives, and compressed
## archives: fileSystem detects them by name and magic bytes.
## Run from this directory:
##   `clue build examples/vfs_walk.nim --out:/tmp/vfs_walk && (cd examples && /tmp/vfs_walk)`

import archive
import archive/vfs        # fileSystem, walkArchive, walkFs, readDirFs

var ctx: ArchiveContext
# walkArchive visits every entry of an archive in sorted order;
# plain dirs list one level via readDirFs
for target in ["../tests/testdata", "../tests/testdata/self-tar.tar"]:
  let fsys = fileSystem(ctx, target, nil)
  echo "--- ", target
  if fsys.kind == fkDir:
    for e in readDirFs(fsys, "."):
      echo (if e.isDir: "dir  " else: "file ") & e.name
  else:
    walkArchive(fsys) do (path: string; e: DirEntry):
      echo (if e.isDir: "dir  " else: "file ") & path

# walkFs is the recursive iterator form over any fs kind, from any
# subtree root ("." = whole fs); a root naming a file yields just it
echo "--- walkFs dir, whole tree"
let dirFs = fileSystem(ctx, "../tests/testdata", nil)
for path, e in walkFs(dirFs):
  echo (if e.isDir: "dir  " else: "file ") & path

# shortest form: a path opens its own filesystem with an internal context
echo "--- walkFs archive one-liner"
for path, e in walkFs("../tests/testdata/self-tar.tar"):
  echo (if e.isDir: "dir  " else: "file ") & path
