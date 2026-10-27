## Archive a directory to tar.gz, then read it back.
## Run: `clue build examples/archive_dir.nim --out:/tmp/archive_dir && /tmp/archive_dir`

import std/[options, strutils]
from std/os import getTempDir, joinPath, createDir
import archive

# build a small demo tree in the temp dir
let demo = joinPath(getTempDir(), "archive_demo")
createDir(joinPath(demo, "docs"))
writeFile(joinPath(demo, "docs", "readme.txt"), "hello archive\n")
writeFile(joinPath(demo, "run.sh"), "#!/bin/sh\necho hi\n")

var ctx: ArchiveContext
let blob = joinPath(getTempDir(), "demo.tar.gz")
# files are memory-mapped lazily: nothing is read up front
archiveDir(afTar, demo, blob, "backup", compression = some(cfGz))
echo "wrote ", blob

# extractAll returns (archive path, content) pairs for regular files
for e in extractAll(blob, ctx):
  echo e.name, ": ", e.data.len, " bytes"
