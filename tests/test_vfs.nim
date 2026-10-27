import std/[unittest, os]
import archive/types
import archive/io
import archive/registry
import archive/files
import archive
import archive/vfs
import archive/formats/tar
import archive/formats/gz

registerTar()
registerGz()


suite "vfs":
  test "dir filesystem lists entries":
    var ctx: ArchiveContext
    let fsys = fileSystem(ctx, "tests/testdata", nil)
    check(fsys.kind == fkDir)
    let entries = readDirFs(fsys, ".")
    check(entries.len >= 4)

  test "archive filesystem reads reference tar":
    var ctx: ArchiveContext
    let fsys = fileSystem(ctx, "tests/testdata/self-tar.tar", nil)
    check(fsys.kind == fkArchive)
    let entries = readDirFs(fsys, ".")
    check(entries.len > 0)
    let r = openArchive(fsys, entries[0].name)
    check(r.meta.name.len > 0)

  test "archive filesystem walks all entries":
    var ctx: ArchiveContext
    let fsys = fileSystem(ctx, "tests/testdata/gnu-hardlinks.tar", nil)
    var count = 0
    walkArchive(fsys) do (path: string; e: DirEntry):
      inc count
      check(path.len > 0)
    check(count > 0)

  test "tar.gz via filesystem":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "note.txt", meta: FileMeta(name: "note.txt", size: 4,
        isRegular: true), data: "note")], ".", "")
    let ca = compressedArchive(fmtTar, fmtGz)
    let dst = newOutput()
    ca.archiveTo(ctx, dst, files)
    let blob = take(dst)
    let tmpPath = joinPath(getTempDir(), "nimarchive_test.tar.gz")
    let f = open(tmpPath, fmWrite)
    f.write(blob)
    f.close()
    let fsys = fileSystem(ctx, tmpPath, nil)
    check(fsys.kind == fkArchive)
    let entries = readDirFs(fsys, ".")
    check(entries.len == 1)
    check(entries[0].name == "note.txt")

  test "path helpers":
    check(pathIsArchive("backup.TAR.GZ"))
    check(pathIsArchive("a.zip"))
    check(not pathIsArchive("a.txt"))
    check(pathContainsArchive("x/a.zip/inner"))
    let (real, inner) = splitArchivePath("base/dir/a.zip/sub/file.txt")
    check(inner == "sub/file.txt")
