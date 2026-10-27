import std/[unittest, os]
import archive/types
import archive/io
import archive/registry
import archive/files
import archive/vfs



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
    let ca = CompressedArchive(archival: afTar, compression: cfGz)
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

  test "walkFs over dir tree":
    var ctx: ArchiveContext
    let base = joinPath(getTempDir(), "nimarchive_walkrec")
    removeDir(base)
    createDir(joinPath(base, "sub", "deep"))
    writeFile(joinPath(base, "top.txt"), "top")
    writeFile(joinPath(base, "sub", "mid.txt"), "mid")
    writeFile(joinPath(base, "sub", "deep", "leaf.txt"), "leaf")
    let fsys = fileSystem(ctx, base, nil)
    var paths: seq[string] = @[]
    for p, e in walkFs(fsys):
      paths.add(p)
      # every yielded path resolves back through dirFullPath
      check(fileExists(dirFullPath(fsys, p)) or
        dirExists(dirFullPath(fsys, p)))
    check("top.txt" in paths)
    check("sub/mid.txt" in paths)
    check("sub/deep/leaf.txt" in paths)
    check(paths.len == 5) # 2 dirs + 3 files
    # subtree root
    var sub: seq[string] = @[]
    for p, e in walkFs(fsys, "sub"):
      sub.add(p)
    check(sub == @["sub/deep", "sub/deep/leaf.txt", "sub/mid.txt"])
    # file root yields just that file
    var one: seq[string] = @[]
    for p, e in walkFs(fsys, "top.txt"):
      one.add(p)
      check(not e.isDir)
    check(one == @["top.txt"])
    removeDir(base)

  test "walkFs over archive":
    var ctx: ArchiveContext
    let fsys = fileSystem(ctx, "tests/testdata/gnu-hardlinks.tar", nil)
    var paths: seq[string] = @[]
    for p, e in walkFs(fsys):
      paths.add(p)
    check(paths == @["dir-1", "dir-1/dir-2", "dir-1/dir-2/file-a",
      "dir-1/dir-2/file-b"])
    # subtree root
    var sub: seq[string] = @[]
    for p, e in walkFs(fsys, "dir-1/dir-2"):
      sub.add(p)
    check(sub == @["dir-1/dir-2/file-a", "dir-1/dir-2/file-b"])
    # file root yields just that file, openable via openArchive
    var one = 0
    for p, e in walkFs(fsys, "dir-1/dir-2/file-a"):
      check(p == "dir-1/dir-2/file-a")
      check(not e.isDir)
      discard openArchive(fsys, p)
      inc one
    check(one == 1)

  test "walkFs over single file":
    var ctx: ArchiveContext
    let fsys = fileSystem(ctx, "tests/testdata/interop.txt", nil)
    check(fsys.kind == fkFile)
    var paths: seq[string] = @[]
    for p, e in walkFs(fsys):
      paths.add(p)
      check(not e.isDir)
    check(paths == @["interop.txt"])

  test "walkFs from path opens its own filesystem":
    var paths: seq[string] = @[]
    for p, e in walkFs("tests/testdata/gnu-hardlinks.tar"):
      paths.add(p)
    check(paths == @["dir-1", "dir-1/dir-2", "dir-1/dir-2/file-a",
      "dir-1/dir-2/file-b"])
    var sub: seq[string] = @[]
    for p, e in walkFs("tests/testdata/gnu-hardlinks.tar",
        "dir-1/dir-2"):
      sub.add(p)
    check(sub == @["dir-1/dir-2/file-a", "dir-1/dir-2/file-b"])
    var one: seq[string] = @[]
    for p, e in walkFs("tests/testdata/interop.txt"):
      one.add(p)
    check(one == @["interop.txt"])
