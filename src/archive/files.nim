## File gathering helpers, ported from archives.go.
##
## FilesFromDisk walks real paths; content is never read eagerly —
## each FileInfo opener memory-maps the file on demand (zero-copy).

import std/[strutils]
from std/os import walkDirRec, fileExists, dirExists, symlinkExists,
  expandSymlink, getFileInfo, lastPathPart, parentDir, isAbsolute, DirSep,
  `/`, splitFile, PathComponent, pcFile, pcDir, pcLinkToFile, pcLinkToDir
import ./types

proc metaForPath*(path: string): FileMeta =
  let info = getFileInfo(path, followSymlink = false)
  result.name = lastPathPart(path)
  result.size = info.size
  result.modTime = info.lastWriteTime
  result.isDir = info.kind == pcDir
  result.isSymlink = info.kind == pcLinkToDir or info.kind == pcLinkToFile
  result.isRegular = info.kind == pcFile
  result.mode =
    if result.isDir: ModeDir or 0o755
    elif result.isSymlink: ModeSymlink or 0o777
    else: 0o644

proc trimTopDir*(dir: string): string =
  ## Port of Go trimTopDir. Expects forward slashes.
  var top: string
  var start = 0
  if dir.len > 0 and dir[0] == '/':
    start = 1
  let pos = dir.find('/', start)
  if pos >= 0:
    top = dir[0 ..< pos]
  else:
    top = dir
  if dir.startsWith(top & "/"):
    return dir[top.len + 1 .. ^1]
  if dir == top:
    return ""
  return dir

proc nameOnDiskToNameInArchive*(nameOnDisk, rootOnDisk, rootInArchive: string;
    separator: char): string =
  ## Port of Go nameOnDiskToNameInArchive.
  var rootIn = rootInArchive
  if rootOnDisk.len > 0 and rootOnDisk[^1] == separator:
    rootIn = trimTopDir(rootIn)
  elif rootIn == "":
    rootIn = lastPathPart(rootOnDisk.strip(chars = {separator}))
  if rootIn == ".":
    rootIn = ""
  if rootIn.endsWith("/"):
    rootIn = rootIn & lastPathPart(rootOnDisk.strip(chars = {separator}))
  var trunc = nameOnDisk
  if trunc.startsWith(rootOnDisk):
    trunc = trunc[rootOnDisk.len .. ^1]
  trunc = trunc.replace('\\', '/').strip(chars = {'/'}, leading = true,
      trailing = false)
  if rootIn == "":
    return trunc
  if trunc == "":
    return rootIn.replace('\\', '/')
  return (rootIn & "/" & trunc).replace('\\', '/')

proc followSymlink*(filename: string; maxDepth = 40): tuple[path: string;
    meta: FileMeta] =
  ## Port of Go followSymlink. Resolves chains, detects loops.
  var visited = @[filename]
  var current = filename
  for _ in 0 ..< maxDepth:
    let target = expandSymlink(current)
    var linkPath = target
    if not linkPath.isAbsolute():
      linkPath = parentDir(current) / linkPath
    let m = metaForPath(linkPath)
    if not m.isSymlink:
      return (linkPath, m)
    if linkPath in visited:
      raise newException(ArchiveError, filename & ": symlink loop")
    visited.add(linkPath)
    current = linkPath
  raise newException(ArchiveError,
    filename & ": maximum symlink depth exceeded")

proc filesFromDisk*(ctx: ArchiveContext; opts: FromDiskOptions;
    filenames: openArray[(string, string)]): seq[FileInfo] =
  ## Port of Go FilesFromDisk. Keys are disk paths, values are archive paths.
  ## Nothing is read here: openers mmap files lazily on first use.
  result = @[]
  for (rootOnDisk, rootInArchive) in filenames:
    ctx.checkCancelled()
    if not fileExists(rootOnDisk) and not dirExists(rootOnDisk) and
        not symlinkExists(rootOnDisk):
      raise newException(ArchiveError, "not found: " & rootOnDisk)
    if dirExists(rootOnDisk) and not symlinkExists(rootOnDisk):
      for path in walkDirRec(rootOnDisk, yieldFilter = {pcFile, pcDir,
          pcLinkToFile, pcLinkToDir}):
        ctx.checkCancelled()
        var nameInArchive = nameOnDiskToNameInArchive(path, rootOnDisk,
            rootInArchive, DirSep)
        var meta = metaForPath(path)
        if meta.isDir and nameInArchive == "":
          continue
        var linkTarget = ""
        if meta.isSymlink:
          if opts.followSymlinks:
            let resolved = followSymlink(path)
            if resolved.meta.isDir:
              let sub = filesFromDisk(ctx, opts, [(resolved.path,
                  nameInArchive)])
              result.add(sub)
              continue
            else:
              meta = resolved.meta
          else:
            linkTarget = expandSymlink(path)
        if opts.clearAttributes:
          meta = noAttrMeta(meta)
        result.add(FileInfo(meta: meta, nameInArchive: nameInArchive,
            linkTarget: linkTarget, open: fileOpener(path)))
      # Also include the root dir itself when it maps to a non-empty name.
      let rootMeta = metaForPath(rootOnDisk)
      if rootMeta.isDir:
        let rootName = nameOnDiskToNameInArchive(rootOnDisk, rootOnDisk,
            rootInArchive, DirSep)
        if rootName != "" and not rootOnDisk.endsWith($DirSep):
          var already = false
          for f in result:
            if f.nameInArchive == rootName:
              already = true
              break
          if not already:
            result.add(FileInfo(meta: rootMeta, nameInArchive: rootName,
                open: stringOpener("")))
    else:
      let meta0 = metaForPath(rootOnDisk)
      var nameInArchive = nameOnDiskToNameInArchive(rootOnDisk, rootOnDisk,
          rootInArchive, DirSep)
      var linkTarget = ""
      var meta = meta0
      if meta.isSymlink and not opts.followSymlinks:
        linkTarget = expandSymlink(rootOnDisk)
      if opts.clearAttributes:
        meta = noAttrMeta(meta)
      result.add(FileInfo(meta: meta, nameInArchive: nameInArchive,
          linkTarget: linkTarget, open: fileOpener(rootOnDisk)))

type FsEntry* = object
  path*: string
  meta*: FileMeta
  data*: string   ## for regular files; empty for dirs/symlinks
  linkTarget*: string

proc filesFromEntries*(ctx: ArchiveContext; opts: FromFSOptions;
    entries: openArray[FsEntry]; rootOnFs, rootInArchive: string): seq[FileInfo] =
  ## In-memory FS variant (port of FilesFromFS shape without io/fs).
  result = @[]
  for e in entries:
    ctx.checkCancelled()
    let nameInArchive = nameOnDiskToNameInArchive(e.path, rootOnFs,
        rootInArchive, '/')
    if e.meta.isDir and nameInArchive == "":
      continue
    var meta = e.meta
    if opts.clearAttributes:
      meta = noAttrMeta(meta)
    result.add(FileInfo(meta: meta, nameInArchive: nameInArchive,
        linkTarget: e.linkTarget, open: stringOpener(e.data)))
