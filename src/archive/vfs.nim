## Virtual file systems, ported from fs.go.
##
## Provides uniform read access over directories, archives, compressed
## archives, individual files and inputs: FileFS, DirFS, ArchiveFS,
## DeepFS, plus TopDir* helpers and PathIsArchive lexing.
## Everything reads through zero-copy Inputs; ArchiveFS indexes once.

import std/[tables, strutils, algorithm, options]
from std/os import dirExists, fileExists, symlinkExists, walkDir,
  getFileInfo, lastPathPart, DirSep, `/`, pcDir, pcFile,
  pcLinkToDir, pcLinkToFile
import ./io
import ./types
import ./registry

type
  FsKind* = enum
    fkFile, fkDir, fkArchive

  DirEntry* = object
    name*: string
    isDir*: bool
    meta*: FileMeta

  Fs* = ref object
    case kind*: FsKind
    of fkFile:
      filePath*: string
      fileComp*: Option[CompressionFormat]  ## optional decompressor
    of fkDir:
      dirPath*: string
    of fkArchive:
      archData*: Input       ## owned (mmap or string); zero-copy source
      archFormat*: ArchiveFormat
      archComp*: Option[CompressionFormat] ## some when archived compressed
      prefix*: string
      actx*: ArchiveContext
      contents*: Table[string, FileMeta]
      dirs*: Table[string, seq[DirEntry]]
      indexed*: bool

  DeepFs* = ref object
    root*: string
    ctx*: ArchiveContext
    inners*: Table[string, Fs]

proc isValidFsPath*(name: string): bool =
  if name.len == 0:
    return false
  if name.contains('\0'):
    return false
  if name == ".":
    return true
  if name.startsWith("/") or name.endsWith("/"):
    return false
  for part in name.split('/'):
    if part == "" or part == "." or part == "..":
      return false
  true

proc checkFsName*(name, op: string) =
  if not isValidFsPath(name):
    raise newException(ArchiveError, op & " " & name & ": invalid path")

proc statPath*(p: string): FileMeta =
  let info = getFileInfo(p, followSymlink = false)
  FileMeta(name: lastPathPart(p), size: info.size, mode: 0o644,
      modTime: info.lastWriteTime, isDir: info.kind == pcDir,
      isSymlink: info.kind in {pcLinkToDir, pcLinkToFile},
      isRegular: info.kind == pcFile)

proc readDirArchive*(fsys: Fs; name: string): seq[DirEntry]

# ---------- FileFS ----------

proc openFileFs*(fsys: Fs; name: string): Input =
  ## Zero-copy open of the single file (decompressing when needed).
  assert fsys.kind == fkFile
  if name != "." and name != lastPathPart(fsys.filePath) and
      name != fsys.filePath:
    checkFsName(name, "open")
    raise newException(ArchiveError, "open " & name & ": not found")
  checkFsName(if name == fsys.filePath: "." else: name, "open")
  let inp = openInputFile(fsys.filePath)
  if fsys.fileComp.isNone:
    return inp
  let dst = newOutput()
  decompressInto(fsys.fileComp.get, inp, dst)
  toInput(dst)

proc statFileFs*(fsys: Fs): FileMeta =
  assert fsys.kind == fkFile
  statPath(fsys.filePath)

# ---------- DirFS ----------

proc dirFullPath*(fsys: Fs; name: string): string =
  assert fsys.kind == fkDir
  checkFsName(name, "open")
  if name == ".":
    return fsys.dirPath
  fsys.dirPath / name.replace('/', DirSep)

proc readDirFs*(fsys: Fs; name: string): seq[DirEntry] =
  case fsys.kind
  of fkDir:
    let full = dirFullPath(fsys, name)
    for kind, path in walkDir(full):
      let m = statPath(path)
      result.add(DirEntry(name: lastPathPart(path), isDir: m.isDir, meta: m))
  of fkFile:
    checkFsName(name, "stat")
    let m = statPath(fsys.filePath)
    result = @[DirEntry(name: lastPathPart(fsys.filePath), isDir: false,
        meta: m)]
  of fkArchive:
    result = readDirArchive(fsys, name)

# ---------- ArchiveFS ----------

proc joinPrefix*(prefix, name: string): string =
  if prefix == "":
    return name
  if name == ".":
    return prefix
  prefix.strip(chars = {'/'}) & "/" & name

proc cleanArchiveName*(n: string): string =
  var parts: seq[string] = @[]
  for p in n.split('/'):
    if p == "" or p == ".":
      continue
    if p == "..":
      if parts.len > 0:
        discard parts.pop()
      continue
    parts.add(p)
  if parts.len == 0: "." else: parts.join("/")

proc indexArchive(fsys: Fs) =
  ## First-ReadDir amortization: walk once, build contents+dirs.
  ## All metadata borrows from archData; no content is copied.
  assert fsys.kind == fkArchive
  fsys.contents = initTable[string, FileMeta]()
  fsys.dirs = initTable[string, seq[DirEntry]]()
  let fmt = fsys.archFormat
  let comp = fsys.archComp
  fsys.archData.seek(0)
  proc handler(ctx: ArchiveContext; info: FileInfo) =
    var nm = cleanArchiveName(info.nameInArchive)
    if nm == ".":
      return
    fsys.contents[nm] = info.meta
    let dir =
      if '/' in nm: nm[0 ..< nm.rfind('/')]
      else: "."
    var entry = DirEntry(name: lastPathPart(nm), isDir: info.isDir,
        meta: info.meta)
    if fsys.dirs.hasKey(dir):
      var found = false
      for i, e in fsys.dirs[dir]:
        if e.name == entry.name:
          fsys.dirs[dir][i] = entry
          found = true
          break
      if not found:
        fsys.dirs[dir].add(entry)
        fsys.dirs[dir].sort(proc(a, b: DirEntry): int = cmp(a.name, b.name))
    else:
      fsys.dirs[dir] = @[entry]
    var cur = dir
    while cur != "." and cur != "":
      let parent =
        if '/' in cur: cur[0 ..< cur.rfind('/')]
        else: "."
      let base = lastPathPart(cur)
      let imp = DirEntry(name: base, isDir: true,
          meta: FileMeta(name: base, isDir: true, isRegular: false))
      if fsys.dirs.hasKey(parent):
        var has = false
        for e in fsys.dirs[parent]:
          if e.name == base:
            has = true
            break
        if not has:
          fsys.dirs[parent].add(imp)
          fsys.dirs[parent].sort(proc(a, b: DirEntry): int = cmp(a.name,
              b.name))
      else:
        fsys.dirs[parent] = @[imp]
      if not fsys.contents.hasKey(cur):
        fsys.contents[cur] = imp.meta
      cur = parent
  if comp.isSome:
    let tmp = newOutput()
    decompressInto(comp.get, fsys.archData, tmp)
    let inner = toInput(tmp)
    extractFormat(fmt, fsys.actx, inner, handler)
  else:
    let saved = inputPos(fsys.archData)
    try:
      extractFormat(fmt, fsys.actx, fsys.archData, handler)
    finally:
      seek(fsys.archData, saved)
  fsys.indexed = true

proc readDirArchive*(fsys: Fs; name: string): seq[DirEntry] =
  checkFsName(name, "readdir")
  let full = joinPrefix(fsys.prefix, name)
  if not fsys.indexed:
    indexArchive(fsys)
  if fsys.dirs.hasKey(full):
    return fsys.dirs[full]
  if fsys.contents.hasKey(full) and not fsys.contents[full].isDir:
    raise newException(ArchiveError, "readdir " & name & ": not a directory")
  return @[]

proc openArchive*(fsys: Fs; name: string): tuple[inp: Input;
    meta: FileMeta; entries: seq[DirEntry]] =
  ## Zero-copy open of a file inside the archive (borrowed span);
  ## directory opens return entries.
  checkFsName(name, "open")
  let full = joinPrefix(fsys.prefix, name)
  if not fsys.indexed:
    indexArchive(fsys)
  if full == "." or (fsys.contents.hasKey(full) and
      fsys.contents[full].isDir) or fsys.dirs.hasKey(full):
    let entries =
      if fsys.dirs.hasKey(full): fsys.dirs[full] else: @[]
    let meta =
      if fsys.contents.hasKey(full): fsys.contents[full]
      else: FileMeta(name: lastPathPart(full), isDir: true)
    return (nil, meta, entries)
  if not fsys.contents.hasKey(full):
    raise newException(ArchiveError, "open " & name & ": not found")
  # Scan again for the content span (tar is sequential; index holds meta).
  let fmt = fsys.archFormat
  let comp = fsys.archComp
  var found: Input = nil
  var foundMeta: FileMeta
  proc handler(ctx: ArchiveContext; info: FileInfo) =
    if cleanArchiveName(info.nameInArchive) == full:
      # gcsafe by confinement: opener runs synchronously in this thread.
      {.gcsafe.}:
        found = info.open()
      foundMeta = info.meta
      raise newException(SkipAll, "found")
  fsys.archData.seek(0)
  try:
    if comp.isSome:
      let tmp = newOutput()
      decompressInto(comp.get, fsys.archData, tmp)
      extractFormat(fmt, fsys.actx, toInput(tmp), handler)
    else:
      extractFormat(fmt, fsys.actx, fsys.archData, handler)
  except SkipAll:
    discard
  if found == nil:
    raise newException(ArchiveError, "open " & name & ": not found")
  (found, foundMeta, @[])

proc walkArchive*(fsys: Fs;
    visit: proc(path: string; e: DirEntry) {.closure.}) =
  ## Walk in sorted order using the index.
  if not fsys.indexed:
    indexArchive(fsys)
  var keys: seq[string] = @[]
  for k in fsys.contents.keys:
    keys.add(k)
  keys.sort()
  for k in keys:
    let m = fsys.contents[k]
    visit(k, DirEntry(name: lastPathPart(k), isDir: m.isDir, meta: m))

# ---------- FileSystem dispatch (port of fs.go FileSystem) ----------

proc fileSystem*(ctx: ArchiveContext; filename: string;
    inp: Input = nil): Fs =
  ## Uniform read access over dirs, archives, files and inputs.
  if filename == "" and inp == nil:
    raise newException(ArchiveError, "no input")
  if filename != "" and inp == nil:
    if dirExists(filename) and not symlinkExists(filename):
      return Fs(kind: fkDir, dirPath: filename)
    if not fileExists(filename):
      raise newException(ArchiveError, "not found: " & filename)
    let probe = openInputFile(filename)
    let res =
      try: identify(ctx, lastPathPart(filename), probe)
      except NoMatchError:
        return Fs(kind: fkFile, filePath: filename)
      except CatchableError as e:
        raise e
    if res.archival.isSome:
      return Fs(kind: fkArchive, archData: openInputFile(filename),
        archFormat: res.archival.get, archComp: res.compression, actx: ctx)
    elif res.compression.isSome:
      return Fs(kind: fkFile, filePath: filename,
        fileComp: res.compression)
    raise newException(ArchiveError,
      "unable to create file system rooted at " & filename)
  else:
    # input-driven; filename is a hint
    let res =
      try: identify(ctx, lastPathPart(filename), inp)
      except NoMatchError:
        raise newException(ArchiveError,
          "input without archive match needs a filename-backed FileFS")
    if res.archival.isSome:
      seek(inp, 0)
      return Fs(kind: fkArchive, archData: inp,
        archFormat: res.archival.get, archComp: res.compression, actx: ctx)
    elif res.compression.isSome:
        raise newException(ArchiveError,
          "compressed input without filename cannot form FileFS in v1")
    raise newException(ArchiveError, "unable to create file system")

# ---------- DeepFS ----------

const archiveExtensions* = [".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2",
  ".tar.zst", ".tar.lz4", ".tar.xz", ".tar.sz", ".tar.s2", ".tar.lz",
  ".tar.br", ".tar.zz"]

proc pathIsArchive*(path: string): bool =
  let lower = path.toLowerAscii()
  for ext in archiveExtensions:
    if lower.endsWith(ext):
      return true
  false

proc pathContainsArchive*(path: string): bool =
  let withSep = path & "/"
  for ext in archiveExtensions:
    if withSep.contains(ext & "/"):
      return true
  false

proc splitArchivePath*(path: string): tuple[realPath, innerPath: string] =
  ## Port of DeepFS.SplitPath. Slash must be the separator.
  if path.len < 2:
    return (path, "")
  var start = 1
  var slash = path.find('/', 1)
  var stop = if slash < 0: path.len else: slash
  while true:
    let part = path[start ..< stop].toLowerAscii().strip()
    if pathIsArchive(part):
      let real = path[0 ..< stop].replace('/', DirSep)
      var inner = ""
      if stop < path.len:
        inner = path[stop + 1 .. ^1]
      else:
        inner = "."
      return (real, inner)
    if stop >= path.len:
      break
    start = stop + 1
    slash = path.find('/', start)
    stop = if slash < 0: path.len else: slash
  (path.replace('/', DirSep), "")

proc getInnerFs*(d: DeepFs; realPath: string): Fs =
  if d.inners.hasKey(realPath):
    return d.inners[realPath]
  var ctx = d.ctx
  let fsys =
    try: fileSystem(ctx, realPath, nil)
    except CatchableError:
      return nil
  d.inners[realPath] = fsys
  fsys

proc deepOpen*(d: DeepFs; name: string): tuple[inp: Input; meta: FileMeta] =
  checkFsName(name, "open")
  let joined = (d.root.replace('\\', '/').strip(chars = {'/'}) & "/" &
      name).replace('\\', '/')
  let (real, inner) = splitArchivePath(joined)
  if inner != "":
    let innerFs = d.getInnerFs(real)
    if innerFs != nil and innerFs.kind == fkArchive:
      if inner == ".":
        raise newException(ArchiveError, "open " & name & ": is a directory")
      let r = openArchive(innerFs, inner)
      if r.inp == nil:
        raise newException(ArchiveError, "open " & name & ": is a directory")
      return (r.inp, r.meta)
  let f = openInputFile(real)
  (f, statPath(real))

# ---------- TopDir helpers (port of TopDirOpen/Stat/ReadDir) ----------

proc pathWithoutTopDir*(p: string): string =
  let idx = p.find('/')
  if idx < 0: p else: p[idx + 1 .. ^1]
