## Zip archival format, ported from zip.go.
##
## Backend is our own zipfile (local headers, central directory, EOCD
## parsed/written directly; store or deflate via our own flate).
## Symlink targets are stored as file content with symlink mode bits,
## like Go. No seekable-stream requirement: entries parse from memory.

import std/[strutils, tables]
from std/os import splitFile, lastPathPart
import ../zipfile
import ../io
import ../types
import ../registry

export zipfile

type Zip* = object
  selectiveCompression*: bool
  compression*: int ## zip method; 8=deflate default, 0=store
  continueOnError*: bool

const zipSigs = ["PK\x03\x04", "PK\x05\x06", "PK\x07\x08"]

proc extension*(z: Zip): string = ".zip"
proc mediaType*(z: Zip): string = "application/zip"

proc matchZip*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == formatExt[fmtZip]:
    result.byName = true
  if inp != nil:
    let s = peek(inp, 4)
    if spanLen(s) == 4:
      let b = cast[ptr UncheckedArray[byte]](s.p)
      for h in zipSigs:
        if b[0].char == h[0] and b[1].char == h[1] and
            b[2].char == h[2] and b[3].char == h[3]:
          result.byStream = true
          break

var compressedExts = @["7z", "avi", "cab", "docx", "gif",
  "jar", "jpeg", "jpg", "lz", "lzma", "m4v", "mov", "mp3", "mp4",
  "mpeg", "mpg", "png", "pptx", "rar", "sz", "tbz2", "tgz", "tsz", "txz",
  "xlsx", "xz", "zipx"]

for f in [fmtZip, fmtGz, fmtBz2, fmtLz4, fmtBrotli]:
  ## Our own formats that zip stores without recompressing. Sourced from
  ## the canonical table (no leading dot), never literals. ".zz" stays
  ## out, preserving historical store/deflate decisions.
  compressedExts.add(formatExt[f].strip(chars = {'.'}))

proc isCompressedExt(name: string): bool =
  splitFile(name.toLowerAscii()).ext.strip(chars = {'.'}) in compressedExts

proc fileIsIncludedLocal(skipDirs: seq[string]; filename: string): bool =
  if skipDirs.len == 0:
    return false
  for d in skipDirs:
    if filename == d:
      return true
    if filename.startsWith(d.strip(chars = {'/'}) & "/"):
      return true
  false

proc skipAddLocal(skipDirs: var seq[string]; dir: string) =
  let trimmed = dir.strip(chars = {'/'})
  var dontAdd = false
  var i = 0
  while i < skipDirs.len:
    let e = skipDirs[i].strip(chars = {'/'})
    if trimmed == e:
      return
    if trimmed.startsWith(e & "/"):
      dontAdd = true
    elif e.startsWith(trimmed & "/"):
      skipDirs.del(i)
      continue
    inc i
  if not dontAdd:
    skipDirs.add(dir)

proc archiveZip*(z: Zip; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  var entries: seq[ZipEntry] = @[]
  var keeps: seq[Input] = @[] # retain borrowed spans through writeZip
  for f in files:
    ctx.checkCancelled()
    var arcName = f.nameInArchive
    if arcName == "":
      arcName = f.name
    if f.meta.isDir:
      if not arcName.endsWith("/"):
        arcName.add('/')
      entries.add(ZipEntry(name: arcName, isDir: true, modTime: f.modTime,
        mode: 0o755))
      continue
    try:
      if f.meta.isSymlink:
        let lt = f.linkTarget
        entries.add(ZipEntry(name: arcName, isSymlink: true,
          linkTarget: lt, data: lt, store: true, modTime: f.modTime,
          mode: 0o120777))
      else:
        let fr = f.open()
        keeps.add(fr)
        var content = peek(fr, remaining(fr))
        if content.len > int(f.size):
          content.len = int(f.size)
        var forceStore = false
        if z.selectiveCompression and isCompressedExt(arcName):
          forceStore = true
        if z.compression == 0:
          forceStore = true
        entries.add(ZipEntry(name: arcName, raw: content, keep: fr,
          store: forceStore, modTime: f.modTime, mode: 0o644))
    except CatchableError as e:
      if z.continueOnError and not ctx.cancelled():
        continue
      raise newException(ArchiveError,
        "file " & f.nameInArchive & ": " & e.msg)
  try:
    writeZip(entries, dst)
  except CatchableError as e:
    raise newException(ArchiveError, "zip create: " & e.msg)

proc extractZip*(z: Zip; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  var reader: ZipReader
  try:
    reader = openZip(inp)
  except CatchableError as e:
    raise newException(ArchiveError, "zip open: " & e.msg)
  var skipDirs: seq[string] = @[]
  for e in reader.files:
    ctx.checkCancelled()
    if fileIsIncludedLocal(skipDirs, e.name):
      continue
    let isLink = e.isSymlink
    var meta = FileMeta(name: lastPathPart(e.name.strip(chars = {'/'})),
        size: entryBytes(e).len.int64, mode: e.mode, modTime: e.modTime,
        isDir: e.isDir, isSymlink: isLink, isRegular: not e.isDir and
        not isLink)
    let eb = entryBytes(e)
    let info = FileInfo(meta: meta, nameInArchive: e.name,
        linkTarget: e.linkTarget,
        open: viewOpener(eb, (if e.keep != nil: e.keep else: inp)))
    try:
      handle(ctx, info)
    except SkipAll:
      break
    except SkipDir:
      if info.isDir():
        skipAddLocal(skipDirs, e.name)
    except CatchableError as e2:
      if z.continueOnError and not ctx.cancelled():
        continue
      raise newException(ArchiveError,
        "handling file: " & e.name & ": " & e2.msg)

proc insertZip*(z: Zip; ctx: ArchiveContext; inp: Input; dst: Output;
    files: seq[FileInfo]) =
  ## Port of Go Zip.Insert: existing entries stream through, replacements
  ## appended. Callers write `dst` back over the original file.
  var reader: ZipReader
  try:
    reader = openZip(inp)
  except CatchableError as e:
    raise newException(ArchiveError, "zip open for insert: " & e.msg)
  var byName = initOrderedTable[string, ZipEntry]()
  for e in reader.files:
    byName[e.name] = e
  for f in files:
    ctx.checkCancelled()
    var arcName = f.nameInArchive
    if arcName == "":
      arcName = f.name
    if f.meta.isDir:
      if not arcName.endsWith("/"):
        arcName.add('/')
      byName[arcName] = ZipEntry(name: arcName, isDir: true,
        modTime: f.modTime, mode: 0o755)
      continue
    try:
      if f.meta.isSymlink:
        let lt = f.linkTarget
        byName[arcName] = ZipEntry(name: arcName, isSymlink: true,
          linkTarget: lt, data: lt, store: true, modTime: f.modTime,
          mode: 0o120777)
      else:
        let fr = f.open()
        var content = peek(fr, remaining(fr))
        if content.len > int(f.size):
          content.len = int(f.size)
        byName[arcName] = ZipEntry(name: arcName, raw: content, keep: fr,
          store: z.compression == 0, modTime: f.modTime, mode: 0o644)
    except CatchableError as e:
      raise newException(ArchiveError,
        "file " & f.nameInArchive & ": open: " & e.msg)
  var entries: seq[ZipEntry] = @[]
  for _, e in byName:
    entries.add(e)
  try:
    writeZip(entries, dst)
  except CatchableError as e:
    raise newException(ArchiveError, "zip rewrite: " & e.msg)

proc registerZip*(z: Zip = Zip()) =
  let h = newHandler(fmtZip)
  let zz = z
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchZip(filename, inp)
  h.archive = proc(ctx: ArchiveContext; dst: Output;
      files: seq[FileInfo]) {.closure.} =
    archiveZip(zz, ctx, dst, files)
  h.extract = proc(ctx: ArchiveContext; inp: Input;
      handle: FileHandler) {.closure.} =
    extractZip(zz, ctx, inp, handle)
  registerFormat(h)
