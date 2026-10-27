## Tar archival format, ported from tar.go.
##
## Pure Nim ustar/pax reader+writer. Headers parse from borrowed spans
## (zero-copy); entry bodies are spans into the mapped archive.
## Writing streams into the caller's reusable Output.

import std/[strutils, times]
from std/os import lastPathPart
import ../io
import ../types
import ../registry

const tarBlockSize* = 512

type TarFormat* = enum
  tfAuto, tfUstar, tfPax, tfGnu

type Tar* = object
  format*: TarFormat
  numericUidGid*: bool
  continueOnError*: bool
  uid*: int
  gid*: int
  uname*: string
  gname*: string
  hasUid*: bool
  hasGid*: bool

proc extension*(t: Tar): string = ".tar"
proc mediaType*(t: Tar): string = "application/x-tar"

# ---------- low-level header codec (span based, zero-copy) ----------

proc spanStr(s: Span; off, n: int): string =
  ## NUL-terminated string field.
  let b = cast[ptr UncheckedArray[byte]](s.p)
  var ln = 0
  while ln < n and b[off + ln] != 0:
    inc ln
  result = newString(ln)
  for i in 0 ..< ln:
    result[i] = char(b[off + i])

proc parseOctalSpan(s: Span; off, n: int): int64 =
  var i = off
  let stop = off + n
  let b = cast[ptr UncheckedArray[byte]](s.p)
  # skip leading NUL/space
  while i < stop and (b[i] == 0 or b[i] == byte(' ')):
    inc i
  if i < stop and (b[i] and 0x80'u8) != 0:
    # base-256 binary form
    var v: int64 = 0
    for j in off ..< stop:
      v = v * 256 + b[j].int64
    return v - (int64(128) shl (8 * (n - 1)))
  var v: int64 = 0
  while i < stop and b[i] >= byte('0') and b[i] <= byte('7'):
    v = v * 8 + (b[i].int - ord('0'))
    inc i
  v

proc formatOctal(v: int64; width: int): string =
  result = newString(width)
  for i in 0 ..< width:
    result[i] = '\0'
  var s = ""
  var x = v
  if x == 0:
    s = "0"
  else:
    while x > 0:
      s = chr(ord('0') + int(x mod 8)) & s
      x = x div 8
  let start = width - s.len - 1
  if start < 0:
    for i in 0 ..< width:
      result[i] = '\0'
    var y = v
    for i in countdown(width - 1, 0):
      result[i] = chr(int(y and 0xff))
      y = y shr 8
    result[0] = chr(ord(result[0]) or 128)
    return result
  for i, c in s:
    result[start + i] = c

proc checksumSpan(blk: Span): int =
  let b = cast[ptr UncheckedArray[byte]](blk.p)
  for i in 0 ..< tarBlockSize:
    if i >= 148 and i < 156:
      result += ord(' ')
    else:
      result += b[i].int

proc splitName(name: string): tuple[name, prefix: string] =
  if name.len <= 100:
    return (name, "")
  var best = -1
  for i in 0 ..< name.len:
    if name[i] == '/' and i <= 155 and name.len - i - 1 <= 100:
      best = i
  if best >= 0:
    return (name[best + 1 .. ^1], name[0 ..< best])
  ("", "")

type TarHeader* = object
  name*: string
  size*: int64
  mode*: int
  uid*, gid*: int
  uname*, gname*: string
  modTime*: Time
  typeflag*: char
  linkname*: string

proc writeHeader(dst: Output; h: TarHeader) =
  let startLen = dst.len
  # reserve full block then fill in place (stable pointer during fill)
  let w = reserve(dst, tarBlockSize)
  let blk = cast[ptr UncheckedArray[byte]](w)
  for i in 0 ..< tarBlockSize:
    blk[i] = 0
  proc put(off: int; s: string; maxLen: int) =
    let n = min(s.len, maxLen)
    for i in 0 ..< n:
      blk[off + i] = byte(s[i])
  let (nm, prefix) = splitName(h.name)
  if nm != "" or h.name.len == 0:
    put(0, nm, 100)
    put(345, prefix, 155)
  else:
    put(0, h.name[0 ..< min(100, h.name.len)], 100)
  put(100, formatOctal(h.mode.int64, 8), 8)
  put(108, formatOctal(h.uid.int64, 8), 8)
  put(116, formatOctal(h.gid.int64, 8), 8)
  put(124, formatOctal(h.size, 12), 12)
  put(136, formatOctal(h.modTime.toUnix(), 12), 12)
  blk[156] = byte(h.typeflag)
  put(157, h.linkname, 100)
  put(257, "ustar", 5)
  blk[262] = 0
  blk[263] = byte('0')
  put(265, h.uname, 32)
  put(297, h.gname, 32)
  var cs = 0
  for i in 0 ..< tarBlockSize:
    if i >= 148 and i < 156:
      cs += ord(' ')
    else:
      cs += blk[i].int
  var css = cs.toOct(6)
  while css.len < 6:
    css = "0" & css
  put(148, css, 6)
  blk[154] = 0
  blk[155] = byte(' ')
  advance(dst, tarBlockSize)
  assert dst.len == startLen + tarBlockSize

proc writePaxHeader(dst: Output; name: string;
    attrs: openArray[(string, string)]) =
  var body = ""
  for (k, v) in attrs:
    let rec = " " & k & "=" & v & "\n"
    var ln = rec.len + ($rec.len).len
    while true:
      let cand = $ln & rec
      if cand.len == ln:
        body.add(cand)
        break
      ln = cand.len
  var h = TarHeader(name: "pax_extended_header", size: body.len.int64,
      mode: 0o644, typeflag: 'x', modTime: getTime())
  writeHeader(dst, h)
  if body.len > 0:
    dst.writeStr(body)
    let pad = (tarBlockSize - body.len mod tarBlockSize) mod tarBlockSize
    for _ in 0 ..< pad:
      dst.writeByte('\0')

proc isZeroBlock(s: Span): bool =
  let b = cast[ptr UncheckedArray[byte]](s.p)
  for i in 0 ..< tarBlockSize:
    if b[i] != 0:
      return false
  true

proc parseHeader(blk: Span): TarHeader =
  let cs = parseOctalSpan(blk, 148, 8)
  if checksumSpan(blk) != int(cs):
    raise newException(ArchiveError, "bad tar checksum")
  var name = spanStr(blk, 0, 100)
  let prefix = spanStr(blk, 345, 155)
  if prefix.len > 0:
    name = prefix & "/" & name
  result.name = name
  result.mode = int(parseOctalSpan(blk, 100, 8))
  result.uid = int(parseOctalSpan(blk, 108, 8))
  result.gid = int(parseOctalSpan(blk, 116, 8))
  result.size = parseOctalSpan(blk, 124, 12)
  result.modTime = fromUnix(parseOctalSpan(blk, 136, 12))
  result.typeflag = char(cast[ptr UncheckedArray[byte]](blk.p)[156])
  if result.typeflag == '\0':
    result.typeflag = '0'
  result.linkname = spanStr(blk, 157, 100)
  result.uname = spanStr(blk, 265, 32)
  result.gname = spanStr(blk, 297, 32)

proc parsePax(body: string): seq[(string, string)] =
  var i = 0
  while i < body.len:
    var j = i
    while j < body.len and body[j] != '\n':
      inc j
    let line = body[i ..< j]
    let sp = line.find(' ')
    let eq = line.find('=')
    if sp > 0 and eq > sp:
      result.add((line[sp + 1 ..< eq], line[eq + 1 .. ^1]))
    i = j + 1

# ---------- FileInfo mapping ----------

proc headerForFile(t: Tar; f: FileInfo): TarHeader =
  result.name = f.nameInArchive
  if result.name == "":
    result.name = f.name
  result.size =
    if f.meta.isDir or f.meta.isSymlink: 0
    elif f.linkTarget != "" and f.meta.isRegular: 0
    else: f.size
  result.mode = f.mode
  if result.mode == 0:
    result.mode = if f.meta.isDir: 0o755 else: 0o644
  result.modTime = f.modTime
  if t.numericUidGid:
    result.uname = ""
    result.gname = ""
  if t.hasUid: result.uid = t.uid
  if t.hasGid: result.gid = t.gid
  if t.uname != "": result.uname = t.uname
  if t.gname != "": result.gname = t.gname
  if f.meta.isDir:
    result.typeflag = '5'
  elif f.meta.isSymlink:
    result.typeflag = '2'
    result.linkname = f.linkTarget
  elif f.linkTarget != "" and f.meta.isRegular:
    result.typeflag = '1'
    result.linkname = f.linkTarget
  else:
    result.typeflag = '0'

proc writeFileToArchive*(t: Tar; dst: Output; f: FileInfo) =
  ## Port of Go writeFileToArchive.
  var hdr = headerForFile(t, f)
  if hdr.name.len > 100:
    let (nm, _) = splitName(hdr.name)
    if nm == "" and t.format != tfGnu:
      writePaxHeader(dst, hdr.name, [("path", hdr.name)])
  writeHeader(dst, hdr)
  if hdr.typeflag != '0':
    return
  if hdr.size == 0:
    return
  let fr = try: f.open()
    except CatchableError as e:
      raise newException(ArchiveError,
        "file " & f.nameInArchive & ": open: " & e.msg)
  var remaining = hdr.size
  while remaining > 0:
    let chunk = readSpan(fr, int(min(remaining, 1 shl 20)))
    if chunk.len == 0:
      raise newException(ArchiveError,
        "file " & f.nameInArchive & ": short read")
    dst.writeBytes(chunk.p, chunk.len)
    remaining -= chunk.len
  let pad = (tarBlockSize - int(hdr.size mod tarBlockSize)) mod tarBlockSize
  for _ in 0 ..< pad:
    dst.writeByte('\0')

proc archiveTar*(t: Tar; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  for f in files:
    ctx.checkCancelled()
    try:
      writeFileToArchive(t, dst, f)
    except CatchableError as e:
      if t.continueOnError and not ctx.cancelled():
        continue
      raise newException(ArchiveError, "file " & f.nameInArchive & ": " & e.msg)
  for _ in 0 ..< tarBlockSize * 2:
    dst.writeByte('\0')

proc fileIsIncluded*(skipDirs: seq[string]; filename: string): bool =
  if skipDirs.len == 0:
    return false
  for d in skipDirs:
    if filename == d:
      return true
    if filename.startsWith(d.strip(chars = {'/'}) & "/"):
      return true
  false

proc skipAdd(skipDirs: var seq[string]; dir: string) =
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

proc extractTar*(t: Tar; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  ## Port of Go Tar.Extract with skipDirs + SkipDir/SkipAll.
  ## Bodies stay borrowed spans into `inp` (zero-copy); entries keep
  ## `inp` alive via viewOpener.
  var skipDirs: seq[string] = @[]
  var paxPath = ""
  var paxLinkpath = ""
  while remaining(inp) >= tarBlockSize:
    ctx.checkCancelled()
    let blk = readSpan(inp, tarBlockSize)
    if isZeroBlock(blk):
      # Two zero blocks end the archive; trailing padding tolerated.
      continue
    var hdr: TarHeader
    try:
      hdr = parseHeader(blk)
    except CatchableError:
      if t.continueOnError and not ctx.cancelled():
        continue
      raise
    if hdr.typeflag == 'g':
      let n = int(hdr.size)
      discard readSpan(inp, n)
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      if pad > 0:
        skip(inp, pad)
      continue
    if hdr.typeflag == 'x':
      let n = int(hdr.size)
      let paxSpan = readSpan(inp, n)
      let body = spanToString(paxSpan)
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      if pad > 0:
        skip(inp, pad)
      for (k, v) in parsePax(body):
        if k == "path": paxPath = v
        elif k == "linkpath": paxLinkpath = v
      continue
    var effName = hdr.name
    var effLink = hdr.linkname
    if paxPath != "":
      effName = paxPath
      paxPath = ""
    if paxLinkpath != "":
      effLink = paxLinkpath
      paxLinkpath = ""
    if hdr.typeflag == 'L' or hdr.typeflag == 'K':
      let n = int(hdr.size)
      let body = spanToString(readSpan(inp, n))
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      if pad > 0:
        skip(inp, pad)
      if hdr.typeflag == 'L':
        paxPath = body.split('\0')[0]
      else:
        paxLinkpath = body.split('\0')[0]
      continue
    let n = int(hdr.size)
    var data = Span(p: nil, len: 0)
    if hdr.typeflag == '0' and n > 0:
      if remaining(inp) < n:
        raise newException(ArchiveError, "truncated tar entry: " & effName)
      data = readSpan(inp, n)
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      if pad > 0:
        skip(inp, pad)
    if fileIsIncluded(skipDirs, effName):
      continue
    var meta = FileMeta(name: lastPathPart(effName.strip(chars = {'/'})),
        size: n.int64, mode: hdr.mode, modTime: hdr.modTime,
        isDir: hdr.typeflag == '5',
        isSymlink: hdr.typeflag == '2', isRegular: hdr.typeflag == '0')
    let info = FileInfo(meta: meta, nameInArchive: effName,
        linkTarget: effLink, open: viewOpener(data, inp))
    try:
      handle(ctx, info)
    except SkipAll:
      break
    except SkipDir:
      if info.isDir():
        skipAdd(skipDirs, effName)
    except CatchableError as e:
      raise newException(ArchiveError,
        "handling file: " & effName & ": " & e.msg)

proc matchTar*(filename: string; inp: Input): MatchResult =
  let lower = filename.toLowerAscii()
  let parts = lower.split('.')
  if "tar" in parts:
    result.byName = true
  if inp != nil and remaining(inp) >= tarBlockSize:
    let blk = peek(inp, tarBlockSize)
    try:
      discard parseHeader(blk)
      result.byStream = true
    except CatchableError:
      discard

proc insertTar*(t: Tar; ctx: ArchiveContext; inp: Input; dst: Output;
    files: seq[FileInfo]) =
  ## Copy-through insert: existing entries stream from `inp` to `dst`,
  ## then new files append. Replaces Go's in-place rewrite with an
  ## allocation-free (spans) pass; callers write `dst` back to disk.
  while remaining(inp) >= tarBlockSize:
    ctx.checkCancelled()
    let startPos = inputPos(inp)
    let blk = readSpan(inp, tarBlockSize)
    if isZeroBlock(blk):
      continue
    let hdr = parseHeader(blk) # corrupt input fails fast here
    if hdr.typeflag == 'g' or hdr.typeflag == 'x' or
        hdr.typeflag == 'L' or hdr.typeflag == 'K':
      # copy the raw record (header + body + pad) verbatim
      let n = int(hdr.size)
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      let raw = spanAt(inp, startPos, tarBlockSize + n + pad)
      dst.writeBytes(raw.p, raw.len)
      skip(inp, n + pad)
      continue
    let n = int(hdr.size)
    var data = Span(p: nil, len: 0)
    if hdr.typeflag == '0' and n > 0:
      data = readSpan(inp, n)
      let pad = (tarBlockSize - n mod tarBlockSize) mod tarBlockSize
      if pad > 0:
        skip(inp, pad)
    # re-emit via normal writer path (normalizes framing)
    var meta = FileMeta(name: lastPathPart(hdr.name.strip(chars = {'/'})),
        size: n.int64, mode: hdr.mode, modTime: hdr.modTime,
        isDir: hdr.typeflag == '5',
        isSymlink: hdr.typeflag == '2', isRegular: hdr.typeflag == '0')
    let info = FileInfo(meta: meta, nameInArchive: hdr.name,
        linkTarget: hdr.linkname, open: viewOpener(data, inp))
    writeFileToArchive(t, dst, info)
  for f in files:
    ctx.checkCancelled()
    writeFileToArchive(t, dst, f)

proc registerTar*(t: Tar = Tar()) =
  let h = newHandler(fmtTar)
  let tt = t
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchTar(filename, inp)
  h.archive = proc(ctx: ArchiveContext; dst: Output;
      files: seq[FileInfo]) {.closure.} =
    archiveTar(tt, ctx, dst, files)
  h.extract = proc(ctx: ArchiveContext; inp: Input;
      handle: FileHandler) {.closure.} =
    extractTar(tt, ctx, inp, handle)
  registerFormat(h)
