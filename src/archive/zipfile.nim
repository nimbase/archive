## ZIP file reader/writer ported from Go archive/zip structure.
##
## Parses from borrowed spans (central directory + stored entries are
## zero-copy views into the caller's mapped memory); deflated entries
## inflate into the caller's reusable Output. Writing streams straight
## into an Output. Zip64, encryption, data descriptors and multi-disk
## archives are rejected with a clear error.

import std/[times, strutils]
import ./io
import ./flate
import ./crc32

type ZipError* = object of CatchableError

const
  fileHeaderSig = 0x04034B50'u32
  centralDirSig = 0x02014B50'u32
  eocdSig = 0x06054B50'u32
  methodStore = 0
  methodDeflate = 8
  flagUtf8 = 0x800
  flagDataDescriptor = 0x08
  flagEncrypted = 0x01
  versionDeflate = 20
  versionStore = 10

type ZipEntry* = object
  ## One file or directory in an archive.
  name*: string       ## slash-separated; dirs end with '/'
  data*: string       ## owned content (deflated entries; "" when span-backed)
  raw*: Span          ## borrowed content (stored entries, dirs have len 0)
  keep*: RootRef      ## keeps `raw` alive (usually the source Input)
  isDir*: bool
  isSymlink*: bool
  linkTarget*: string ## valid when isSymlink
  store*: bool        ## force stored (no deflate) even if non-empty
  modTime*: Time
  mode*: int          ## Unix permission bits, default 0o644/0o755

type ZipReader* = object
  files*: seq[ZipEntry]

proc entryBytes*(e: ZipEntry): Span =
  ## Borrowed view of the entry's content (zero-copy either way).
  if e.raw.len > 0 or e.data.len == 0:
    e.raw
  else:
    Span(p: unsafeAddr e.data[0], len: e.data.len)

proc put16(dst: Output; v: int) {.inline.} =
  dst.writeByte(char(v and 0xFF))
  dst.writeByte(char((v shr 8) and 0xFF))

proc put32(dst: Output; v: uint32) {.inline.} =
  for i in 0 ..< 4:
    dst.writeByte(char((v shr (8 * i)) and 0xFF))

proc dosTimeToTime(dosDate, dosTime: int): Time =
  let sec = (dosTime and 0x1F) * 2
  let mins = (dosTime shr 5) and 0x3F
  let hrs = (dosTime shr 11) and 0x1F
  let day = dosDate and 0x1F
  let mon = (dosDate shr 5) and 0x0F
  let yr = ((dosDate shr 9) and 0x7F) + 1980
  try:
    dateTime(yr, mon.Month, day.MonthdayRange, hrs.HourRange,
      mins.MinuteRange, sec.SecondRange, 0, local()).toTime()
  except CatchableError:
    dateTime(1980, mJan, 1.MonthdayRange, 0.HourRange, 0.MinuteRange,
      0.SecondRange, 0, local()).toTime()

proc timeToDos(t: Time): tuple[date, time: int] =
  let dt = t.local()
  var yr = dt.year - 1980
  if yr < 0:
    return (0x21, 0) # 1980-01-01
  if yr > 127:
    yr = 127
  let date = (yr shl 9) or (dt.month.ord shl 5) or dt.monthday
  let time = (dt.hour shl 11) or (dt.minute shl 5) or (dt.second div 2)
  (date, time)

proc findEocd(inp: Input): int =
  ## Locate EOCD by scanning backwards (comment up to 64KB).
  let total = inputLen(inp)
  var i = total - 22
  let lo = max(0, total - 22 - 65535)
  while i >= lo:
    let s = spanAt(inp, i, 4)
    if s.u32le(0) == eocdSig:
      return i
    dec i
  raise newException(ZipError, "zip: end of central directory not found")

proc rd16at(inp: Input; pos: int): int =
  spanAt(inp, pos, 2).u16le(0)

proc rd32at(inp: Input; pos: int): uint32 =
  spanAt(inp, pos, 4).u32le(0)

proc openZip*(inp: Input): ZipReader =
  ## Parse central directory; inflate + verify each entry. Stored
  ## entries stay zero-copy views into `inp` (kept alive per entry).
  let eocd = findEocd(inp)
  let total = inputLen(inp)
  if eocd + 22 > total:
    raise newException(ZipError, "zip: truncated EOCD")
  let diskNum = rd16at(inp, eocd + 4)
  let cdDisk = rd16at(inp, eocd + 6)
  let entriesThisDisk = rd16at(inp, eocd + 8)
  let totalEntries = rd16at(inp, eocd + 10)
  let cdSize = rd32at(inp, eocd + 12).int
  let cdOff = rd32at(inp, eocd + 16).int
  if diskNum != 0 or cdDisk != 0 or entriesThisDisk != totalEntries:
    raise newException(ZipError, "zip: multi-disk archives not supported")
  if cdOff + cdSize > total:
    raise newException(ZipError, "zip: central directory out of range")
  var pos = cdOff
  let scratch = newOutput(65536) # reused inflate buffer
  for _ in 0 ..< totalEntries:
    if rd32at(inp, pos) != centralDirSig:
      raise newException(ZipError, "zip: bad central directory signature")
    let flags = rd16at(inp, pos + 8)
    let meth = rd16at(inp, pos + 10)
    let mtime = rd16at(inp, pos + 12)
    let mdate = rd16at(inp, pos + 14)
    let crc = rd32at(inp, pos + 16)
    let compSize = rd32at(inp, pos + 20).int
    let uncompSize = rd32at(inp, pos + 24).int
    let nameLen = rd16at(inp, pos + 28)
    let extraLen = rd16at(inp, pos + 30)
    let commentLen = rd16at(inp, pos + 32)
    let localOff = rd32at(inp, pos + 42).int
    if (flags and flagEncrypted) != 0:
      raise newException(ZipError, "zip: encrypted entries not supported")
    if (flags and flagDataDescriptor) != 0:
      raise newException(ZipError,
        "zip: data-descriptor entries not supported")
    let nameSpan = spanAt(inp, pos + 46, nameLen)
    let name = spanToString(nameSpan)
    let recBase = pos
    pos += 46 + nameLen + extraLen + commentLen
    # Local header.
    if localOff + 30 > total or rd32at(inp, localOff) != fileHeaderSig:
      raise newException(ZipError, "zip: bad local header at offset " &
        $localOff)
    let lmeth = rd16at(inp, localOff + 8)
    let lNameLen = rd16at(inp, localOff + 26)
    let lExtraLen = rd16at(inp, localOff + 28)
    let dataStart = localOff + 30 + lNameLen + lExtraLen
    if dataStart + compSize > total:
      raise newException(ZipError, "zip: entry data out of range: " & name)
    if lmeth != meth:
      raise newException(ZipError, "zip: method mismatch: " & name)
    let raw = spanAt(inp, dataStart, compSize)
    let isDir = name.endsWith("/")
    var content = ""
    var borrowed = Span(p: nil, len: 0)
    case meth
    of methodStore:
      borrowed = raw # zero-copy
    of methodDeflate:
      reset(scratch)
      let sub = openInputView(raw, inp)
      try:
        inflateInto(sub, scratch)
      except FlateError as e:
        raise newException(ZipError, "zip: deflate error in " & name &
          ": " & e.msg)
      let ob = outputBytes(scratch)
      content = newString(ob.len)
      if ob.len > 0:
        copyMem(addr content[0], ob.p, ob.len)
    else:
      raise newException(ZipError, "zip: unsupported method in " & name)
    let gotLen =
      if meth == methodStore: raw.len
      else: content.len
    if gotLen != uncompSize:
      raise newException(ZipError, "zip: size mismatch: " & name)
    let checkCrc =
      if meth == methodStore:
        (if raw.len == 0: 0'u32
         else: crc32Update(0xFFFFFFFF'u32, raw.p, raw.len) xor 0xFFFFFFFF'u32)
      else:
        crc32Checksum(content)
    if checkCrc != crc:
      raise newException(ZipError, "zip: checksum mismatch: " & name)
    # Unix mode in high 16 bits of external attributes.
    let modeAttr = (rd32at(inp, recBase + 38).int shr 16)
    let isLink = (modeAttr and 0o170000) == 0o120000
    result.files.add(ZipEntry(name: name, data: content, raw: borrowed,
      keep: inp, isDir: isDir, isSymlink: isLink and not isDir,
      linkTarget: (if isLink and not isDir: content else: ""),
      modTime: dosTimeToTime(mdate, mtime),
      mode: (if modeAttr != 0: modeAttr and 0o777777 else: 0o644)))

type ZipCentral = object
  name: string
  meth: int
  crc: uint32
  compLen, uncompLen: int
  dosDate, dosTime: int
  mode: int
  isDir: bool
  localOff: int

proc writeZip*(entries: openArray[ZipEntry]; dst: Output) =
  ## Build a zip archive straight into `dst` (reusable buffer).
  var centrals: seq[ZipCentral] = @[]
  let scratch = newOutput(65536) # reused deflate buffer
  for e in entries:
    let isDir = e.isDir or e.name.endsWith("/")
    var name = e.name
    if isDir and not name.endsWith("/"):
      name.add('/')
    let src = entryBytes(e)
    let useStore = e.store or isDir or src.len == 0 or e.isSymlink
    var bodyLen = 0
    var crc: uint32 = 0
    if not useStore:
      reset(scratch)
      # deflate from the borrowed span without copying it first
      let sub = openInputView(src, e.keep)
      deflateInto(sub, scratch)
      let ob = outputBytes(scratch)
      bodyLen = ob.len
      crc = (if src.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, src.p, src.len) xor 0xFFFFFFFF'u32)
    else:
      if src.len > 0:
        crc = crc32Update(0xFFFFFFFF'u32, src.p, src.len) xor 0xFFFFFFFF'u32
    let meth =
      if useStore: methodStore
      else: methodDeflate
    let (dd, dt) = timeToDos(e.modTime)
    let mode =
      if e.mode != 0: e.mode
      elif isDir: 0o755
      else: 0o644
    centrals.add(ZipCentral(name: name, meth: meth, crc: crc,
      compLen: (if useStore: src.len else: bodyLen),
      uncompLen: (if isDir: 0 else: src.len),
      dosDate: dd, dosTime: dt, mode: mode, isDir: isDir,
      localOff: dst.len))
    put32(dst, fileHeaderSig)
    put16(dst, if meth == methodDeflate: versionDeflate else: versionStore)
    put16(dst, flagUtf8)
    put16(dst, meth)
    put16(dst, dt)
    put16(dst, dd)
    put32(dst, crc)
    put32(dst, (if useStore: src.len else: bodyLen).uint32)
    put32(dst, (if isDir: 0 else: src.len).uint32)
    put16(dst, name.len)
    put16(dst, 0) # extra
    dst.writeStr(name)
    if useStore:
      if src.len > 0:
        dst.writeBytes(src.p, src.len)
    else:
      let ob = outputBytes(scratch)
      if ob.len > 0:
        dst.writeBytes(ob.p, ob.len)
  let cdStart = dst.len
  for c in centrals:
    put32(dst, centralDirSig)
    put16(dst, (3 shl 8) or 20) # made by Unix, v2.0
    put16(dst, if c.meth == methodDeflate: versionDeflate else: versionStore)
    put16(dst, flagUtf8)
    put16(dst, c.meth)
    put16(dst, c.dosTime)
    put16(dst, c.dosDate)
    put32(dst, c.crc)
    put32(dst, c.compLen.uint32)
    put32(dst, c.uncompLen.uint32)
    put16(dst, c.name.len)
    put16(dst, 0) # extra
    put16(dst, 0) # comment
    put16(dst, 0) # disk
    put16(dst, 0) # int attr
    let extAttr = ((c.mode and 0o777777) shl 16) or (if c.isDir: 0x10 else: 0)
    put32(dst, extAttr.uint32)
    put32(dst, c.localOff.uint32)
    dst.writeStr(c.name)
  let cdSize = dst.len - cdStart
  put32(dst, eocdSig)
  put16(dst, 0)
  put16(dst, 0)
  put16(dst, entries.len)
  put16(dst, entries.len)
  put32(dst, cdSize.uint32)
  put32(dst, cdStart.uint32)
  put16(dst, 0)
