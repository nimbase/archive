## ZIP file reader/writer ported from Go archive/zip structure.
##
## Parses from borrowed spans (central directory + stored entries are
## zero-copy views into the caller's mapped memory); deflated entries
## inflate into the caller's reusable Output. Writing streams straight
## into an Output. Zip64, encryption and multi-disk archives are
## rejected with a clear error.
##
## Data-descriptor entries are supported: sizes and CRC always come
## from the central directory (never the zeroed local header), so the
## trailing descriptor is simply never read.

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
  flagEncrypted = 0x01
  versionDeflate = 20
  versionStore = 10

type ZipEntry* = object
  ## One file or directory in an archive. Read entries from `openZip`
  ## are metadata-only: `raw` borrows the entry bytes (stored content,
  ## or the *compressed* bytes for deflated entries — use entryContent,
  ## never raw spans, for plain content), `keep` retains the source
  ## mapping, and `meth`/`expectCrc`/`expectLen` carry the
  ## central-directory values for inflate-on-open verification.
  ## Write entries built by callers use `data` (or a stored `raw`
  ## span) exactly as before.
  name*: string       ## slash-separated; dirs end with '/'
  data*: string       ## owned content (deflated entries, once inflated)
  raw*: Span          ## borrowed content (stored), or compressed bytes
  keep*: RootRef      ## keeps `raw` alive (always the source Input here)
  meth*: int          ## zip method (0 = stored, 8 = deflate)
  expectCrc*: uint32  ## central-directory CRC (verified on inflate/open)
  expectLen*: int     ## central-directory uncompressed size
  isDir*: bool
  isSymlink*: bool
  linkTarget*: string ## valid when isSymlink
  store*: bool        ## force stored (no deflate) even if non-empty
  modTime*: Time
  mode*: int          ## Unix permission bits, default 0o644/0o755

type ZipReader* = object
  files*: seq[ZipEntry]

proc entryContent*(e: ZipEntry): Input =
  ## Materialize a read entry's bytes for `FileInfo.open` and friends.
  ## Stored entries return a borrowed zero-copy view; deflated entries
  ## inflate into a fresh buffer with size/CRC verification against the
  ## central directory. The inflated `Output` itself is returned via
  ## `toInput` (no intermediate copy). Raises ZipError naming the entry.
  ## Only for entries produced by `openZip` (user-built write entries
  ## carry no expectations and never reach here).
  ## NOTE: for large archives prefer the streaming to-dir fast path
  ## (writeEntryToFile) which never materializes the full entry.
  if e.meth == methodDeflate and e.data.len == 0:
    # Cap initial allocation: exact for small entries (no regrowth),
    # bounded 64KB starter for huge ones to avoid pinning a giant
    # buffer on a lying central directory. Growth still reaches the
    # true size for honest archives via the generic path.
    let dst = newOutput(min(e.expectLen, StreamChunkSize))
    let sub = openInputView(e.raw, e.keep)
    try:
      inflateInto(sub, dst)
    except FlateError as err:
      raise newException(ZipError, "zip: deflate error in " & e.name &
        ": " & err.msg)
    let ob = outputBytes(dst)
    if ob.len != e.expectLen:
      raise newException(ZipError, "zip: size mismatch: " & e.name)
    if (crc32Update(0xFFFFFFFF'u32, ob.p, ob.len) xor 0xFFFFFFFF'u32) !=
        e.expectCrc:
      raise newException(ZipError, "zip: checksum mismatch: " & e.name)
    return toInput(dst)
  if e.data.len > 0:
    return openInputString(e.data)
  # stored read entry: borrowed view (keep retains the mapping).
  # Verify size/CRC up front (zero-copy scan, no allocation) so corrupt
  # entries fail here, not silently downstream.
  if e.raw.len != e.expectLen:
    raise newException(ZipError, "zip: size mismatch: " & e.name)
  if e.raw.len > 0:
    let got = crc32Update(0xFFFFFFFF'u32, e.raw.p, e.raw.len) xor
      0xFFFFFFFF'u32
    if got != e.expectCrc:
      raise newException(ZipError, "zip: checksum mismatch: " & e.name)
  return openInputView(e.raw, e.keep)

proc writeEntryToFile*(e: ZipEntry, f: File, scratch: Output) =
  ## Stream a regular read entry directly to an open file with bounded
  ## memory: stored entries go mmap-span -> file (zero-copy, chunked),
  ## deflated entries inflate in ~96KB windows straight to `f`.
  ## Verifies central-directory size/CRC; raises ZipError naming the
  ## entry. `scratch` is reused across entries (capped, never scales
  ## with entry size). Caller opens/closes `f` and handles dirs,
  ## symlinks, zip-slip, and partial-file cleanup on error.
  if e.isDir:
    raise newException(ZipError, "zip: writeEntryToFile on directory: " &
      e.name)
  if e.isSymlink:
    raise newException(ZipError, "zip: writeEntryToFile on symlink: " &
      e.name)
  if e.data.len > 0:
    # Materialized (user-built) entry: chunked write, no extra copy.
    var crc: uint32 = 0xFFFFFFFF'u32
    var total = 0
    if e.data.len != e.expectLen and e.expectLen != 0:
      # Write entries from callers carry no expectations (expectLen 0);
      # read entries materialized via materializeEntry have expectLen set.
      # Only enforce when expectations exist to avoid breaking writer paths.
      raise newException(ZipError, "zip: size mismatch: " & e.name)
    let s = Span(p: unsafeAddr e.data[0], len: e.data.len)
    writeSpanToFile(s, f, crc, total)
    if (crc xor 0xFFFFFFFF'u32) != e.expectCrc and e.expectCrc != 0:
      raise newException(ZipError, "zip: checksum mismatch: " & e.name)
    return
  if e.meth == methodStore:
    if e.raw.len != e.expectLen:
      raise newException(ZipError, "zip: size mismatch: " & e.name)
    var crc: uint32 = 0xFFFFFFFF'u32
    var total = 0
    writeSpanToFile(e.raw, f, crc, total)
    if total != e.expectLen:
      raise newException(ZipError, "zip: size mismatch: " & e.name)
    if (crc xor 0xFFFFFFFF'u32) != e.expectCrc:
      raise newException(ZipError, "zip: checksum mismatch: " & e.name)
    return
  elif e.meth == methodDeflate:
    let sub = openInputView(e.raw, e.keep)
    var res: tuple[bytes: int, crc: uint32]
    try:
      res = inflateIntoFile(sub, f, scratch)
    except FlateError as err:
      raise newException(ZipError, "zip: deflate error in " & e.name &
        ": " & err.msg)
    if res.bytes != e.expectLen:
      raise newException(ZipError, "zip: size mismatch: " & e.name)
    if res.crc != e.expectCrc:
      raise newException(ZipError, "zip: checksum mismatch: " & e.name)
    return
  else:
    raise newException(ZipError, "zip: unsupported method in " & e.name)

proc streamStoredRangeToFile*(rf, wf: File, inBuf: var string, compLen,
    expectLen: int, expectCrc: uint32, entryName: string) =
  ## Copy a stored (uncompressed) file range `rf` -> `wf` with bounded
  ## memory: 64KB reusable `inBuf`, no full-entry buffering. Verifies
  ## size/CRC; raises ZipError naming the entry. `rf` must be positioned
  ## at the range start; exactly `compLen` bytes are consumed.
  if compLen != expectLen:
    raise newException(ZipError, "zip: size mismatch: " & entryName)
  if inBuf.len < StreamChunkSize:
    inBuf = newString(StreamChunkSize)
  var crc: uint32 = 0xFFFFFFFF'u32
  var total = 0
  var remaining = compLen
  while remaining > 0:
    let toRead = min(remaining, inBuf.len)
    let n = readBuffer(rf, addr inBuf[0], toRead)
    if n <= 0:
      raise newException(ZipError, "zip: truncated entry: " & entryName)
    crc = crc32Update(crc, addr inBuf[0], n)
    var woff = 0
    while woff < n:
      let w = writeBuffer(wf, addr inBuf[woff], n - woff)
      if w <= 0:
        raise newException(ZipError, "zip: short write: " & entryName)
      woff += w
    total += n
    remaining -= n
  if total != expectLen:
    raise newException(ZipError, "zip: size mismatch: " & entryName)
  if (crc xor 0xFFFFFFFF'u32) != expectCrc:
    raise newException(ZipError, "zip: checksum mismatch: " & entryName)

proc streamDeflatedRangeToFile*(rf: File, compLen: int, wf: File,
    scratch: Output, inBuf: var string, expectLen: int, expectCrc: uint32,
    entryName: string) =
  ## Inflate a deflated file range `rf` (positioned, `compLen` bytes) to
  ## `wf` with bounded memory (64KB input + ~96KB window, reused).
  ## Verifies size/CRC; raises ZipError naming the entry.
  var res: tuple[bytes: int, crc: uint32]
  try:
    res = inflateFileRange(rf, compLen, wf, scratch, inBuf)
  except FlateError as err:
    raise newException(ZipError, "zip: deflate error in " & entryName &
      ": " & err.msg)
  if res.bytes != expectLen:
    raise newException(ZipError, "zip: size mismatch: " & entryName)
  if res.crc != expectCrc:
    raise newException(ZipError, "zip: checksum mismatch: " & entryName)

proc entryOpener*(e: ZipEntry): proc(): Input {.closure.} =
  ## `FileInfo.open` factory over a per-call copy of the entry (same
  ## reason as stringOpener: loop-shared captures would alias).
  let ee = e
  result = proc(): Input {.closure.} = entryContent(ee)

proc materializeEntry*(e: ZipEntry): ZipEntry =
  ## Inflate a lazy deflated read entry into owned `data` and drop the
  ## borrowed compressed span. Stored entries (and user-built ones)
  ## pass through untouched. Used by the writer, which only accepts
  ## plain content.
  if e.meth == methodDeflate and e.data.len == 0:
    result = e
    result.data = readAll(entryContent(e))
    result.raw = Span()
  else:
    result = e

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
  ## Parse the central directory into metadata-only entries. Nothing is
  ## inflated here: stored entries borrow zero-copy spans into `inp`
  ## (kept alive per entry) and deflated entries inflate lazily on
  ## `open`, with size/CRC verification then. Peak memory is one entry,
  ## not the whole archive.
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
    # NOTE: no data-descriptor rejection. Streaming writers zero the
    # local sizes/CRC and append a descriptor after the data, but the
    # central directory always carries the true values — and those are
    # the only ones used below (dataStart comes from the local header's
    # name/extra lengths alone).
    if meth != methodStore and meth != methodDeflate:
      raise newException(ZipError, "zip: unsupported method")
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
    # Unix mode in high 16 bits of external attributes.
    let modeAttr = (rd32at(inp, recBase + 38).int shr 16)
    let isLink = (modeAttr and 0o170000) == 0o120000
    result.files.add(ZipEntry(name: name, raw: raw, keep: inp,
      meth: meth, expectCrc: crc, expectLen: uncompSize, isDir: isDir,
      isSymlink: isLink and not isDir,
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
    # Writer contract is plain content: materialize lazy deflated
    # read entries (no-op for stored/user entries) so `src` below is
    # always uncompressed bytes, borrowed when possible.
    var ee = materializeEntry(e)
    let src: Span =
      if ee.data.len > 0:
        Span(p: unsafeAddr ee.data[0], len: ee.data.len)
      else:
        ee.raw
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
