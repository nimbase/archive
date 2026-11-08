## RAR5/7.0 archival format, clean-room implementation.
##
## Covers the RAR 5.0 container (also used by RAR 7.0): vint codec,
## block walk, header CRC, file/service headers, extra-area skipping,
## symlink redirection records, plus Unpack50/70 LZ+Huffman decoding
## (methods m1..m5) via rarcodec. Header encryption, multivolume and
## recovery records stay refused with clear errors.
##
## Memory: header parsing is bounded (2MB header cap); STORE bodies are
## borrowed spans, never copied. Dict/unpacked caps from ArchiveContext
## are enforced when an entry is opened, so listing stays cheap.
## Compressed entries decode into caller-capped outputs retained for the
## extraction call (solid groups decode forward once, in walk order).
## Thread safety: no globals, all state on the stack or per-call.

import std/[strutils, times, tables]
from std/os import splitFile
import ../io
import ../types
import ../crc32
import ./rarcodec

type Rar* = object
  ## RAR5/7.0 archive. No settings in v1 (STORE-only writer).
  continueOnError*: bool

proc extension*(r: Rar): ArchiveFormat = afRar
proc mediaType*(r: Rar): MediaType = mtRar

const
  rar5Magic* = "\x52\x61\x72\x21\x1A\x07\x01\x00"
  rarMaxHeaderSize* = 2 * 1024 * 1024
  rarMaxHeaderCount* = 1_000_000
  rarMaxNameLen* = 4 * 1024 * 1024
  rarDictGate* = 0x1000000000'u64 ## 64 GiB version gate (§11.10)

type RarError* = object of ArchiveError

# ---------- vint codec ----------

proc putVint*(dst: Output; v: uint64) =
  var x = v
  while true:
    var b = byte(x and 0x7F)
    x = x shr 7
    if x != 0:
      writeByte(dst, b or 0x80)
    else:
      writeByte(dst, b)
      break

proc readVint*(inp: Input): uint64 =
  ## Minimal decoder with overflow guard: stops at shift >= 64.
  var shift = 0
  var count = 0
  while true:
    if remaining(inp) <= 0:
      raise newException(RarError, "rar: truncated vint")
    let b = readByte(inp)
    inc count
    if count > 10:
      raise newException(RarError, "rar: vint too long")
    if shift < 64:
      result += (uint64(b and 0x7F)) shl shift
    shift += 7
    if (b and 0x80) == 0:
      break

proc readU32le*(inp: Input): uint32 =
  if remaining(inp) < 4:
    raise newException(RarError, "rar: truncated u32")
  let s = readSpan(inp, 4)
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint32 or (b[1].uint32 shl 8) or (b[2].uint32 shl 16) or
    (b[3].uint32 shl 24)

proc putU32le*(dst: Output; v: uint32) =
  writeByte(dst, byte(v and 0xFF))
  writeByte(dst, byte((v shr 8) and 0xFF))
  writeByte(dst, byte((v shr 16) and 0xFF))
  writeByte(dst, byte((v shr 24) and 0xFF))

# ---------- matching ----------

proc matchRar*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == $afRar:
    result.byName = true
  if inp != nil:
    let s = peek(inp, 8)
    if s.len == 8 and spanEqual(s, rar5Magic):
      result.byStream = true

# ---------- CompInfo helpers ----------

proc rarDictSize*(compInfo: uint64): uint64 =
  ## Unified formula: (fraction+32) << (power+12). v0 has fraction 0.
  let power = (compInfo shr 10) and 0x1F
  let fraction = (compInfo shr 15) and 0x1F
  (fraction + 32) shl (power + 12)

proc compMethod*(compInfo: uint64): int = int((compInfo shr 7) and 0x7)
proc compVersion*(compInfo: uint64): int = int(compInfo and 0x3F)
proc compSolid*(compInfo: uint64): bool = (compInfo and 0x40) != 0

# ---------- writer ----------

proc emitBlock(dst: Output; htype: uint64; hflags: uint64;
    typeSpecific: string; extra: string; data: openArray[byte];
    dataSizePresent: bool; dataSize: uint64) =
  let hasExtra = extra.len > 0
  let hf = hflags or (if hasExtra: 0x0001 else: 0) or
    (if dataSizePresent: 0x0002 else: 0)
  let body = newOutput()
  putVint(body, htype)
  putVint(body, hf)
  if hasExtra:
    putVint(body, extra.len.uint64)
  if dataSizePresent:
    putVint(body, dataSize)
  if typeSpecific.len > 0:
    writeStr(body, typeSpecific)
  if hasExtra:
    writeStr(body, extra)
  let bodyBytes = take(body)
  let hsEnc = newOutput()
  putVint(hsEnc, bodyBytes.len.uint64)
  let hsBytes = take(hsEnc)
  var crc = crc32Update(0xFFFFFFFF'u32, hsBytes)
  crc = crc32Update(crc, bodyBytes) xor 0xFFFFFFFF'u32
  putU32le(dst, crc)
  writeStr(dst, hsBytes)
  writeStr(dst, bodyBytes)
  if data.len > 0:
    writeBytes(dst, unsafeAddr data[0], data.len)

proc buildRedirExtra(target: string; redirType = 1): string =
  ## File-system redirection record (type 0x05) for symlinks.
  let payload = newOutput()
  putVint(payload, redirType.uint64)
  putVint(payload, 0'u64) # flags
  putVint(payload, target.len.uint64)
  writeStr(payload, target)
  let p = take(payload)
  let rec = newOutput()
  putVint(rec, 0x05'u64) # type
  writeStr(rec, p)
  let r = take(rec)
  let outer = newOutput()
  putVint(outer, r.len.uint64) # Size = from Type onwards
  writeStr(outer, r)
  take(outer)

proc unixTime(m: Time): uint32 =
  uint32(toUnix(m))

proc archiveRar*(r: Rar; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  writeStr(dst, rar5Magic)
  # main header: type 1, flags 0, archive flags 0
  let ts = newOutput()
  putVint(ts, 0'u64)
  emitBlock(dst, 1, 0, take(ts), "", newSeq[byte](0), false, 0)
  var keeps: seq[Input] = @[]
  for i, f in files:
    ctx.checkCancelled()
    ctx.reportProgress(f.nameInArchive, i, files.len, f.size)
    var arcName = f.nameInArchive
    if arcName == "":
      arcName = f.name
    arcName = arcName.replace('\\', '/')
    while arcName.startsWith("/"):
      arcName = arcName[1 .. ^1]
    while arcName.startsWith("./"):
      arcName = arcName[2 .. ^1]
    if arcName == "" or arcName == ".":
      continue
    if f.meta.isDir:
      while arcName.endsWith("/"):
        arcName = arcName[0 ..< ^1]
      let tsd = newOutput()
      putVint(tsd, 0x0001'u64 or 0x0002'u64) # dir + mtime
      putVint(tsd, 0'u64) # unpacked
      let mode = if f.meta.mode != 0: f.meta.mode else: 0x41ED
      putVint(tsd, mode.uint64)
      putU32le(tsd, unixTime(f.meta.modTime))
      # no CRC field
      putVint(tsd, 0'u64) # compInfo STORE
      putVint(tsd, 1'u64) # host OS Unix
      putVint(tsd, arcName.len.uint64)
      writeStr(tsd, arcName)
      emitBlock(dst, 2, 0, take(tsd), "", newSeq[byte](0), false, 0)
    elif f.meta.isSymlink:
      let target = f.linkTarget
      let extra = buildRedirExtra(target)
      let tsf = newOutput()
      putVint(tsf, 0x0002'u64 or 0x0004'u64) # mtime + crc
      putVint(tsf, target.len.uint64) # unpacked = target len
      putVint(tsf, 0x81A4'u64)
      putU32le(tsf, unixTime(f.meta.modTime))
      putU32le(tsf, 0'u32) # zero CRC per spec table
      putVint(tsf, 0'u64)
      putVint(tsf, 1'u64)
      putVint(tsf, arcName.len.uint64)
      writeStr(tsf, arcName)
      emitBlock(dst, 2, 0x0001'u64 or 0x0002'u64, take(tsf), extra,
        newSeq[byte](0), true, 0)
    else:
      var fr: Input
      {.gcsafe.}:
        fr = f.open()
      keeps.add(fr)
      let content = readSpan(fr, remaining(fr))
      let tsf = newOutput()
      putVint(tsf, 0x0002'u64 or 0x0004'u64)
      putVint(tsf, content.len.uint64)
      let mode = if f.meta.mode != 0: f.meta.mode else: 0x81A4
      putVint(tsf, mode.uint64)
      putU32le(tsf, unixTime(f.meta.modTime))
      let crc =
        if content.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, content.p, content.len) xor
          0xFFFFFFFF'u32
      putU32le(tsf, crc)
      putVint(tsf, 0'u64) # STORE
      putVint(tsf, 1'u64)
      putVint(tsf, arcName.len.uint64)
      writeStr(tsf, arcName)
      if content.len == 0:
        emitBlock(dst, 2, 0x0002'u64, take(tsf), "", [], true, 0)
      else:
        var tmp = newString(content.len)
        copyMem(addr tmp[0], content.p, content.len)
        emitBlock(dst, 2, 0x0002'u64, take(tsf), "", tmp.toOpenArrayByte(0,
          tmp.len - 1), true, content.len.uint64)
  # end header: type 5, flags 0, end flags 0
  let te = newOutput()
  putVint(te, 0'u64)
  emitBlock(dst, 5, 0, take(te), "", newSeq[byte](0), false, 0)

# ---------- reader ----------

type RarEntry* = object
  name*: string
  isDir*: bool
  isSymlink*: bool
  linkTarget*: string
  size*: int64
  modTime*: Time
  mode*: int
  compInfo*: uint64
  dataOff*: int
  dataLen*: int
  dataCrc*: uint32
  hasCrc*: bool
  hasBlake*: bool
    ## File Hash extra record (BLAKE2sp) present. v1 decodes without
    ## hash verification for BLAKE2sp-only entries (no BLAKE2sp in the
    ## dependency set); CRC32-carrying entries are always verified.
  encrypted*: bool

# ---------- compressed entries: solid-group decode cache ----------

type RarMember = object
  ## Compressed regular file metadata for forward decode.
  idx*: int
  compInfo*: uint64
  dataOff*: int
  dataLen*: int
  unpacked*: uint64
  unpackedKnown*: bool
  hasCrc*: bool
  dataCrc*: uint32
  hasBlake*: bool
  dictSize*: uint64
  algo70*: bool ## true = Unpack70 distance alphabet
  meth*: int
  grp*: int

type RarGroupCache* = ref object
  ## Per-extraction decode cache. Owns decoded outputs (openers borrow
  ## from it) and one solid-group decoder state. No globals: allocated
  ## per extractRar call, safe to use from any thread.
  state*: UnpackState
  groupId*: int
  hasGroup*: bool
  groupDict*: uint64
  groupAlgo70*: bool
  members*: Table[int, seq[RarMember]] ## groupId -> walk-order members
  upto*: Table[int, int]               ## groupId -> members decoded so far
  decoded*: Table[int, string]         ## entry idx -> decoded bytes

type RarChecked = object
  ## Validated compression parameters (walk-safe to compute, enforced
  ## on open so listing never allocates).
  meth*: int
  dictSize*: uint64
  algo70*: bool

proc checkRarMethod*(compInfo: uint64; unpacked: uint64;
    ctx: ArchiveContext): RarChecked =
  ## Validate version/dictionary fields. Raises RarCodecError on unknown
  ## versions, reserved combinations, the 64 GiB gate, or cap breaches.
  ## Method range itself is checked by the caller.
  let ver = compVersion(compInfo)
  if ver notin [0, 1]:
    raise newException(RarCodecError,
      "rar: unknown compression version " & $ver)
  let compat = (compInfo shr 20) and 1
  if ver == 0 and compat == 1:
    raise newException(RarCodecError, "rar: unknown compression version")
  result.meth = compMethod(compInfo)
  result.algo70 = ver == 1 and compat == 0
  if ver == 0:
    if ((compInfo shr 10) and 0x1F) > 15:
      raise newException(RarCodecError, "rar: unknown compression version")
  result.dictSize = rarDictSize(compInfo)
  if result.dictSize > rarDictGate:
    raise newException(RarCodecError,
      "rar: unknown method (dictionary beyond 64 GiB gate)")
  if ctx.maxRarDictBytes != 0 and result.dictSize > uint64(ctx.maxRarDictBytes):
    raise newException(RarCodecError, "rar: dictionary exceeds cap")
  if ctx.maxRarUnpackedBytes > 0 and
      unpacked > uint64(ctx.maxRarUnpackedBytes):
    raise newException(RarCodecError, "rar: unpacked size exceeds cap")

proc verifyRarDecoded*(dec: string; unpacked: uint64; known, hasCrc: bool;
    dataCrc: uint32; hasBlake: bool) =
  if known and dec.len.uint64 != unpacked:
    raise newException(RarCodecError, "rar: size mismatch")
  if hasCrc and dec.len > 0:
    let got = crc32Update(0xFFFFFFFF'u32, unsafeAddr dec[0], dec.len) xor
      0xFFFFFFFF'u32
    if got != dataCrc:
      raise newException(RarCodecError, "rar: data crc mismatch")

proc decodeRarMember*(cache: RarGroupCache; ctx: ArchiveContext; src: Input;
    idx: int): string =
  ## Decode (or fetch cached) one compressed entry. Solid groups decode
  ## forward from the last decoded member, caching intermediates; a lone
  ## entry is just a group of one. State resets at each group start.
  ## Every decoded member is validated (version/dict/caps/method/CRC);
  ## entries never opened cost nothing beyond walk metadata.
  if cache.decoded.hasKey(idx):
    return cache.decoded[idx]
  var grp = -1
  var pos = -1
  for gid, ms in cache.members:
    for i, mm in ms:
      if mm.idx == idx:
        grp = gid
        pos = i
        break
    if grp >= 0:
      break
  if grp < 0:
    raise newException(RarCodecError, "rar: member not in solid walk")
  let members = cache.members[grp]
  if members[pos].dataLen == 0:
    if members[pos].unpackedKnown and members[pos].unpacked != 0:
      raise newException(RarCodecError, "rar: truncated file data")
    cache.decoded[idx] = ""
    return ""
  if cache.state == nil or cache.groupId != grp:
    cache.state = UnpackState()
    let first = members[0]
    let fm = checkRarMethod(first.compInfo, first.unpacked, ctx)
    if fm.meth notin 1 .. 5:
      raise newException(RarCodecError,
        "rar: unknown compression method " & $fm.meth)
    resetUnpack(cache.state, int(fm.dictSize),
      if fm.algo70: 1 else: 0)
    cache.groupId = grp
    cache.upto[grp] = -1
  let done = cache.upto.getOrDefault(grp, -1)
  for i in done + 1 .. pos:
    let mm = members[i]
    let m = checkRarMethod(mm.compInfo, mm.unpacked, ctx)
    if m.meth notin 1 .. 5:
      raise newException(RarCodecError,
        "rar: unknown compression method " & $m.meth)
    if int(m.dictSize) != cache.state.dictSize or
        m.algo70 != (cache.state.algoVer == 1):
      # Dictionary change forces Solid=false: fresh window.
      resetUnpack(cache.state, int(m.dictSize),
        if m.algo70: 1 else: 0)
    let sp = spanAt(src, mm.dataOff, mm.dataLen)
    let limit =
      if mm.unpackedKnown: mm.unpacked
      elif ctx.maxRarUnpackedBytes > 0: uint64(ctx.maxRarUnpackedBytes)
      else: 1'u64 shl 62
    let dec = decodeMember(cache.state, sp.p, sp.len, limit,
      if m.algo70: 1 else: 0)
    verifyRarDecoded(dec, mm.unpacked, mm.unpackedKnown, mm.hasCrc,
      mm.dataCrc, mm.hasBlake)
    cache.decoded[mm.idx] = dec
    cache.upto[grp] = i
  cache.decoded[idx]

proc parseExtra(inp: Input; extraEnd: int; entry: var RarEntry) =
  ## Scan extra records; tolerant trailing junk ends the walk.
  while inputPos(inp) < extraEnd:
    let recStart = inputPos(inp)
    var size: uint64
    try:
      size = readVint(inp)
    except RarError:
      break
    if size == 0:
      break
    if size > uint64(extraEnd - inputPos(inp)) + 1:
      break # claims beyond extra: stop, don't fail
    let typPos = inputPos(inp)
    var typ: uint64
    try:
      typ = readVint(inp)
    except RarError:
      break
    let payloadStart = inputPos(inp)
    let recEnd = typPos + int(size) # Size counts from Type onwards
    if recEnd > extraEnd or recEnd < payloadStart:
      break
    if typ == 0x01:
      entry.encrypted = true
    elif typ == 0x02:
      entry.hasBlake = true
    elif typ == 0x05:
      # redirection: redirType, flags, nameLen, name
      let save = inputPos(inp)
      try:
        let rt = readVint(inp)
        discard readVint(inp) # flags
        let nl = readVint(inp)
        if nl <= rarMaxNameLen.uint64 and inputPos(inp) + int(nl) <= recEnd:
          var nm = newString(int(nl))
          if nl > 0:
            let s = readSpan(inp, int(nl))
            copyMem(addr nm[0], s.p, int(nl))
          if rt in [1'u64, 2'u64, 3'u64]:
            entry.isSymlink = true
            entry.linkTarget = nm
          else:
            # hardlink/filecopy: mark encrypted=false but unsupported
            entry.linkTarget = nm
            entry.isSymlink = false
        seek(inp, save)
      except RarError:
        discard
    # skip to next record
    seek(inp, recEnd)
    if inputPos(inp) <= recStart:
      break

proc extractRar*(r: Rar; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  if remaining(inp) < 8:
    raise newException(RarError, "rar: truncated signature")
  let sig = readSpan(inp, 8)
  if not spanEqual(sig, rar5Magic):
    raise newException(RarError, "rar: bad signature")
  let groupCache = RarGroupCache()
  var headerCount = 0
  var index = 0
  while true:
    ctx.checkCancelled()
    if remaining(inp) == 0:
      break # tolerant EOF like RAR 2.x; RAR5 normally has ENDARC
    let blockPos = inputPos(inp)
    if remaining(inp) < 4:
      raise newException(RarError, "rar: truncated header crc")
    let storedCrc = readU32le(inp)
    let hsizePos = inputPos(inp)
    let hsize = readVint(inp)
    if hsize > rarMaxHeaderSize.uint64:
      raise newException(RarError, "rar: header too large")
    let bodyStart = inputPos(inp)
    let hsizeBytes = bodyStart - hsizePos
    if uint64(remaining(inp)) < hsize:
      raise newException(RarError, "rar: truncated header")
    let headerEnd = bodyStart + int(hsize)
    # CRC over hsize vint + body
    let crcSpan = spanAt(inp, hsizePos, hsizeBytes + int(hsize))
    let calc =
      if crcSpan.len == 0: 0xFFFFFFFF'u32
      else: crc32Update(0xFFFFFFFF'u32, crcSpan.p, crcSpan.len) xor
        0xFFFFFFFF'u32
    if calc != storedCrc:
      if r.continueOnError:
        seek(inp, headerEnd)
        # skip data if present? need flags; parse minimally: try skip
        continue
      raise newException(RarError, "rar: header crc mismatch")
    let htype = readVint(inp)
    let hflags = readVint(inp)
    var extraSize: uint64 = 0
    var dataSize: uint64 = 0
    if (hflags and 0x0001) != 0:
      extraSize = readVint(inp)
    if (hflags and 0x0002) != 0:
      dataSize = readVint(inp)
    let typeStart = inputPos(inp)
    # safety: extra+type fields must fit in hsize
    if inputPos(inp) > headerEnd:
      raise newException(RarError, "rar: header overrun")
    inc headerCount
    if headerCount > rarMaxHeaderCount:
      raise newException(RarError, "rar: too many headers")
    case htype
    of 1: # main
      let archFlags = readVint(inp)
      if (archFlags and 0x0002) != 0:
        discard readVint(inp) # volume number
      # extra starts at headerEnd - extraSize
      # skip to headerEnd (extra parsed only for locator: skip)
      seek(inp, headerEnd)
      if (hflags and 0x0002) != 0:
        # main never has data, but guard
        if dataSize > uint64(remaining(inp)):
          raise newException(RarError, "rar: truncated main data")
        skip(inp, int(dataSize))
    of 2, 3: # file / service
      let isService = htype == 3
      let fileFlags = readVint(inp)
      let unpacked = readVint(inp)
      let attrs = readVint(inp)
      var mtime = fromUnix(0)
      if (fileFlags and 0x0002) != 0:
        let t = readU32le(inp)
        mtime = fromUnix(t.int64)
      var dcrc: uint32 = 0
      var hasCrc = false
      if (fileFlags and 0x0004) != 0:
        dcrc = readU32le(inp)
        hasCrc = true
      let compInfo = readVint(inp)
      let hostOs = readVint(inp)
      let nameLen = readVint(inp)
      if nameLen > rarMaxNameLen.uint64:
        raise newException(RarError, "rar: name too long")
      var nm = ""
      if nameLen > 0:
        if uint64(remaining(inp)) < nameLen or
            inputPos(inp) + int(nameLen) > headerEnd:
          raise newException(RarError, "rar: truncated name")
        let ns = readSpan(inp, int(nameLen))
        nm = newString(int(nameLen))
        copyMem(addr nm[0], ns.p, int(nameLen))
      var entry = RarEntry(name: nm, size: cast[int64](unpacked),
        modTime: mtime, compInfo: compInfo, dataOff: -1,
        dataLen: 0, dataCrc: dcrc, hasCrc: hasCrc)
      entry.mode =
        if hostOs == 1: int(attrs)
        elif (fileFlags and 0x0001) != 0: 0o40755
        else: 0o100644
      if (fileFlags and 0x0001) != 0:
        entry.isDir = true
      # extra area: last extraSize bytes of header
      let extraStart = headerEnd - int(extraSize)
      if extraSize > 0:
        if extraStart < inputPos(inp) or headerEnd < extraStart:
          raise newException(RarError, "rar: bad extra area")
        seek(inp, extraStart)
        parseExtra(inp, headerEnd, entry)
        seek(inp, headerEnd)
      else:
        seek(inp, headerEnd)
      # split flags: fail fast, can't reassemble multivolume v1
      if (hflags and 0x0008) != 0 or (hflags and 0x0010) != 0:
        raise newException(RarError,
          "rar: multivolume split unsupported in v1")
      if entry.encrypted:
        raise newException(RarError,
          "rar: encrypted entry unsupported in v1")
      if isService:
        # skip data (ACL/STM/CMT/QO/RR): metadata loss documented
        if dataSize > uint64(remaining(inp)):
          raise newException(RarError, "rar: truncated service data")
        skip(inp, int(dataSize))
        continue
      # regular file or dir/symlink
      if entry.isDir:
        if dataSize != 0:
          # dirs carry no data; tolerate by skipping
          if dataSize > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated dir data")
          skip(inp, int(dataSize))
        var meta = FileMeta(name: baseNameV(nm), size: 0,
          mode: entry.mode, modTime: entry.modTime, isDir: true,
          isSymlink: false, isRegular: false)
        let fi = FileInfo(meta: meta, nameInArchive: nm,
          linkTarget: "", open: stringOpener(""))
        ctx.reportProgress(nm, index, -1, 0)
        inc index
        # gcsafe by confinement: handle runs synchronously in this thread.
        {.gcsafe.}:
          handle(ctx, fi)
        continue
      if entry.isSymlink:
        if dataSize != 0:
          if dataSize > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated link data")
          skip(inp, int(dataSize))
        var meta = FileMeta(name: baseNameV(nm), size: entry.size,
          mode: entry.mode, modTime: entry.modTime, isDir: false,
          isSymlink: true, isRegular: false)
        let fi = FileInfo(meta: meta, nameInArchive: nm,
          linkTarget: entry.linkTarget, open: stringOpener(""))
        ctx.reportProgress(nm, index, -1, entry.size)
        inc index
        {.gcsafe.}:
          handle(ctx, fi)
        continue
      # regular file
      if uint64(remaining(inp)) < dataSize:
        raise newException(RarError, "rar: truncated file data")
      let doff = inputPos(inp)
      entry.dataOff = doff
      entry.dataLen = int(dataSize)
      let e = entry # copy for closure
      let src = inp
      let curCtx = ctx
      let curIdx = index
      let cache = groupCache
      var meta = FileMeta(name: baseNameV(nm), size: e.size,
        mode: e.mode, modTime: e.modTime, isDir: false,
        isSymlink: false, isRegular: true)
      # Compressed: decoded lazily on first open into a closure-owned
      # buffer (proven to pin the bytes under ORC + pressure, unlike a
      # bare table fetch whose buffer may be reused by later big
      # allocations). The shared table still dedups repeat opens and
      # solid intermediates; all validation lives in decodeRarMember.
      var owned = ""
      var done = false
      proc opener(): Input =
        if compMethod(e.compInfo) == 0:
          if curCtx.maxRarUnpackedBytes != 0 and
              e.size > curCtx.maxRarUnpackedBytes:
            raise newException(RarError, "rar: unpacked size exceeds cap")
          if e.dataLen != int(e.size):
            raise newException(RarError, "rar: size mismatch")
          let sp = spanAt(src, e.dataOff, e.dataLen)
          if e.hasCrc and e.dataLen > 0:
            let got =
              if sp.len == 0: 0'u32
              else: crc32Update(0xFFFFFFFF'u32, sp.p, sp.len) xor
                0xFFFFFFFF'u32
            if got != e.dataCrc:
              raise newException(RarError, "rar: data crc mismatch")
          return openInputView(sp, src)
        if not done:
          owned = decodeRarMember(cache, curCtx, src, curIdx)
          done = true
        openInputString(owned)
      let fi = FileInfo(meta: meta, nameInArchive: nm, linkTarget: "",
        open: opener)
      # Record solid-group membership for forward decode (metadata only,
      # no version/dict validation: the opener reports the real error).
      # All non-STORE methods record, so unknown methods still list and
      # fail on open with the accurate error instead of "not in walk".
      let meth = compMethod(e.compInfo)
      if meth != 0:
        let ver = compVersion(e.compInfo)
        let compat = (e.compInfo shr 20) and 1
        let algo70 = ver == 1 and compat == 0
        let ds = rarDictSize(e.compInfo)
        var grp = cache.groupId
        if not cache.hasGroup or not compSolid(e.compInfo) or
            ds != cache.groupDict or algo70 != cache.groupAlgo70:
          inc cache.groupId
          grp = cache.groupId
          cache.hasGroup = true
        cache.groupDict = ds
        cache.groupAlgo70 = algo70
        if not cache.members.hasKey(grp):
          cache.members[grp] = @[]
          cache.upto[grp] = -1
        let known = (fileFlags and 0x0008) == 0
        cache.members[grp].add(RarMember(idx: curIdx,
          compInfo: e.compInfo, dataOff: e.dataOff, dataLen: e.dataLen,
          unpacked: cast[uint64](e.size), unpackedKnown: known,
          hasCrc: e.hasCrc, dataCrc: e.dataCrc, hasBlake: e.hasBlake,
          dictSize: ds, algo70: algo70, meth: meth, grp: grp))
      ctx.reportProgress(nm, index, -1, e.size)
      inc index
      {.gcsafe.}:
        handle(ctx, fi)
      skip(inp, int(dataSize))
    of 4:
      raise newException(RarError,
        "rar: header encryption unsupported in v1")
    of 5:
      # endarc: consume optional data, stop
      seek(inp, headerEnd)
      if dataSize > 0:
        if dataSize > uint64(remaining(inp)):
          raise newException(RarError, "rar: truncated endarc data")
        skip(inp, int(dataSize))
      break
    else:
      # unknown: skip via lengths
      seek(inp, headerEnd)
      if (hflags and 0x0002) != 0:
        if dataSize > uint64(remaining(inp)):
          raise newException(RarError, "rar: truncated unknown data")
        skip(inp, int(dataSize))
    let nextPos = inputPos(inp)
    if nextPos <= blockPos:
      raise newException(RarError, "rar: walk did not advance")
    discard typeStart
