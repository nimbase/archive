## RAR5/7.0 archival format, clean-room implementation (STORE-only v1).
##
## Covers the RAR 5.0 container (also used by RAR 7.0) with stored
## (method 0) entries: vint codec, block walk, header CRC, file/service
## headers, extra-area skipping, symlink redirection records. Compressed
## methods (m1..m5, Unpack50/70) list correctly but fail on content with
## a clear error — decoding them is the next phase.
##
## Memory: header parsing is bounded (2MB header cap); entry bodies are
## borrowed spans, never copied. Dict/unpacked caps from ArchiveContext
## are enforced when an entry is opened, so listing stays cheap.
## Thread safety: no globals, all state on the stack or per-call.

import std/[strutils, times]
from std/os import splitFile
import ../io
import ../types
import ../crc32

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
  encrypted*: bool

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
      var meta = FileMeta(name: baseNameV(nm), size: e.size,
        mode: e.mode, modTime: e.modTime, isDir: false,
        isSymlink: false, isRegular: true)
      proc opener(): Input =
        let meth = compMethod(e.compInfo)
        let ver = compVersion(e.compInfo)
        if ver notin [0, 1]:
          raise newException(RarError,
            "rar: unknown compression version " & $ver)
        if meth != 0:
          # dict gate + cap before any allocation
          let ds = rarDictSize(e.compInfo)
          if ds > rarDictGate:
            raise newException(RarError,
              "rar: unknown method (dictionary beyond 64 GiB gate)")
          if curCtx.maxRarDictBytes != 0 and
              ds > uint64(curCtx.maxRarDictBytes):
            raise newException(RarError,
              "rar: dictionary exceeds cap")
          if curCtx.maxRarUnpackedBytes != 0 and
              e.size > curCtx.maxRarUnpackedBytes:
            raise newException(RarError,
              "rar: unpacked size exceeds cap")
          raise newException(RarError,
            "rar: unsupported compression method " & $meth &
            " (STORE-only v1)")
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
        openInputView(sp, src)
      let fi = FileInfo(meta: meta, nameInArchive: nm, linkTarget: "",
        open: opener)
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
