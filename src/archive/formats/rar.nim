## RAR5/7.0 archival format, clean-room implementation.
##
## Covers the RAR 5.0 container (also used by RAR 7.0): vint codec,
## block walk, header CRC, file/service headers, extra-area skipping,
## symlink redirection records, Unpack50/70 LZ+Huffman codec (methods
## m1..m5, solid groups, DELTA/E8/E8E9/ARM filters), AES-256-CBC per-file
## and header encryption via PBKDF2-HMAC-SHA256, and multivolume sets
## (split-file reassembly; solid multivolume and header-encrypted
## multivolume stay refused). Recovery records are skipped (service
## headers); `.rev` volumes are not archives.
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
import ./rarenc
import ./rarcrypt

type Rar* = object
  ## RAR5/7.0 archive. `method` selects the file codec: 0 = STORE
  ## (default, also used for empty files), 1..5 = Unpack50 LZ with
  ## increasing match-finder effort. Writer always emits non-solid
  ## archives with a 1 MiB dictionary.
  ##
  ## `password` enables AES-256-CBC per-file encryption on write and
  ## decryption on read; it flows per call (the `Rar` value itself is
  ## per-call, never global). Empty means no encryption. `kdfLg2`
  ## selects the PBKDF2 iteration log2 on write (0 = default 15);
  ## readers take the count from each header and ignore this field.
  ## `encHeaders` requests archive-wide header encryption (`-hp`
  ## equivalent): the writer emits HEAD_CRYPT and encrypts every
  ## subsequent header with the archive key (file data still gets
  ## per-file keys); the reader decrypts headers automatically when
  ## it sees HEAD_CRYPT. Requires `password`.
  continueOnError*: bool
  meth*: int
  password*: string
  kdfLg2*: int
  encHeaders*: bool
  useFilters*: bool
    ## Auto filters on write (ratio only): when true, the writer tries
    ## E8E9/DELTA/ARM forward transforms per file and keeps the smallest
    ## packing (fallback to filter-free when nothing wins). Default false
    ## preserves existing behavior and speed.
  dictSize*: int
    ## Explicit dictionary bytes (0 = default 1 MiB). Must be >=128KB when
    ## set; v0 requires a power of two ≤4GiB, v1 allows fractions and up
    ## to 1TiB (capped at 64GiB, which no reader unpacks). The reader's
    ## `maxRarDictBytes` cap still applies on open.
  algoVer*: int
    ## 0 = Unpack50 default (or auto v1 when `dictSize` needs it),
    ## 1 = force Unpack70 (80-symbol distance table, version bit 1).
    ## Forcing v1 with a small dictionary exercises the 80-symbol path
    ## without a >4GiB input.

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

proc isPow2(x: int): bool =
  x > 0 and (x and (x - 1)) == 0

proc resolveWriterDict*(r: Rar): tuple[dictSize: int; algoVer: int] =
  ## Resolve writer dictionary + algorithm version. Default 1MiB v0.
  ## Explicit `dictSize` must be >=128KB; v0 requires power-of-two ≤4GiB,
  ## otherwise v1 is selected automatically (or must be forced). Never
  ## emits above the 64GiB version gate.
  const defDict = 1 shl 20
  const minDict = 128 * 1024
  const gate = 0x1000000000 # 64GiB, same as rarDictGate
  var ds = if r.dictSize == 0: defDict else: r.dictSize
  if ds < minDict:
    raise newException(RarError, "rar: dictionary too small")
  if ds > gate:
    raise newException(RarError,
      "rar: dictionary beyond 64 GiB gate")
  var av = r.algoVer
  if av notin [0, 1]:
    raise newException(RarError, "rar: unknown algorithm version")
  let needsV1 = ds > (1 shl 32) or not isPow2(ds)
  if needsV1:
    av = 1
  # v0 power check (≤15, i.e. ≤4GiB) is enforced by rarCompInfo truncation;
  # explicit power>15 with algoVer 0 would silently clamp, so refuse.
  if av == 0:
    var p = 0
    var b = minDict
    while b < ds:
      b = b shl 1
      inc p
    # b == ds here since pow2 (checked above); p is power index where
    # 128KB<<p == ds. v0 allows p ≤ 15 (4GiB).
    if p > 15:
      raise newException(RarError,
        "rar: dictionary needs Unpack70 (set algoVer 1)")
  result = (ds, av)

proc writerCompInfo*(meth, dictSize, algoVer: int): uint64 =
  if algoVer == 1:
    rarCompInfo70(meth, dictSize)
  else:
    rarCompInfo(meth, dictSize)

# ---------- encryption helpers (CRYPT_RAR50) ----------

proc rarWriterLg2*(r: Rar): int =
  ## KDF log2 for writes: explicit field or default 15. Tests use small
  ## values for speed; production should stay >= 15.
  if r.kdfLg2 == 0: rarKdfDefaultLg2 else: r.kdfLg2

proc checkWriterLg2*(lg2: int) =
  if lg2 < 1 or lg2 > rarKdfMaxLg2:
    raise newException(RarError,
      "rar: KDF count out of range (1..24)")

proc deriveRarKeys*(password: string; salt: array[16, byte]; lg2: int):
    tuple[key, hashKey, checkRaw: array[32, byte]] =
  if password == "":
    raise newException(RarError, "rar: password required")
  if lg2 < 0 or lg2 > rarKdfMaxLg2:
    raise newException(RarError,
      "rar: KDF count exceeds decoder maximum")
  let pb = pwdBytes(password)
  let count = 1 shl lg2
  result = rarPbkdf2Chain(pb, salt, count)

# ---------- filter auto-selection (ratio only) ----------

proc countE8E9Bytes(data: string): int =
  for i in 0 ..< data.len:
    let b = ord(data[i])
    if b == 0xE8 or b == 0xE9:
      inc result

proc countArmAligned(data: string): int =
  var i = 3
  while i < data.len:
    if ord(data[i]) == 0xEB:
      inc result
    i += 4

proc chunkFilters(totalLen, kind, channels: int): seq[RarFilterSpec] =
  ## Split a whole-file filter into ≤4MB chunks (max filter length).
  const maxF = 1 shl 22
  var off = 0
  while off < totalLen:
    let ln = min(maxF, totalLen - off)
    result.add(RarFilterSpec(start: off, len: ln, kind: kind,
      channels: channels))
    off += ln

proc transformWithFilters(data: string;
    specs: openArray[RarFilterSpec]): string =
  ## Apply forward transforms per filter region (each region independent,
  ## with its own fileOff = region start). Regions must be non-overlapping
  ## and within bounds (validated by the encoder).
  result = data
  for f in specs:
    let sub = result[f.start ..< f.start + f.len]
    let t =
      case f.kind
      of 0: fwdDelta(sub, f.channels)
      of 1: fwdE8(sub, f.start.uint64)
      of 2: fwdE8E9(sub, f.start.uint64)
      else: fwdArm(sub, f.start.uint64)
    for i in 0 ..< f.len:
      result[f.start + i] = t[i]

proc encodeWithFiltersAuto*(data: string; meth, dictSize, algoVer: int):
    tuple[packed: string; filters: seq[RarFilterSpec]; compInfo: uint64] =
  ## Try filter-free + E8E9/ARM/DELTA candidates, keep smallest packing.
  ## `data` is raw unpacked bytes. Returns packed stream + filter specs
  ## (empty = filter-free) + CompInfo for the chosen algoVer.
  let ci =
    if algoVer == 1: rarCompInfo70(meth, dictSize)
    else: rarCompInfo(meth, dictSize)
  # Baseline: filter-free.
  var bestPacked = encodeRarMemberFiltered(
    data.toOpenArrayByte(0, data.len - 1), meth, dictSize, [], algoVer)
  var bestFilters: seq[RarFilterSpec] = @[]
  if data.len < 4096:
    return (bestPacked, bestFilters, ci)
  # E8E9 candidate (x86 binaries).
  if countE8E9Bytes(data) * 200 >= data.len: # >=0.5%
    let specs = chunkFilters(data.len, 2, 1)
    let t = transformWithFilters(data, specs)
    let p = try:
      encodeRarMemberFiltered(t.toOpenArrayByte(0, t.len - 1), meth,
        dictSize, specs, algoVer)
    except CatchableError: ""
    if p.len > 0 and p.len < bestPacked.len:
      bestPacked = p
      bestFilters = specs
      # E8E9 and ARM are mutually exclusive (both target executables);
      # skip ARM when E8E9 already wins to save an encode.
      return (bestPacked, bestFilters, ci)
  # ARM candidate (32-bit ARM binaries, 4-byte aligned EB).
  if data.len >= 16 and countArmAligned(data) * 400 >= data.len div 4:
    let specs = chunkFilters(data.len, 3, 1)
    let t = transformWithFilters(data, specs)
    let p = try:
      encodeRarMemberFiltered(t.toOpenArrayByte(0, t.len - 1), meth,
        dictSize, specs, algoVer)
    except CatchableError: ""
    if p.len > 0 and p.len < bestPacked.len:
      bestPacked = p
      bestFilters = specs
      return (bestPacked, bestFilters, ci)
  # DELTA candidates (PCM-like, channels 2 and 4 cover mono/stereo).
  for ch in [2, 4]:
    let specs = chunkFilters(data.len, 0, ch)
    let t = transformWithFilters(data, specs)
    let p = try:
      encodeRarMemberFiltered(t.toOpenArrayByte(0, t.len - 1), meth,
        dictSize, specs, algoVer)
    except CatchableError: ""
    if p.len > 0 and p.len < bestPacked.len:
      bestPacked = p
      bestFilters = specs
  (bestPacked, bestFilters, ci)

proc buildCryptExtra*(salt, iv: array[16, byte]; lg2: int;
    check12: openArray[byte]; useHashMac = true): string =
  ## Full extra-area record (Size + Type 0x01 + payload) for per-file
  ## encryption. Always carries a check value (flag 0x0001); HashMAC
  ## (flag 0x0002) defaults on for fresh archives.
  let flags: uint64 = 0x0001 or (if useHashMac: 0x0002'u64 else: 0)
  let payload = newOutput()
  putVint(payload, 0'u64) # version AES-256
  putVint(payload, flags)
  writeByte(payload, byte(lg2))
  writeBytes(payload, unsafeAddr salt[0], 16)
  writeBytes(payload, unsafeAddr iv[0], 16)
  if check12.len != 12:
    raise newException(RarError, "rar: bad check value length")
  writeBytes(payload, unsafeAddr check12[0], 12)
  let p = take(payload)
  let rec = newOutput()
  putVint(rec, 0x01'u64)
  writeStr(rec, p)
  let r = take(rec)
  let outer = newOutput()
  putVint(outer, r.len.uint64)
  writeStr(outer, r)
  take(outer)

proc decryptRarBytes*(ciphertext: openArray[byte];
    key: array[32, byte]; iv: array[16, byte]): string =
  if ciphertext.len == 0:
    return ""
  let plain = rarAesDecrypt(key, iv, ciphertext)
  result = newString(plain.len)
  if plain.len > 0:
    copyMem(addr result[0], unsafeAddr plain[0], plain.len)

# ---------- writer ----------

proc buildHeaderBytes(htype: uint64; hflags: uint64;
    typeSpecific: string; extra: string; dataSizePresent: bool;
    dataSize: uint64): string =
  ## Complete plaintext header block bytes (CRC + hsize vint + body),
  ## without the data area. Shared by clear and header-encrypted paths.
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
  let outp = newOutput()
  putU32le(outp, crc)
  writeStr(outp, hsBytes)
  writeStr(outp, bodyBytes)
  take(outp)

proc emitBlock(dst: Output; htype: uint64; hflags: uint64;
    typeSpecific: string; extra: string; data: openArray[byte];
    dataSizePresent: bool; dataSize: uint64) =
  writeStr(dst, buildHeaderBytes(htype, hflags, typeSpecific, extra,
    dataSizePresent, dataSize))
  if data.len > 0:
    writeBytes(dst, unsafeAddr data[0], data.len)

proc emitBlockEncrypted(dst: Output; archiveKey: array[32, byte];
    htype: uint64; hflags: uint64; typeSpecific: string; extra: string;
    data: openArray[byte]; dataSizePresent: bool; dataSize: uint64) =
  ## Header-encrypted variant: plaintext header (CRC included) is padded
  ## to 16 bytes, encrypted with a fresh IV, stored as IV + ciphertext.
  ## The data area follows in the clear (per-file ciphertext when the
  ## file itself is encrypted, else raw packed bytes).
  let plainHdr = buildHeaderBytes(htype, hflags, typeSpecific, extra,
    dataSizePresent, dataSize)
  var pt = newSeq[byte](plainHdr.len)
  if plainHdr.len > 0:
    copyMem(addr pt[0], unsafeAddr plainHdr[0], plainHdr.len)
  let iv = rarRandomIv()
  let ct = rarAesEncrypt(archiveKey, iv, pt)
  writeBytes(dst, unsafeAddr iv[0], 16)
  if ct.len > 0:
    writeBytes(dst, unsafeAddr ct[0], ct.len)
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
  let useHdrEnc = r.encHeaders
  var archKey: array[32, byte]
  if useHdrEnc:
    if r.password == "":
      raise newException(RarError, "rar: password required")
    let lg2 = rarWriterLg2(r)
    checkWriterLg2(lg2)
    let archSalt = rarRandomSalt()
    let archKeys = deriveRarKeys(r.password, archSalt, lg2)
    archKey = archKeys.key
    let archCheck = rarCheckStored(archKeys.checkRaw)
    writeStr(dst, rar5Magic)
    # HEAD_CRYPT in the clear (type 4): version + flags + lg2 + salt + check
    let tc = newOutput()
    putVint(tc, 0'u64) # version AES-256
    putVint(tc, 0x0001'u64) # password check present
    writeByte(tc, byte(lg2))
    writeBytes(tc, unsafeAddr archSalt[0], 16)
    writeBytes(tc, unsafeAddr archCheck[0], 12)
    emitBlock(dst, 4, 0, take(tc), "", newSeq[byte](0), false, 0)
  else:
    writeStr(dst, rar5Magic)
  proc emitHdr(htype: uint64; hflags: uint64; typeSpecific: string;
      extra: string; data: openArray[byte]; dsp: bool; dsz: uint64) =
    if useHdrEnc:
      emitBlockEncrypted(dst, archKey, htype, hflags, typeSpecific, extra,
        data, dsp, dsz)
    else:
      emitBlock(dst, htype, hflags, typeSpecific, extra, data, dsp, dsz)
  # main header: type 1, flags 0, archive flags 0
  let ts = newOutput()
  putVint(ts, 0'u64)
  emitHdr(1, 0, take(ts), "", newSeq[byte](0), false, 0)
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
      emitHdr(2, 0, take(tsd), "", newSeq[byte](0), false, 0)
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
      emitHdr(2, 0x0001'u64 or 0x0002'u64, take(tsf), extra,
        newSeq[byte](0), true, 0)
    else:
      if r.meth notin 0 .. 5:
        raise newException(RarError,
          "rar: unknown compression method " & $r.meth)
      var fr: Input
      {.gcsafe.}:
        fr = f.open()
      keeps.add(fr)
      let content = readSpan(fr, remaining(fr))
      let rawCrc =
        if content.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, content.p, content.len) xor
          0xFFFFFFFF'u32
      # Decide packed plaintext and CompInfo first (encryption wraps it).
      # Dictionary/algorithm from writer settings; filters when opted in.
      let (wDict, wAlgo) = resolveWriterDict(r)
      var plainPacked = newString(0)
      var compInfoVal: uint64 = 0
      var useStore = true
      if r.meth != 0 and content.len > 0:
        var raw = newString(content.len)
        copyMem(addr raw[0], content.p, content.len)
        if r.useFilters and content.len >= 4096:
          let best = encodeWithFiltersAuto(raw, r.meth, wDict, wAlgo)
          if best.packed.len < raw.len:
            plainPacked = best.packed
            compInfoVal = best.compInfo
            useStore = false
          else:
            plainPacked = raw
            compInfoVal = 0
            useStore = true
        else:
          let packed = encodeRarMemberFiltered(
            raw.toOpenArrayByte(0, raw.len - 1), r.meth, wDict, [], wAlgo)
          if packed.len < raw.len:
            plainPacked = packed
            compInfoVal = writerCompInfo(r.meth, wDict, wAlgo)
            useStore = false
          else:
            plainPacked = raw
            compInfoVal = 0
            useStore = true
      else:
        if content.len > 0:
          var tmp = newString(content.len)
          copyMem(addr tmp[0], content.p, content.len)
          plainPacked = tmp
        compInfoVal = 0
        useStore = true
      let encrypting = r.password != "" and content.len > 0
      var cryptExtra = ""
      var storedCrc = rawCrc
      var cryptSalt: array[16, byte]
      var cryptIv: array[16, byte]
      var cryptKey: array[32, byte]
      var cryptHashKey: array[32, byte]
      if encrypting:
        let lg2 = rarWriterLg2(r)
        checkWriterLg2(lg2)
        cryptSalt = rarRandomSalt()
        cryptIv = rarRandomIv()
        let keys = deriveRarKeys(r.password, cryptSalt, lg2)
        cryptKey = keys.key
        cryptHashKey = keys.hashKey
        let check12 = rarCheckStored(keys.checkRaw)
        cryptExtra = buildCryptExtra(cryptSalt, cryptIv, lg2, check12, true)
        storedCrc = rarHashMacCrc(cryptHashKey, rawCrc)
      let tsf = newOutput()
      putVint(tsf, 0x0002'u64 or 0x0004'u64)
      putVint(tsf, content.len.uint64)
      let mode = if f.meta.mode != 0: f.meta.mode else: 0x81A4
      putVint(tsf, mode.uint64)
      putU32le(tsf, unixTime(f.meta.modTime))
      putU32le(tsf, storedCrc)
      putVint(tsf, compInfoVal)
      putVint(tsf, 1'u64)
      putVint(tsf, arcName.len.uint64)
      writeStr(tsf, arcName)
      if content.len == 0:
        emitHdr(2, 0x0002'u64, take(tsf), "", [], true, 0)
      elif not encrypting:
        if useStore:
          emitHdr(2, 0x0002'u64, take(tsf), "", plainPacked.toOpenArrayByte(0,
            plainPacked.len - 1), true, plainPacked.len.uint64)
        else:
          emitHdr(2, 0x0002'u64, take(tsf), "", plainPacked.toOpenArrayByte(0,
            plainPacked.len - 1), true, plainPacked.len.uint64)
      else:
        var ptBytes = newSeq[byte](plainPacked.len)
        if plainPacked.len > 0:
          copyMem(addr ptBytes[0], unsafeAddr plainPacked[0], plainPacked.len)
        let ct = rarAesEncrypt(cryptKey, cryptIv, ptBytes)
        emitHdr(2, 0x0002'u64, take(tsf), cryptExtra,
          ct, true, ct.len.uint64)
  # end header: type 5, flags 0, end flags 0
  let te = newOutput()
  putVint(te, 0'u64)
  emitHdr(5, 0, take(te), "", newSeq[byte](0), false, 0)

# ---------- multivolume writer ----------

type RarVolFile = object
  ## Prepared logical file for multivolume packing.
  arcName: string
  isDir, isSymlink: bool
  linkTarget: string
  mode: int
  modTime: Time
  compInfo: uint64
  unpacked: int
  rawCrc: uint32
  fullData: string ## packed plaintext or ciphertext (full, before split)
  isEncrypted: bool
  cryptSalt, cryptIv: array[16, byte]
  cryptKey, cryptHashKey: array[32, byte]
  cryptLg2: int
  cryptCheck12: array[12, byte]

proc archiveRarVolumes*(r: Rar; ctx: ArchiveContext; files: seq[FileInfo];
    volumeSize: int64): seq[string] =
  ## Split archive into volumes of `volumeSize` bytes (each volume is a
  ## complete RAR5 archive with its own MARK/MAIN/ENDARC). Non-solid,
  ## clear headers only in v1 (header-encrypted multivolume refused).
  ## Per-file AES is supported (salt/iv shared across a file's parts,
  ## HashMAC only on the last part). Headers never cross a boundary;
  ## file data splits at byte granularity.
  if volumeSize < 1024:
    raise newException(RarError, "rar: volume size too small")
  if r.encHeaders:
    raise newException(RarError,
      "rar: header-encrypted multivolume unsupported in v1")
  if r.meth notin 0 .. 5:
    raise newException(RarError,
      "rar: unknown compression method " & $r.meth)
  # Prepare logical files (same naming/sanitization as single-volume).
  var vols: seq[RarVolFile] = @[]
  var keeps: seq[Input] = @[]
  for f in files:
    ctx.checkCancelled()
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
      var an = arcName
      while an.endsWith("/"):
        an = an[0 ..< ^1]
      vols.add(RarVolFile(arcName: an, isDir: true,
        mode: if f.meta.mode != 0: f.meta.mode else: 0x41ED,
        modTime: f.meta.modTime))
    elif f.meta.isSymlink:
      vols.add(RarVolFile(arcName: arcName, isSymlink: true,
        linkTarget: f.linkTarget,
        mode: 0x81A4, modTime: f.meta.modTime,
        unpacked: f.linkTarget.len))
    else:
      var fr: Input
      {.gcsafe.}:
        fr = f.open()
      keeps.add(fr)
      let content = readSpan(fr, remaining(fr))
      var raw = newString(content.len)
      if content.len > 0:
        copyMem(addr raw[0], content.p, content.len)
      let rawCrc =
        if content.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, content.p, content.len) xor
          0xFFFFFFFF'u32
      let (wDictV, wAlgoV) = resolveWriterDict(r)
      var plainPacked = raw
      var compInfoVal: uint64 = 0
      if r.meth != 0 and content.len > 0:
        if r.useFilters and content.len >= 4096:
          let best = encodeWithFiltersAuto(raw, r.meth, wDictV, wAlgoV)
          if best.packed.len < raw.len:
            plainPacked = best.packed
            compInfoVal = best.compInfo
        else:
          let packed = encodeRarMemberFiltered(
            raw.toOpenArrayByte(0, raw.len - 1), r.meth, wDictV, [], wAlgoV)
          if packed.len < raw.len:
            plainPacked = packed
            compInfoVal = writerCompInfo(r.meth, wDictV, wAlgoV)
      let encrypting = r.password != "" and content.len > 0
      var vf = RarVolFile(arcName: arcName,
        mode: if f.meta.mode != 0: f.meta.mode else: 0x81A4,
        modTime: f.meta.modTime, compInfo: compInfoVal,
        unpacked: content.len, rawCrc: rawCrc)
      if encrypting:
        let lg2 = rarWriterLg2(r)
        checkWriterLg2(lg2)
        vf.isEncrypted = true
        vf.cryptSalt = rarRandomSalt()
        vf.cryptIv = rarRandomIv()
        vf.cryptLg2 = lg2
        let keys = deriveRarKeys(r.password, vf.cryptSalt, lg2)
        vf.cryptKey = keys.key
        vf.cryptHashKey = keys.hashKey
        let chk = rarCheckStored(keys.checkRaw)
        for i in 0 ..< 12:
          vf.cryptCheck12[i] = chk[i]
        var ptb = newSeq[byte](plainPacked.len)
        if plainPacked.len > 0:
          copyMem(addr ptb[0], unsafeAddr plainPacked[0], plainPacked.len)
        let ct = rarAesEncrypt(vf.cryptKey, vf.cryptIv, ptb)
        vf.fullData = newString(ct.len)
        if ct.len > 0:
          copyMem(addr vf.fullData[0], unsafeAddr ct[0], ct.len)
      else:
        vf.fullData = plainPacked
      vols.add(vf)
  # Volume packing.
  var outVols: seq[string] = @[]
  var cur = newOutput()
  var volIdx = 0 # 0-based; volume number field is volIdx for volIdx>=1
  proc startVolume() =
    cur = newOutput()
    writeStr(cur, rar5Magic)
    let ts = newOutput()
    if volIdx == 0:
      putVint(ts, 0x0001'u64) # volume
      emitBlock(cur, 1, 0, take(ts), "", newSeq[byte](0), false, 0)
    else:
      putVint(ts, 0x0003'u64) # volume + volume number present
      putVint(ts, volIdx.uint64) # 1 for second volume, etc.
      emitBlock(cur, 1, 0, take(ts), "", newSeq[byte](0), false, 0)
  proc endVolume(notLast: bool) =
    let te = newOutput()
    putVint(te, if notLast: 1'u64 else: 0'u64)
    emitBlock(cur, 5, 0x0004, take(te), "", newSeq[byte](0), false, 0)
    outVols.add(take(cur))
    inc volIdx
  const endarcSize = 8 # CRC4 + hsize1 + type1 + hflags1 + endflags1
  startVolume()
  for vfi in 0 ..< vols.len:
    let vf = vols[vfi]
    ctx.checkCancelled()
    if vf.isDir:
      let tsd = newOutput()
      putVint(tsd, 0x0001'u64 or 0x0002'u64)
      putVint(tsd, 0'u64)
      putVint(tsd, vf.mode.uint64)
      putU32le(tsd, unixTime(vf.modTime))
      putVint(tsd, 0'u64)
      putVint(tsd, 1'u64)
      putVint(tsd, vf.arcName.len.uint64)
      writeStr(tsd, vf.arcName)
      let hdr = buildHeaderBytes(2, 0, take(tsd), "", false, 0)
      if int64(outputBytes(cur).len + hdr.len + endarcSize) > volumeSize:
        endVolume(true)
        startVolume()
      writeStr(cur, hdr)
    elif vf.isSymlink:
      let extra = buildRedirExtra(vf.linkTarget)
      let tsf = newOutput()
      putVint(tsf, 0x0002'u64 or 0x0004'u64)
      putVint(tsf, vf.unpacked.uint64)
      putVint(tsf, 0x81A4'u64)
      putU32le(tsf, unixTime(vf.modTime))
      putU32le(tsf, 0'u32)
      putVint(tsf, 0'u64)
      putVint(tsf, 1'u64)
      putVint(tsf, vf.arcName.len.uint64)
      writeStr(tsf, vf.arcName)
      let hdr = buildHeaderBytes(2, 0x0001'u64 or 0x0002'u64, take(tsf),
        extra, true, 0)
      if int64(outputBytes(cur).len + hdr.len + endarcSize) > volumeSize:
        endVolume(true)
        startVolume()
      writeStr(cur, hdr)
    else:
      # Regular file, possibly split.
      if vf.fullData.len == 0 and vf.unpacked == 0:
        # Empty file: single header, no data.
        let tsf = newOutput()
        putVint(tsf, 0x0002'u64 or 0x0004'u64)
        putVint(tsf, 0'u64)
        putVint(tsf, vf.mode.uint64)
        putU32le(tsf, unixTime(vf.modTime))
        var stored: uint32 = 0
        var extra = ""
        if vf.isEncrypted:
          # Empty files never encrypt (no data area).
          discard
        putU32le(tsf, stored)
        putVint(tsf, vf.compInfo)
        putVint(tsf, 1'u64)
        putVint(tsf, vf.arcName.len.uint64)
        writeStr(tsf, vf.arcName)
        let hdr = buildHeaderBytes(2, 0x0002'u64, take(tsf), extra,
          true, 0)
        if int64(outputBytes(cur).len + hdr.len + endarcSize) > volumeSize:
          endVolume(true)
          startVolume()
        writeStr(cur, hdr)
      else:
        var off = 0
        var firstFrag = true
        let total = vf.fullData.len
        while off < total:
          # Header for this fragment (metadata identical, DataSize varies).
          let isFirst = firstFrag
          let remainingTotal = total - off
          # Build header with placeholder DataSize to measure header len?
          # Header len depends on DataSize vint length (1-3 bytes) and
          # stored CRC (4 bytes fixed) + crypt extra (fixed 49/50? Actually
          # crypt extra len fixed: Size1 + Type1 + payload47 = 49 bytes on
          # disk? Wait extra string len = 49? Size vint 1 + Type 1 + payload
          # 47 = 49. Good fixed. So header len varies only by DataSize vint
          # len (1-3 bytes). To avoid circular sizing, try DataSize vint
          # len 1 first, then adjust if fragment len needs more bytes.
          # Simpler: compute available for data, then clamp fragment len to
          # fit vint len.
          var fragLen = 0
          var fragHdr = ""
          var fragStored: uint32 = 0
          var fragExtra = ""
          var splitFlags: uint64 = 0
          # Determine if this is the last fragment (tentative).
          # We need to know remaining space to decide split.
          let curLen = outputBytes(cur).len
          let avail = int(volumeSize) - curLen - endarcSize
          # Build candidate header pieces without DataSize to measure base.
          # Instead, iterate: try fragLen = min(remainingTotal, avail - hdrBase)
          # where hdrBase estimated. Do two passes.
          # First, build header with DataSize = remainingTotal (max) to get
          # max header len, then compute actual fragLen.
          # Simpler loop: compute hdr len for fragLen = min(remaining, avail-100)
          # (conservative), then adjust.
          # For clarity, implement helper inline:
          proc buildFragHdr(dataLen: int; isFirstF, isLastF: bool;
              storedCrc: uint32; extraStr: string): string =
            let ts = newOutput()
            putVint(ts, 0x0002'u64 or 0x0004'u64)
            putVint(ts, vf.unpacked.uint64)
            putVint(ts, vf.mode.uint64)
            putU32le(ts, unixTime(vf.modTime))
            putU32le(ts, storedCrc)
            putVint(ts, vf.compInfo)
            putVint(ts, 1'u64)
            putVint(ts, vf.arcName.len.uint64)
            writeStr(ts, vf.arcName)
            var sf: uint64 = 0x0002'u64
            if not isFirstF:
              sf = sf or 0x0008'u64
            if not isLastF:
              sf = sf or 0x0010'u64
            # Note: buildHeaderBytes adds 0x0001 if extra present.
            result = buildHeaderBytes(2, sf, take(ts), extraStr, true,
              dataLen.uint64)
          # Decide split flags and stored CRC / extra for this fragment.
          # Peek whether file will need split at all: if total fits in
          # current volume (with header), no split.
          # Compute header len for full remaining (as if last).
          var testExtra = ""
          var testStored: uint32
          if vf.isEncrypted:
            # Final-fragment values (HashMAC on) for size estimate (extra
            # len same for non-final? Non-final extra flags 0x0001 vs final
            # 0x0003, but extra len identical (49 bytes) since flags vint
            # same length (1 byte) and check present in both. Good fixed.
            let chkArr = vf.cryptCheck12
            var chkSeq = newSeq[byte](12)
            for i in 0 ..< 12: chkSeq[i] = chkArr[i]
            testExtra = buildCryptExtra(vf.cryptSalt, vf.cryptIv,
              vf.cryptLg2, chkSeq, true)
            testStored = rarHashMacCrc(vf.cryptHashKey, vf.rawCrc)
          else:
            testStored = vf.rawCrc
          let testHdrLast = buildFragHdr(remainingTotal, isFirst, true,
            testStored, testExtra)
          if int64(curLen + testHdrLast.len + remainingTotal +
              endarcSize) <= volumeSize and
              (isFirst or off > 0):
            # Whole remaining fits as final fragment (split-before iff
            # continuation from a previous volume).
            fragLen = remainingTotal
            fragHdr = testHdrLast
            splitFlags = 0 # not needed (buildFragHdr already set flags 0? Actually buildFragHdr with isFirst=true,isLast=true gives sf=0x0002 only, no split bits. Good.)
          else:
            # Need split: this fragment is not last (unless remaining fits
            # after accounting for split overhead – recompute below).
            # First, determine fragLen that fits in avail.
            # Build header for non-last fragment (split-after or both).
            var isLastTry = false
            # Estimate header len for non-last (extra without HashMAC for
            # encrypted? Extra len same, so use testExtra with HashMAC off
            # for size? Actually len same, so use testExtra len.)
            var extraNoMac = testExtra
            var storedNoMac: uint32 = 0
            if vf.isEncrypted:
              var chkSeq2 = newSeq[byte](12)
              for i in 0 ..< 12: chkSeq2[i] = vf.cryptCheck12[i]
              extraNoMac = buildCryptExtra(vf.cryptSalt, vf.cryptIv,
                vf.cryptLg2, chkSeq2, false)
              # Packed-part CRC computed below after fragLen known.
            # Iteratively find fragLen that fits (header len depends on
            # fragLen vint len, 1-3 bytes difference – converge in 2 tries).
            fragLen = min(remainingTotal, avail - 120) # conservative base
            if fragLen <= 0:
              # Header doesn't fit in remaining space: close volume, start new.
              endVolume(true)
              startVolume()
              continue # retry this fragment at top of new volume
            # Clamp and compute exact header len.
            for _ in 0 ..< 3:
              var eExtra = ""
              var sCrc: uint32 = 0
              if vf.isEncrypted:
                if remainingTotal - fragLen == 0:
                  # This would be last fragment.
                  var chkL = newSeq[byte](12)
                  for i in 0 ..< 12: chkL[i] = vf.cryptCheck12[i]
                  eExtra = buildCryptExtra(vf.cryptSalt, vf.cryptIv,
                    vf.cryptLg2, chkL, true)
                  sCrc = rarHashMacCrc(vf.cryptHashKey, vf.rawCrc)
                else:
                  var chkN = newSeq[byte](12)
                  for i in 0 ..< 12: chkN[i] = vf.cryptCheck12[i]
                  eExtra = buildCryptExtra(vf.cryptSalt, vf.cryptIv,
                    vf.cryptLg2, chkN, false)
                  # Packed-part CRC of this fragment's ciphertext bytes.
                  var c = 0xFFFFFFFF'u32
                  for i in off ..< off + fragLen:
                    c = crc32Update(c, unsafeAddr vf.fullData[i], 1)
                  sCrc = c xor 0xFFFFFFFF'u32
              else:
                if remainingTotal - fragLen == 0:
                  sCrc = vf.rawCrc
                else:
                  var c = 0xFFFFFFFF'u32
                  for i in off ..< off + fragLen:
                    c = crc32Update(c, unsafeAddr vf.fullData[i], 1)
                  sCrc = c xor 0xFFFFFFFF'u32
              let h = buildFragHdr(fragLen, isFirst,
                remainingTotal - fragLen == 0, sCrc, eExtra)
              if curLen + h.len + fragLen + endarcSize <=
                  int(volumeSize):
                fragHdr = h
                fragStored = sCrc
                fragExtra = eExtra
                break
              # Shrink fragLen to fit.
              fragLen = int(volumeSize) - curLen - h.len - endarcSize
              if fragLen <= 0:
                endVolume(true)
                startVolume()
                fragLen = -1
                break
            if fragLen <= 0:
              continue # new volume started, retry
            # If after fitting, remainingTotal - fragLen == 0, this is last
            # fragment (flags split-before only if not first). Else middle.
          # Emit fragment.
          let isLast = off + fragLen >= total
          # Rebuild header with exact isFirst/isLast (in case our estimate
          # used tentative flags – buildFragHdr already used correct flags
          # in the loop above for the fitting case; for the no-split case
          # fragHdr already correct. For safety, if isLast differs from
          # loop assumption, rebuild once (header len change is at most
          # split-bits in hflags, same vint len, so size unchanged).
          if fragHdr == "":
            # Fallback (should not happen): build with correct flags.
            var eE = ""
            var sC: uint32
            if vf.isEncrypted:
              var chkF = newSeq[byte](12)
              for i in 0 ..< 12: chkF[i] = vf.cryptCheck12[i]
              let useMac = isLast
              eE = buildCryptExtra(vf.cryptSalt, vf.cryptIv, vf.cryptLg2,
                chkF, useMac)
              if isLast:
                sC = rarHashMacCrc(vf.cryptHashKey, vf.rawCrc)
              else:
                var c = 0xFFFFFFFF'u32
                for i in off ..< off + fragLen:
                  c = crc32Update(c, unsafeAddr vf.fullData[i], 1)
                sC = c xor 0xFFFFFFFF'u32
            else:
              if isLast:
                sC = vf.rawCrc
              else:
                var c = 0xFFFFFFFF'u32
                for i in off ..< off + fragLen:
                  c = crc32Update(c, unsafeAddr vf.fullData[i], 1)
                sC = c xor 0xFFFFFFFF'u32
            fragHdr = buildFragHdr(fragLen, isFirst, isLast, sC, eE)
          writeStr(cur, fragHdr)
          if fragLen > 0:
            writeStr(cur, vf.fullData[off ..< off + fragLen])
          off += fragLen
          firstFrag = false
          if off < total:
            endVolume(true)
            startVolume()
  endVolume(false)
  result = outVols

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
  cryptVer*: int
  cryptFlags*: uint64
  cryptLg2*: int
  cryptSalt*: array[16, byte]
  cryptIv*: array[16, byte]
  cryptCheck*: array[12, byte]
  hasCryptCheck*: bool
  useHashMac*: bool

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
  encrypted*: bool
  cryptVer*: int
  cryptFlags*: uint64
  cryptLg2*: int
  cryptSalt*: array[16, byte]
  cryptIv*: array[16, byte]
  cryptCheck*: array[12, byte]
  hasCryptCheck*: bool
  useHashMac*: bool
  password*: string ## per-call password copy for lazy decrypt on open

proc verifyRarCryptCheck*(entry: RarEntry;
    checkRaw: array[32, byte]) =
  if not entry.hasCryptCheck:
    return
  var stored: array[12, byte]
  for i in 0 ..< 12:
    stored[i] = entry.cryptCheck[i]
  if not rarVerifyCheck(stored, checkRaw):
    raise newException(RarError,
      "rar: incorrect password for " & entry.name)

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

proc verifyRarDecodedCrypt*(dec: string; unpacked: uint64; known, hasCrc: bool;
    storedCrc: uint32; hasBlake: bool; useHashMac: bool;
    hashKey: array[32, byte]) =
  if known and dec.len.uint64 != unpacked:
    raise newException(RarCodecError, "rar: size mismatch")
  if hasCrc and dec.len > 0:
    let raw =
      if dec.len == 0: 0'u32
      else: crc32Update(0xFFFFFFFF'u32, unsafeAddr dec[0], dec.len) xor
        0xFFFFFFFF'u32
    let expect =
      if useHashMac: rarHashMacCrc(hashKey, raw)
      else: raw
    if expect != storedCrc:
      # Wrong password also lands here when PswCheck was all-zero
      # (no explicit check); report as checksum to avoid oracle.
      raise newException(RarCodecError, "rar: data crc mismatch")

proc decryptRarMemberBytes*(mm: RarMember; src: Input;
    ctx: ArchiveContext): string =
  ## Decrypt one member's data area with its own salt/iv. Returns the
  ## padded plaintext as a string (LZ framing trims padding). Enforces
  ## packed-size caps before allocating.
  if not mm.encrypted:
    let sp = spanAt(src, mm.dataOff, mm.dataLen)
    result = newString(sp.len)
    if sp.len > 0:
      copyMem(addr result[0], sp.p, sp.len)
    return
  if mm.password == "":
    raise newException(RarError, "rar: password required")
  if mm.cryptVer != 0:
    raise newException(RarCodecError, "rar: unknown encryption version")
  if mm.cryptLg2 > rarKdfMaxLg2:
    raise newException(RarCodecError,
      "rar: KDF count exceeds decoder maximum")
  if ctx.maxRarUnpackedBytes > 0 and
      mm.dataLen > int(ctx.maxRarUnpackedBytes) + 16:
    raise newException(RarCodecError, "rar: unpacked size exceeds cap")
  let keys = deriveRarKeys(mm.password, mm.cryptSalt, mm.cryptLg2)
  var stored: array[12, byte]
  for i in 0 ..< 12:
    stored[i] = mm.cryptCheck[i]
  if mm.hasCryptCheck and not rarVerifyCheck(stored, keys.checkRaw):
    raise newException(RarError, "rar: incorrect password")
  let sp = spanAt(src, mm.dataOff, mm.dataLen)
  var ct = newSeq[byte](sp.len)
  if sp.len > 0:
    copyMem(addr ct[0], sp.p, sp.len)
  result = decryptRarBytes(ct, keys.key, mm.cryptIv)

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
    let limit =
      if mm.unpackedKnown: mm.unpacked
      elif ctx.maxRarUnpackedBytes > 0: uint64(ctx.maxRarUnpackedBytes)
      else: 1'u64 shl 62
    var dec: string
    var hashKey: array[32, byte]
    var useMac = false
    if mm.encrypted:
      let pt = decryptRarMemberBytes(mm, src, ctx)
      # Derive HashKey once more for MAC verification (cached per
      # member would be nicer; KDF dominates but correctness first).
      if mm.useHashMac:
        let keys = deriveRarKeys(mm.password, mm.cryptSalt, mm.cryptLg2)
        hashKey = keys.hashKey
        useMac = true
      if pt.len == 0:
        dec = ""
      else:
        dec = decodeMember(cache.state, unsafeAddr pt[0], pt.len, limit,
          if m.algo70: 1 else: 0)
    else:
      let sp = spanAt(src, mm.dataOff, mm.dataLen)
      dec = decodeMember(cache.state, sp.p, sp.len, limit,
        if m.algo70: 1 else: 0)
    if mm.encrypted and mm.useHashMac:
      verifyRarDecodedCrypt(dec, mm.unpacked, mm.unpackedKnown, mm.hasCrc,
        mm.dataCrc, mm.hasBlake, useMac, hashKey)
    else:
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
      # File encryption record (type 0x01): Version, Flags, KDF byte,
      # Salt16, IV16, Check12 if flags & 1. Tolerant: leave params
      # unset on truncation; the opener reports the real error.
      let save = inputPos(inp)
      try:
        let ver = readVint(inp)
        let cflags = readVint(inp)
        entry.cryptVer = int(ver)
        entry.cryptFlags = cflags
        entry.useHashMac = (cflags and 0x0002) != 0
        entry.hasCryptCheck = (cflags and 0x0001) != 0
        if inputPos(inp) + 1 > recEnd:
          raise newException(RarError, "rar: truncated crypt record")
        let lg = readByte(inp).int
        entry.cryptLg2 = lg
        if inputPos(inp) + 32 > recEnd:
          raise newException(RarError, "rar: truncated crypt salt/iv")
        let ss = readSpan(inp, 16)
        copyMem(addr entry.cryptSalt[0], ss.p, 16)
        let vs = readSpan(inp, 16)
        copyMem(addr entry.cryptIv[0], vs.p, 16)
        if entry.hasCryptCheck:
          if inputPos(inp) + 12 > recEnd:
            raise newException(RarError, "rar: truncated crypt check")
          let cs = readSpan(inp, 12)
          copyMem(addr entry.cryptCheck[0], cs.p, 12)
      except CatchableError:
        seek(inp, save)
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

proc parseVintBytes(data: openArray[byte]; pos: var int): uint64 =
  ## Vint decode from a byte buffer (for encrypted-header first block).
  var shift = 0
  var count = 0
  while true:
    if pos >= data.len:
      raise newException(RarError, "rar: truncated vint")
    let b = data[pos]
    inc pos
    inc count
    if count > 10:
      raise newException(RarError, "rar: vint too long")
    if shift < 64:
      result += (uint64(b and 0x7F)) shl shift
    shift += 7
    if (b and 0x80) == 0:
      break

proc readHdrEncPlaintext*(inp: Input; key: array[32, byte]): string =
  ## Consume one header-encrypted block (IV + ciphertext) from `inp`,
  ## leaving `inp` at the data-area start, and return the plaintext
  ## header block bytes (CRC + hsize + body, without padding). Verifies
  ## the header CRC.
  let blkStart = inputPos(inp)
  if remaining(inp) < 32:
    raise newException(RarError, "rar: truncated encrypted header")
  let ivSp = readSpan(inp, 16)
  var iv: array[16, byte]
  copyMem(addr iv[0], ivSp.p, 16)
  # First ciphertext block to learn the plaintext extent.
  let ct0Sp = readSpan(inp, 16)
  var ct0 = newSeq[byte](16)
  copyMem(addr ct0[0], ct0Sp.p, 16)
  let pt0 = rarAesDecrypt(key, iv, ct0)
  if pt0.len < 5:
    raise newException(RarError, "rar: truncated encrypted header")
  var p = 4
  let hsize = parseVintBytes(pt0, p)
  if hsize > rarMaxHeaderSize.uint64:
    raise newException(RarError, "rar: header too large")
  let hsizeLen = p - 4
  let plainExtent = 4 + hsizeLen + int(hsize)
  if plainExtent < 5 or plainExtent > pt0.len + 1000000:
    # plainExtent must be sane; full check after reading all.
    discard
  let ctLen = ((plainExtent + 15) div 16) * 16
  if ctLen < 16 or ctLen > int(rarMaxHeaderSize) + 16:
    raise newException(RarError, "rar: header too large")
  var fullCt = newSeq[byte](ctLen)
  copyMem(addr fullCt[0], addr ct0[0], 16)
  if ctLen > 16:
    if remaining(inp) < ctLen - 16:
      raise newException(RarError, "rar: truncated encrypted header")
    let restSp = readSpan(inp, ctLen - 16)
    copyMem(addr fullCt[16], restSp.p, ctLen - 16)
  let fullPt = rarAesDecrypt(key, iv, fullCt)
  if fullPt.len < plainExtent:
    raise newException(RarError, "rar: truncated encrypted header")
  # CRC over plaintext bytes [4 ..< plainExtent].
  var calc = crc32Update(0xFFFFFFFF'u32, unsafeAddr fullPt[4],
    plainExtent - 4) xor 0xFFFFFFFF'u32
  var stored: uint32 = fullPt[0].uint32 or (fullPt[1].uint32 shl 8) or
    (fullPt[2].uint32 shl 16) or (fullPt[3].uint32 shl 24)
  if calc != stored:
    raise newException(RarError, "rar: header crc mismatch")
  result = newString(plainExtent)
  copyMem(addr result[0], unsafeAddr fullPt[0], plainExtent)
  discard blkStart

proc parseHeadCrypt*(typeSpecific: string; recEnd: int): tuple[
    ver: int; flags: uint64; lg2: int; salt: array[16, byte];
    check: array[12, byte]; hasCheck: bool] =
  ## Parse HEAD_CRYPT / file-crypt-agnostic? Only for archive header
  ## (type 4) type-specific bytes: Version, Flags, Lg2, Salt16, Check12.
  ## `typeSpecific` is the raw type-specific bytes (from Type start to
  ## Extra start). Raises RarError on truncation.
  var pos = 0
  proc rv(): uint64 =
    var shift = 0
    var cnt = 0
    while true:
      if pos >= typeSpecific.len:
        raise newException(RarError, "rar: truncated crypt header")
      let b = typeSpecific[pos].byte
      inc pos
      inc cnt
      if cnt > 10:
        raise newException(RarError, "rar: vint too long")
      if shift < 64:
        result += (uint64(b and 0x7F)) shl shift
      shift += 7
      if (b and 0x80) == 0:
        break
  let ver = int(rv())
  let fl = rv()
  if pos >= typeSpecific.len:
    raise newException(RarError, "rar: truncated crypt header")
  let lg = int(typeSpecific[pos].byte)
  inc pos
  if pos + 16 > typeSpecific.len:
    raise newException(RarError, "rar: truncated crypt salt")
  for i in 0 ..< 16:
    result.salt[i] = typeSpecific[pos + i].byte
  pos += 16
  result.ver = ver
  result.flags = fl
  result.lg2 = lg
  result.hasCheck = (fl and 1) != 0
  if result.hasCheck:
    if pos + 12 > typeSpecific.len:
      raise newException(RarError, "rar: truncated crypt check")
    for i in 0 ..< 12:
      result.check[i] = typeSpecific[pos + i].byte
  discard recEnd

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
      # (multivolume reassembly lives in extractRarVolumes; single-shot
      # extractRar refuses split parts with a clear error).
      if (hflags and 0x0008) != 0 or (hflags and 0x0010) != 0:
        raise newException(RarError,
          "rar: multivolume split unsupported in v1")
      if isService:
        # skip data (ACL/STM/CMT/QO/RR): metadata loss documented.
        # Encrypted service payloads are skipped as ciphertext; no
        # password needed since nothing is decoded.
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
      let ePwd = r.password
      proc opener(): Input =
        if compMethod(e.compInfo) == 0:
          if curCtx.maxRarUnpackedBytes != 0 and
              e.size > curCtx.maxRarUnpackedBytes:
            raise newException(RarError, "rar: unpacked size exceeds cap")
          if e.encrypted:
            if ePwd == "":
              raise newException(RarError, "rar: password required")
            if e.cryptVer != 0:
              raise newException(RarCodecError,
                "rar: unknown encryption version")
            if e.cryptLg2 > rarKdfMaxLg2:
              raise newException(RarCodecError,
                "rar: KDF count exceeds decoder maximum")
            let keys = deriveRarKeys(ePwd, e.cryptSalt, e.cryptLg2)
            var stored: array[12, byte]
            for i in 0 ..< 12:
              stored[i] = e.cryptCheck[i]
            if e.hasCryptCheck and not rarVerifyCheck(stored, keys.checkRaw):
              raise newException(RarError, "rar: incorrect password")
            let sp = spanAt(src, e.dataOff, e.dataLen)
            var ct = newSeq[byte](sp.len)
            if sp.len > 0:
              copyMem(addr ct[0], sp.p, sp.len)
            let fullPt = decryptRarBytes(ct, keys.key, e.cryptIv)
            # Zero padding: ciphertext pads to 16 bytes; plaintext is
            # the first e.size bytes.
            if fullPt.len < int(e.size):
              raise newException(RarError, "rar: truncated file data")
            let pt = fullPt[0 ..< int(e.size)]
            if e.hasCrc and pt.len > 0:
              let raw = crc32Update(0xFFFFFFFF'u32, unsafeAddr pt[0],
                pt.len) xor 0xFFFFFFFF'u32
              let expect =
                if e.useHashMac: rarHashMacCrc(keys.hashKey, raw)
                else: raw
              if expect != e.dataCrc:
                raise newException(RarError, "rar: data crc mismatch")
            # Pin the plaintext in the closure env (same ORC pattern
            # as the compressed path).
            owned = pt
            done = true
            return openInputString(owned)
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
          dictSize: ds, algo70: algo70, meth: meth, grp: grp,
          encrypted: e.encrypted, cryptVer: e.cryptVer,
          cryptFlags: e.cryptFlags, cryptLg2: e.cryptLg2,
          cryptSalt: e.cryptSalt, cryptIv: e.cryptIv,
          cryptCheck: e.cryptCheck, hasCryptCheck: e.hasCryptCheck,
          useHashMac: e.useHashMac, password: r.password))
      ctx.reportProgress(nm, index, -1, e.size)
      inc index
      {.gcsafe.}:
        handle(ctx, fi)
      skip(inp, int(dataSize))
    of 4:
      # HEAD_CRYPT (archive-wide header encryption): derive the archive
      # key and rebuild a clear archive in memory, then walk it with the
      # existing per-file logic (which handles per-file AES). Full-copy
      # is bounded by the unpacked cap plus headers; header-encrypted
      # archives are rare and small in practice. Zero-copy is preserved
      # for clear archives; encrypted-header STORE necessarily copies
      # through decryption anyway.
      if r.password == "":
        raise newException(RarError, "rar: password required")
      # Type-specific starts at typeStart (current inp pos), ends at
      # headerEnd (no extra for HEAD_CRYPT). Parse Version/Flags/Lg2/
      # Salt/Check from the clear bytes.
      let tsLen = headerEnd - typeStart
      if tsLen <= 0 or tsLen > 64:
        raise newException(RarError, "rar: bad crypt header")
      let tsSp = spanAt(inp, typeStart, tsLen)
      var tsStr = newString(tsLen)
      copyMem(addr tsStr[0], tsSp.p, tsLen)
      let hc = parseHeadCrypt(tsStr, 0)
      if hc.ver != 0:
        raise newException(RarCodecError, "rar: unknown encryption version")
      if hc.lg2 > rarKdfMaxLg2:
        raise newException(RarCodecError,
          "rar: KDF count exceeds decoder maximum")
      let akeys = deriveRarKeys(r.password, hc.salt, hc.lg2)
      var stored12: array[12, byte]
      for i in 0 ..< 12:
        stored12[i] = hc.check[i]
      if hc.hasCheck and not rarVerifyCheck(stored12, akeys.checkRaw):
        raise newException(RarError, "rar: incorrect password")
      # Position after HEAD_CRYPT (header has no data).
      seek(inp, headerEnd)
      let clearOut = newOutput()
      writeStr(clearOut, rar5Magic)
      var totalCopied: uint64 = 0
      let cap =
        if ctx.maxRarUnpackedBytes > 0: uint64(ctx.maxRarUnpackedBytes) +
          16 * 1024 * 1024 else: 1'u64 shl 62
      var encHeaders = 0
      while true:
        ctx.checkCancelled()
        if remaining(inp) == 0:
          break
        inc encHeaders
        if encHeaders > rarMaxHeaderCount:
          raise newException(RarError, "rar: too many headers")
        let plain = readHdrEncPlaintext(inp, akeys.key)
        # Learn dataSize by parsing the plaintext header.
        let hin = openInputString(plain)
        discard readU32le(hin) # stored crc (already verified)
        discard readVint(hin) # hsize
        let eht = readVint(hin)
        let ehf = readVint(hin)
        var eextra: uint64 = 0
        var edata: uint64 = 0
        if (ehf and 0x0001) != 0:
          eextra = readVint(hin)
        if (ehf and 0x0002) != 0:
          edata = readVint(hin)
        # Write the clear header block.
        writeStr(clearOut, plain)
        if edata > 0:
          if edata > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated file data")
          totalCopied += edata
          if totalCopied > cap:
            raise newException(RarCodecError,
              "rar: unpacked size exceeds cap")
          let dsp = readSpan(inp, int(edata))
          if dsp.len > 0:
            writeBytes(clearOut, dsp.p, dsp.len)
        if eht == 5:
          break
      let clearInp = toInput(clearOut)
      extractRar(r, ctx, clearInp, handle)
      return
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

# ---------- multivolume reader ----------

type RarVolFrag = object
  dataOff: int
  dataLen: int
  volIdx: int
  storedCrc: uint32
  hasCrc: bool

type RarVolLogical = object
  name: string
  isDir, isSymlink: bool
  linkTarget: string
  size: int64
  modTime: Time
  mode: int
  compInfo: uint64
  fileFlags: uint64
  hasCrcFinal: bool
  dataCrcFinal: uint32
  hasBlake: bool
  encrypted: bool
  cryptVer: int
  cryptFlagsFinal: uint64
  cryptLg2: int
  cryptSalt, cryptIv: array[16, byte]
  cryptCheck: array[12, byte]
  hasCryptCheck: bool
  useHashMacFinal: bool
  frags: seq[RarVolFrag]

proc extractRarVolumes*(r: Rar; ctx: ArchiveContext;
    volumes: openArray[Input]; handle: FileHandler) =
  ## Walk a multivolume set in order, reassembling split files (data
  ## areas concatenated across volumes) before decoding. Non-solid only
  ## in v1; solid multivolume and header-encrypted multivolume are
  ## refused with clear errors. Listing stays cheap (headers only);
  ## reassembly buffers are bounded by the unpacked cap.
  if volumes.len == 0:
    raise newException(RarError, "rar: no volumes")
  if r.encHeaders:
    # Header-encrypted multivolume would need the arch key shared across
    # volumes; refuse for now (single-volume header encryption works).
    # Callers can still read header-encrypted single volumes via extractRar.
    raise newException(RarError,
      "rar: header-encrypted multivolume unsupported in v1")
  var pending: RarVolLogical
  var hasPending = false
  var volNo = 0
  var totalLogical = 0
  # For non-split STORE zero-copy: need volume Inputs retained (kept by
  # caller; volumes array outlives extraction).
  for vi, vinp in volumes:
    let inp = vinp
    if remaining(inp) < 8:
      raise newException(RarError, "rar: truncated signature")
    let sig = readSpan(inp, 8)
    if not spanEqual(sig, rar5Magic):
      raise newException(RarError, "rar: bad signature")
    var headerCount = 0
    var expectVolNum = vi # vol 0 has no number, vol>=1 has number volIdx
    while true:
      ctx.checkCancelled()
      if remaining(inp) == 0:
        break
      let blockPos = inputPos(inp)
      # Tolerant trailing zeros (WinRAR pads volumes to the size budget):
      # if the rest is all zeros, treat as EOF, not a header.
      var allZero = true
      for i in 0 ..< remaining(inp):
        if byteAt(inp, inputPos(inp) + i) != 0:
          allZero = false
          break
      if allZero:
        break
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
      let crcSpan = spanAt(inp, hsizePos, hsizeBytes + int(hsize))
      let calc =
        if crcSpan.len == 0: 0xFFFFFFFF'u32
        else: crc32Update(0xFFFFFFFF'u32, crcSpan.p, crcSpan.len) xor
          0xFFFFFFFF'u32
      if calc != storedCrc:
        raise newException(RarError, "rar: header crc mismatch")
      let htype = readVint(inp)
      let hflags = readVint(inp)
      var extraSize: uint64 = 0
      var dataSize: uint64 = 0
      if (hflags and 0x0001) != 0:
        extraSize = readVint(inp)
      if (hflags and 0x0002) != 0:
        dataSize = readVint(inp)
      if inputPos(inp) > headerEnd:
        raise newException(RarError, "rar: header overrun")
      inc headerCount
      if headerCount > rarMaxHeaderCount:
        raise newException(RarError, "rar: too many headers")
      case htype
      of 1: # main
        let archFlags = readVint(inp)
        if (archFlags and 0x0001) == 0:
          raise newException(RarError, "rar: not a volume")
        if vi == 0:
          if (archFlags and 0x0002) != 0:
            raise newException(RarError, "rar: first volume has number")
        else:
          if (archFlags and 0x0002) == 0:
            raise newException(RarError, "rar: volume number missing")
          let vn = readVint(inp)
          if vn != expectVolNum.uint64:
            raise newException(RarError, "rar: wrong volume number")
        if (archFlags and 0x0004) != 0:
          raise newException(RarError,
            "rar: solid multivolume unsupported in v1")
        seek(inp, headerEnd)
        if (hflags and 0x0002) != 0:
          if dataSize > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated main data")
          skip(inp, int(dataSize))
      of 4:
        raise newException(RarError,
          "rar: header-encrypted multivolume unsupported in v1")
      of 2, 3:
        let isService = htype == 3
        let fileFlags = readVint(inp)
        let unpacked = readVint(inp)
        let attrs = readVint(inp)
        var mtime = fromUnix(0)
        if (fileFlags and 0x0002) != 0:
          mtime = fromUnix(readU32le(inp).int64)
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
          modTime: mtime, compInfo: compInfo, dataCrc: dcrc, hasCrc: hasCrc)
        entry.mode =
          if hostOs == 1: int(attrs)
          elif (fileFlags and 0x0001) != 0: 0o40755
          else: 0o100644
        if (fileFlags and 0x0001) != 0:
          entry.isDir = true
        let extraStart = headerEnd - int(extraSize)
        if extraSize > 0:
          if extraStart < inputPos(inp) or headerEnd < extraStart:
            raise newException(RarError, "rar: bad extra area")
          seek(inp, extraStart)
          parseExtra(inp, headerEnd, entry)
          seek(inp, headerEnd)
        else:
          seek(inp, headerEnd)
        let splitBefore = (hflags and 0x0008) != 0
        let splitAfter = (hflags and 0x0010) != 0
        if compSolid(compInfo):
          raise newException(RarError,
            "rar: solid multivolume unsupported in v1")
        if isService:
          if uint64(remaining(inp)) < dataSize:
            raise newException(RarError, "rar: truncated service data")
          # Per-fragment packed CRC for split services is ignored (skipped).
          skip(inp, int(dataSize))
          continue
        if entry.isDir:
          if splitBefore or splitAfter:
            raise newException(RarError, "rar: split directory")
          if dataSize != 0:
            if dataSize > uint64(remaining(inp)):
              raise newException(RarError, "rar: truncated dir data")
            skip(inp, int(dataSize))
          var meta = FileMeta(name: baseNameV(nm), size: 0,
            mode: entry.mode, modTime: entry.modTime, isDir: true,
            isSymlink: false, isRegular: false)
          let fi = FileInfo(meta: meta, nameInArchive: nm,
            linkTarget: "", open: stringOpener(""))
          ctx.reportProgress(nm, totalLogical, -1, 0)
          inc totalLogical
          {.gcsafe.}:
            handle(ctx, fi)
          continue
        if entry.isSymlink:
          if splitBefore or splitAfter:
            raise newException(RarError, "rar: split symlink")
          if dataSize != 0:
            if dataSize > uint64(remaining(inp)):
              raise newException(RarError, "rar: truncated link data")
            skip(inp, int(dataSize))
          var meta = FileMeta(name: baseNameV(nm), size: entry.size,
            mode: entry.mode, modTime: entry.modTime, isDir: false,
            isSymlink: true, isRegular: false)
          let fi = FileInfo(meta: meta, nameInArchive: nm,
            linkTarget: entry.linkTarget, open: stringOpener(""))
          ctx.reportProgress(nm, totalLogical, -1, entry.size)
          inc totalLogical
          {.gcsafe.}:
            handle(ctx, fi)
          continue
        # Regular file (possibly split).
        if uint64(remaining(inp)) < dataSize:
          raise newException(RarError, "rar: truncated file data")
        let fragOff = inputPos(inp)
        let fragLen = int(dataSize)
        # Per-fragment packed CRC check for non-final parts when the file
        # carries a CRC (split files store packed-part CRCs raw, even when
        # the final unpacked CRC is HashMAC'd).
        let isLastFrag = not splitAfter
        if hasCrc and not isLastFrag and fragLen > 0:
          # Non-final packed-part CRC is always raw (never HashMAC'd).
          let fsp = spanAt(inp, fragOff, fragLen)
          let got = crc32Update(0xFFFFFFFF'u32, fsp.p, fsp.len) xor
            0xFFFFFFFF'u32
          if got != dcrc:
            raise newException(RarError, "rar: data crc mismatch")
        if not splitBefore and not splitAfter:
          # Whole file in this volume.
          if hasPending:
            raise newException(RarError, "rar: missing split continuation")
          # Zero-copy fast path for unencrypted STORE.
          if compMethod(compInfo) == 0 and not entry.encrypted:
            if ctx.maxRarUnpackedBytes != 0 and
                entry.size > ctx.maxRarUnpackedBytes:
              raise newException(RarError,
                "rar: unpacked size exceeds cap")
            if fragLen != int(entry.size):
              raise newException(RarError, "rar: size mismatch")
            let e = entry
            let src = inp
            let curCtx = ctx
            proc opener(): Input =
              if e.hasCrc and fragLen > 0:
                let sp = spanAt(src, fragOff, fragLen)
                let got = crc32Update(0xFFFFFFFF'u32, sp.p, sp.len) xor
                  0xFFFFFFFF'u32
                if got != e.dataCrc:
                  raise newException(RarError, "rar: data crc mismatch")
              openInputView(spanAt(src, fragOff, fragLen), src)
            var meta = FileMeta(name: baseNameV(nm), size: e.size,
              mode: e.mode, modTime: e.modTime, isDir: false,
              isSymlink: false, isRegular: true)
            let fi = FileInfo(meta: meta, nameInArchive: nm,
              linkTarget: "", open: opener)
            ctx.reportProgress(nm, totalLogical, -1, e.size)
            inc totalLogical
            {.gcsafe.}:
              handle(ctx, fi)
            skip(inp, fragLen)
          else:
            # Compressed or encrypted: reassemble single-fragment logical
            # file (copy bounded by the unpacked cap) then decode.
            if ctx.maxRarUnpackedBytes > 0 and
                fragLen > int(ctx.maxRarUnpackedBytes) + 16:
              raise newException(RarCodecError,
                "rar: unpacked size exceeds cap")
            var packed = newString(fragLen)
            if fragLen > 0:
              let fsp = spanAt(inp, fragOff, fragLen)
              copyMem(addr packed[0], fsp.p, fragLen)
            skip(inp, fragLen)
            let e = entry
            let curCtx = ctx
            let curIdx = totalLogical
            let pwd = r.password
            var owned = ""
            var done = false
            proc opener(): Input =
              if compMethod(e.compInfo) == 0:
                if curCtx.maxRarUnpackedBytes != 0 and
                    e.size > curCtx.maxRarUnpackedBytes:
                  raise newException(RarError,
                    "rar: unpacked size exceeds cap")
                var pt = packed
                if e.encrypted:
                  if pwd == "":
                    raise newException(RarError, "rar: password required")
                  if e.cryptVer != 0:
                    raise newException(RarCodecError,
                      "rar: unknown encryption version")
                  let keys = deriveRarKeys(pwd, e.cryptSalt, e.cryptLg2)
                  var st: array[12, byte]
                  for i in 0 ..< 12: st[i] = e.cryptCheck[i]
                  if e.hasCryptCheck and
                      not rarVerifyCheck(st, keys.checkRaw):
                    raise newException(RarError, "rar: incorrect password")
                  var ct = newSeq[byte](packed.len)
                  if packed.len > 0:
                    copyMem(addr ct[0], unsafeAddr packed[0], packed.len)
                  let full = decryptRarBytes(ct, keys.key, e.cryptIv)
                  if full.len < int(e.size):
                    raise newException(RarError,
                      "rar: truncated file data")
                  pt = full[0 ..< int(e.size)]
                  if e.hasCrc and pt.len > 0:
                    let raw = crc32Update(0xFFFFFFFF'u32,
                      unsafeAddr pt[0], pt.len) xor 0xFFFFFFFF'u32
                    let expect =
                      if e.useHashMac: rarHashMacCrc(keys.hashKey, raw)
                      else: raw
                    if expect != e.dataCrc:
                      raise newException(RarError,
                        "rar: data crc mismatch")
                else:
                  if packed.len != int(e.size):
                    raise newException(RarError, "rar: size mismatch")
                  if e.hasCrc and packed.len > 0:
                    let got = crc32Update(0xFFFFFFFF'u32,
                      unsafeAddr packed[0], packed.len) xor 0xFFFFFFFF'u32
                    if got != e.dataCrc:
                      raise newException(RarError,
                        "rar: data crc mismatch")
                owned = pt
                done = true
                return openInputString(owned)
              # Compressed: fresh window per file (non-solid multivolume).
              let m = checkRarMethod(e.compInfo,
                cast[uint64](e.size), curCtx)
              if m.meth notin 1 .. 5:
                raise newException(RarCodecError,
                  "rar: unknown compression method " & $m.meth)
              var st = UnpackState()
              resetUnpack(st, int(m.dictSize), if m.algo70: 1 else: 0)
              var ptPacked = packed
              if e.encrypted:
                if pwd == "":
                  raise newException(RarError, "rar: password required")
                if e.cryptVer != 0:
                  raise newException(RarCodecError,
                    "rar: unknown encryption version")
                let keys = deriveRarKeys(pwd, e.cryptSalt, e.cryptLg2)
                var stc: array[12, byte]
                for i in 0 ..< 12: stc[i] = e.cryptCheck[i]
                if e.hasCryptCheck and
                    not rarVerifyCheck(stc, keys.checkRaw):
                  raise newException(RarError, "rar: incorrect password")
                var ct = newSeq[byte](packed.len)
                if packed.len > 0:
                  copyMem(addr ct[0], unsafeAddr packed[0], packed.len)
                ptPacked = decryptRarBytes(ct, keys.key, e.cryptIv)
              let limit =
                if curCtx.maxRarUnpackedBytes > 0:
                  uint64(curCtx.maxRarUnpackedBytes)
                else: 1'u64 shl 62
              let dec = decodeMember(st, unsafeAddr ptPacked[0],
                ptPacked.len, limit, if m.algo70: 1 else: 0)
              if e.encrypted and e.useHashMac:
                let keys2 = deriveRarKeys(pwd, e.cryptSalt, e.cryptLg2)
                verifyRarDecodedCrypt(dec, cast[uint64](e.size), true,
                  e.hasCrc, e.dataCrc, e.hasBlake, true, keys2.hashKey)
              else:
                verifyRarDecoded(dec, cast[uint64](e.size), true,
                  e.hasCrc, e.dataCrc, e.hasBlake)
              owned = dec
              done = true
              openInputString(owned)
            var meta = FileMeta(name: baseNameV(nm), size: e.size,
              mode: e.mode, modTime: e.modTime, isDir: false,
              isSymlink: false, isRegular: true)
            let fi = FileInfo(meta: meta, nameInArchive: nm,
              linkTarget: "", open: opener)
            ctx.reportProgress(nm, totalLogical, -1, e.size)
            inc totalLogical
            {.gcsafe.}:
              handle(ctx, fi)
        else:
          # Split file: accumulate fragments, emit on last part.
          if not splitBefore and splitAfter:
            if hasPending:
              raise newException(RarError,
                "rar: missing split continuation")
            hasPending = true
            pending = RarVolLogical(name: nm, size: entry.size,
              modTime: entry.modTime, mode: entry.mode,
              compInfo: entry.compInfo, fileFlags: fileFlags,
              hasCrcFinal: false, hasBlake: entry.hasBlake,
              encrypted: entry.encrypted, cryptVer: entry.cryptVer,
              cryptLg2: entry.cryptLg2, cryptSalt: entry.cryptSalt,
              cryptIv: entry.cryptIv, cryptCheck: entry.cryptCheck,
              hasCryptCheck: entry.hasCryptCheck,
              useHashMacFinal: false, frags: @[])
            # First fragment's crypt flags must not have HashMAC (only last).
            if entry.encrypted and entry.useHashMac:
              raise newException(RarError,
                "rar: HashMAC on non-final split part")
          else:
            if not hasPending:
              raise newException(RarError,
                "rar: split continuation without start")
            if pending.name != nm or
                pending.compInfo != compInfo or
                pending.size != entry.size:
              raise newException(RarError, "rar: split header mismatch")
            if pending.encrypted != entry.encrypted:
              raise newException(RarError, "rar: split header mismatch")
            if entry.encrypted:
              for i in 0 ..< 16:
                if pending.cryptSalt[i] != entry.cryptSalt[i] or
                    pending.cryptIv[i] != entry.cryptIv[i]:
                  raise newException(RarError,
                    "rar: split salt/iv mismatch")
              if entry.cryptLg2 != pending.cryptLg2:
                raise newException(RarError,
                  "rar: split KDF mismatch")
          # Append this fragment's bytes (bounded by the unpacked cap).
          if ctx.maxRarUnpackedBytes > 0 and
              fragLen > int(ctx.maxRarUnpackedBytes) + 16:
            raise newException(RarCodecError,
              "rar: unpacked size exceeds cap")
          pending.frags.add(RarVolFrag(dataOff: fragOff,
            dataLen: fragLen, volIdx: vi, storedCrc: dcrc, hasCrc: hasCrc))
          # Remember final-part verification material.
          if isLastFrag:
            pending.hasCrcFinal = hasCrc
            pending.dataCrcFinal = dcrc
            pending.hasBlake = pending.hasBlake or entry.hasBlake
            pending.cryptFlagsFinal = entry.cryptFlags
            pending.useHashMacFinal = entry.useHashMac
            pending.hasCryptCheck = entry.hasCryptCheck
            pending.cryptCheck = entry.cryptCheck
            if entry.encrypted and entry.useHashMac == false and
                pending.encrypted:
              # Final part of an encrypted file should carry HashMAC when
              # the file is encrypted with hashing (our writer always sets
              # it); WinRAR may omit it for STORE? Tolerate either.
              discard
          skip(inp, fragLen)
          if isLastFrag:
            # Reassemble logical packed data from fragments across volumes.
            var totalPacked = 0
            for fg in pending.frags:
              totalPacked += fg.dataLen
            if ctx.maxRarUnpackedBytes > 0 and
                totalPacked > int(ctx.maxRarUnpackedBytes) + 16:
              raise newException(RarCodecError,
                "rar: unpacked size exceeds cap")
            var packed = newString(totalPacked)
            var poff = 0
            for fg in pending.frags:
              let vsrc = volumes[fg.volIdx]
              let fsp = spanAt(vsrc, fg.dataOff, fg.dataLen)
              if fg.dataLen > 0:
                copyMem(addr packed[poff], fsp.p, fg.dataLen)
              poff += fg.dataLen
            let lp = pending
            hasPending = false
            let curCtx2 = ctx
            let curIdx2 = totalLogical
            let pwd2 = r.password
            var owned2 = ""
            var done2 = false
            # Capture packed by value (owned string, pinned in closure).
            let packedOwned = packed
            proc opener2(): Input =
              if compMethod(lp.compInfo) == 0:
                if curCtx2.maxRarUnpackedBytes != 0 and
                    lp.size > curCtx2.maxRarUnpackedBytes:
                  raise newException(RarError,
                    "rar: unpacked size exceeds cap")
                var pt = packedOwned
                if lp.encrypted:
                  if pwd2 == "":
                    raise newException(RarError, "rar: password required")
                  if lp.cryptVer != 0:
                    raise newException(RarCodecError,
                      "rar: unknown encryption version")
                  let keys = deriveRarKeys(pwd2, lp.cryptSalt, lp.cryptLg2)
                  var st: array[12, byte]
                  for i in 0 ..< 12: st[i] = lp.cryptCheck[i]
                  if lp.hasCryptCheck and
                      not rarVerifyCheck(st, keys.checkRaw):
                    raise newException(RarError, "rar: incorrect password")
                  var ct = newSeq[byte](packedOwned.len)
                  if packedOwned.len > 0:
                    copyMem(addr ct[0], unsafeAddr packedOwned[0],
                      packedOwned.len)
                  let full = decryptRarBytes(ct, keys.key, lp.cryptIv)
                  if full.len < int(lp.size):
                    raise newException(RarError,
                      "rar: truncated file data")
                  pt = full[0 ..< int(lp.size)]
                  if lp.hasCrcFinal and pt.len > 0:
                    let raw = crc32Update(0xFFFFFFFF'u32,
                      unsafeAddr pt[0], pt.len) xor 0xFFFFFFFF'u32
                    let expect =
                      if lp.useHashMacFinal:
                        rarHashMacCrc(keys.hashKey, raw)
                      else: raw
                    if expect != lp.dataCrcFinal:
                      raise newException(RarError,
                        "rar: data crc mismatch")
                else:
                  if packedOwned.len != int(lp.size):
                    raise newException(RarError, "rar: size mismatch")
                  if lp.hasCrcFinal and packedOwned.len > 0:
                    let got = crc32Update(0xFFFFFFFF'u32,
                      unsafeAddr packedOwned[0], packedOwned.len) xor
                      0xFFFFFFFF'u32
                    if got != lp.dataCrcFinal:
                      raise newException(RarError,
                        "rar: data crc mismatch")
                owned2 = pt
                done2 = true
                return openInputString(owned2)
              let m = checkRarMethod(lp.compInfo,
                cast[uint64](lp.size), curCtx2)
              if m.meth notin 1 .. 5:
                raise newException(RarCodecError,
                  "rar: unknown compression method " & $m.meth)
              var st = UnpackState()
              resetUnpack(st, int(m.dictSize), if m.algo70: 1 else: 0)
              var ptPacked = packedOwned
              if lp.encrypted:
                if pwd2 == "":
                  raise newException(RarError, "rar: password required")
                if lp.cryptVer != 0:
                  raise newException(RarCodecError,
                    "rar: unknown encryption version")
                let keys = deriveRarKeys(pwd2, lp.cryptSalt, lp.cryptLg2)
                var stc: array[12, byte]
                for i in 0 ..< 12: stc[i] = lp.cryptCheck[i]
                if lp.hasCryptCheck and
                    not rarVerifyCheck(stc, keys.checkRaw):
                  raise newException(RarError, "rar: incorrect password")
                var ct = newSeq[byte](packedOwned.len)
                if packedOwned.len > 0:
                  copyMem(addr ct[0], unsafeAddr packedOwned[0],
                    packedOwned.len)
                ptPacked = decryptRarBytes(ct, keys.key, lp.cryptIv)
              let limit =
                if curCtx2.maxRarUnpackedBytes > 0:
                  uint64(curCtx2.maxRarUnpackedBytes)
                else: 1'u64 shl 62
              let dec = decodeMember(st, unsafeAddr ptPacked[0],
                ptPacked.len, limit, if m.algo70: 1 else: 0)
              if lp.encrypted and lp.useHashMacFinal:
                let keys2 = deriveRarKeys(pwd2, lp.cryptSalt, lp.cryptLg2)
                verifyRarDecodedCrypt(dec, cast[uint64](lp.size), true,
                  lp.hasCrcFinal, lp.dataCrcFinal, lp.hasBlake, true,
                  keys2.hashKey)
              else:
                verifyRarDecoded(dec, cast[uint64](lp.size), true,
                  lp.hasCrcFinal, lp.dataCrcFinal, lp.hasBlake)
              owned2 = dec
              done2 = true
              openInputString(owned2)
            var meta = FileMeta(name: baseNameV(lp.name), size: lp.size,
              mode: lp.mode, modTime: lp.modTime, isDir: false,
              isSymlink: false, isRegular: true)
            let fi = FileInfo(meta: meta, nameInArchive: lp.name,
              linkTarget: "", open: opener2)
            ctx.reportProgress(lp.name, totalLogical, -1, lp.size)
            inc totalLogical
            {.gcsafe.}:
              handle(ctx, fi)
      of 5:
        seek(inp, headerEnd)
        if dataSize > 0:
          if dataSize > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated endarc data")
          skip(inp, int(dataSize))
        # Non-last volumes carry EHFL_NEXTVOLUME; the caller supplies the
        # next volume explicitly, so just continue. Last volume ends here.
        # Detect last by endflags: type-specific vint at typeStart.
        var ef: uint64 = 0
        let save = inputPos(inp)
        # typeStart is before headerEnd; endflags vint is the type-specific.
        # Re-parse cheaply: seek to typeStart, read vint, restore.
        # For clear headers, typeStart is in inp coordinates.
        # (Encoded headers never reach here: header-encrypted multivolume
        # is refused above.)
        seek(inp, headerEnd) # ensure at header end before data? Already.
        # Actually typeStart was recorded before; re-read endflags:
        # (headerEnd - typeStart) bytes are type-specific; for ENDARC it's
        # a single vint. Parse from a span to avoid moving inp.
        # Simplest: if this is not the last volume in the caller's list,
        # expect next-volume flag; if it is the last, expect final.
        # We validate loosely: trailing data after ENDARC (padding) is
        # ignored by breaking only on last volume.
        if vi + 1 < volumes.len:
          # Expect continuation; keep walking this volume's trailing bytes
          # (usually padding zeros) then proceed to next volume.
          # Break inner walk to advance to next volume.
          discard ef
          discard save
          break
        else:
          break
      else:
        seek(inp, headerEnd)
        if (hflags and 0x0002) != 0:
          if dataSize > uint64(remaining(inp)):
            raise newException(RarError, "rar: truncated unknown data")
          skip(inp, int(dataSize))
      let nextPos = inputPos(inp)
      if nextPos <= blockPos:
        raise newException(RarError, "rar: walk did not advance")
    inc volNo
  if hasPending:
    raise newException(RarError, "rar: missing split continuation")
