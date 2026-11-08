## RAR5/7.0 Unpack50/70 LZ+Huffman decoder (STORE is handled inline).
##
## Clean-room implementation from the format specification: MSB-first
## bitstream, canonical Huffman tables per the DEFLATE rule (max 15 bits),
## length/distance slot codecs, repeat-distance ring, circular LZ window
## with out-of-window zero-fill, and hardcoded post-filters (DELTA, E8,
## E8E9, ARM) applied once per file at end of stream over disjoint regions.
##
## No globals: all mutable state lives in UnpackState (per solid group),
## so every proc is safe to call from any thread. Memory is bounded by
## the caller's dictionary cap (window) plus the decoded entry, itself
## bounded by the unpacked-size cap.

import ../types

type RarCodecError* = object of ArchiveError

const
  rarMainSyms* = 306
  rarDistSyms50* = 64
  rarDistSyms70* = 80
  rarAlignSyms* = 16
  rarLenSyms* = 44
  rarLevelSyms* = 20
  rarMaxCodeLen* = 15
  rarMaxFilters* = 8192
  rarMaxFilterLen* = 1 shl 22
  rarBonusDist1* = 0x100'u64
  rarBonusDist2* = 0x2000'u64
  rarBonusDist3* = 0x40000'u64

# ---------- MSB-first bit reader ----------

type BitReader = object
  p: ptr UncheckedArray[byte]
  len: int
  bytePos: int
  cache: uint64 ## valid bits left-aligned in the high `bits` positions
  bits: int
  read: int     ## total bits consumed (payload bound)

proc initBitReader(p: pointer; len: int): BitReader =
  BitReader(p: cast[ptr UncheckedArray[byte]](p), len: len)

proc refill(br: var BitReader) =
  while br.bits <= 56 and br.bytePos < br.len:
    br.cache = br.cache or (br.p[br.bytePos].uint64 shl (56 - br.bits))
    inc br.bytePos
    br.bits += 8

proc readBits(br: var BitReader; n: int): uint64 =
  ## Read 0..32 bits, MSB-first. Raises on truncation.
  if n == 0:
    return 0
  doAssert n > 0 and n <= 32
  if br.bits < n:
    refill(br)
    if br.bits < n:
      raise newException(RarCodecError, "rar: truncated block stream")
  result = br.cache shr (64 - n)
  br.cache = br.cache shl n
  br.bits -= n
  br.read += n

proc readBitsWide(br: var BitReader; n: int): uint64 =
  ## Read 0..64 bits in 16-bit chunks (for Unpack70 large distances).
  var left = n
  while left > 0:
    let take = min(left, 16)
    result = (result shl take) or br.readBits(take)
    left -= take

# ---------- canonical Huffman (DEFLATE rule) ----------

type HuffTable = object
  counts: array[16, int] ## per length 1..15
  first: array[16, int]  ## first code per length
  base: array[16, int]   ## symbol index base per length
  syms: seq[int]         ## symbols ordered by (length, index)

proc buildHuff*(lengths: openArray[int]): HuffTable =
  for L in lengths:
    if L < 0 or L > rarMaxCodeLen:
      raise newException(RarCodecError, "rar: bad huffman length")
    if L != 0:
      inc result.counts[L]
  # Kraft check: reject oversubscribed, allow incomplete.
  var left = 1 shl rarMaxCodeLen
  for L in 1 .. rarMaxCodeLen:
    left -= result.counts[L] * (1 shl (rarMaxCodeLen - L))
    if left < 0:
      raise newException(RarCodecError, "rar: oversubscribed huffman table")
  var code = 0
  var off = 0
  for L in 1 .. rarMaxCodeLen:
    result.first[L] = code
    result.base[L] = off
    off += result.counts[L]
    code = (code + result.counts[L]) shl 1
  result.syms = newSeq[int](off)
  var pos = result.base
  for sym, L in lengths:
    if L != 0:
      result.syms[pos[L]] = sym
      inc pos[L]

proc decodeSym*(t: HuffTable; br: var BitReader): int =
  var code = 0
  for L in 1 .. rarMaxCodeLen:
    code = (code shl 1) or int(br.readBits(1))
    if t.counts[L] > 0:
      let idx = code - t.first[L]
      if idx >= 0 and idx < t.counts[L]:
        return t.syms[t.base[L] + idx]
  raise newException(RarCodecError, "rar: invalid huffman code")

# ---------- table-length codec ----------

proc readLevelLengths(br: var BitReader): array[rarLevelSyms, int] =
  var pos = 0
  while pos < rarLevelSyms:
    let L = int(br.readBits(4))
    if L == 15:
      let n = int(br.readBits(4))
      if n == 0:
        result[pos] = 15
        inc pos
      else:
        for _ in 0 ..< n + 2:
          if pos >= rarLevelSyms:
            break
          result[pos] = 0
          inc pos
    else:
      result[pos] = L
      inc pos

proc decodeLengths(br: var BitReader; level: HuffTable;
    total: int): seq[int] =
  result = @[]
  var prev = -1
  while result.len < total:
    let s = decodeSym(level, br)
    if s < 16:
      result.add(s)
      prev = s
    elif s == 16:
      if prev < 0:
        raise newException(RarCodecError, "rar: repeat with no previous length")
      for _ in 0 ..< 3 + int(br.readBits(3)):
        result.add(prev)
    elif s == 17:
      if prev < 0:
        raise newException(RarCodecError, "rar: repeat with no previous length")
      for _ in 0 ..< 11 + int(br.readBits(7)):
        result.add(prev)
    elif s == 18:
      for _ in 0 ..< 3 + int(br.readBits(3)):
        result.add(0)
    elif s == 19:
      for _ in 0 ..< 11 + int(br.readBits(7)):
        result.add(0)
    else:
      raise newException(RarCodecError, "rar: bad level symbol")
  if result.len > total:
    raise newException(RarCodecError, "rar: length table overrun")
  result.setLen(total)

# ---------- slot codecs ----------

proc lengthExtraBits(slot: int): int =
  if slot < 8: 0 else: (slot shr 2) - 1

proc lengthFromSlot(slot: int; extra: uint64): uint64 =
  if slot < 8:
    result = slot.uint64 + 2
  else:
    let n = (slot shr 2) - 1
    result = (((4 or (slot and 3)) shl n).uint64 or extra) + 2

proc distBitCount(slot: int): int =
  if slot < 4: 0 else: (slot - 2) shr 1

proc distFromSlot(slot: int; nbits: int; extra: uint64): uint64 =
  if slot < 4:
    result = slot.uint64 + 1
  else:
    result = (((2 or (slot and 1)) shl nbits).uint64 or extra) + 1

proc lengthBonus(dist: uint64): uint64 =
  (if dist > rarBonusDist1: 1'u64 else: 0) +
  (if dist > rarBonusDist2: 1'u64 else: 0) +
  (if dist > rarBonusDist3: 1'u64 else: 0)

# ---------- filters ----------

type RarFilterKind = enum
  fkDelta, fkE8, fkE8E9, fkArm

type RarFilter = object
  start: uint64 ## file-relative region start
  len: uint64
  kind: RarFilterKind
  channels: int

proc readFilter(br: var BitReader; curPos: uint64): RarFilter =
  proc readU32(br: var BitReader): uint64 =
    let nbytes = int(br.readBits(2)) + 1
    for i in 0 ..< nbytes:
      result = result or (br.readBits(8) shl (i * 8))
  let off = readU32(br)
  let flen = readU32(br)
  let t = br.readBits(3)
  result.kind =
    case t
    of 0: fkDelta
    of 1: fkE8
    of 2: fkE8E9
    of 3: fkArm
    else: raise newException(RarCodecError, "rar: bad filter type")
  result.start = curPos + off
  result.len = flen
  if result.kind == fkDelta:
    result.channels = int(br.readBits(5)) + 1

proc applyDelta*(data: var string; start: int; len: int; channels: int) =
  ## Delta decode: input is channel-major (sequential read), output is
  ## deinterleaved. Decodes into a temp buffer first: naive in-place
  ## corrupts because later channels read bytes earlier channels wrote.
  if channels <= 0 or channels > 32:
    raise newException(RarCodecError, "rar: bad delta channels")
  var tmp = newString(len)
  var src = start
  for c in 0 ..< channels:
    var prev = 0
    var p = c
    while p < len:
      if src >= start + len:
        raise newException(RarCodecError, "rar: truncated delta")
      let v = (prev - ord(data[src])) and 0xFF
      inc src
      tmp[p] = chr(v)
      prev = v
      p += channels
  if src != start + len:
    raise newException(RarCodecError, "rar: bad delta length")
  for i in 0 ..< len:
    data[start + i] = tmp[i]

proc le32At(s: string; at: int): uint32 =
  ord(s[at]).uint32 or (ord(s[at + 1]).uint32 shl 8) or
    (ord(s[at + 2]).uint32 shl 16) or (ord(s[at + 3]).uint32 shl 24)

proc putLe32At(s: var string; at: int; v: uint32) =
  s[at] = chr(int(v and 0xFF))
  s[at + 1] = chr(int((v shr 8) and 0xFF))
  s[at + 2] = chr(int((v shr 16) and 0xFF))
  s[at + 3] = chr(int((v shr 24) and 0xFF))

proc applyE8*(data: var string; start: int; len: int; fileStart: uint64;
    e9: bool) =
  const fileSize = 0x1000000'u32
  var p = start
  let stop = start + len
  while p + 5 <= stop:
    let b = ord(data[p])
    if (if e9: (b and 0xFE) == 0xE8 else: b == 0xE8):
      let offset = uint32((fileStart + uint64(p - start) + 1) and
        (fileSize - 1))
      let a = le32At(data, p + 1)
      if a < fileSize:
        putLe32At(data, p + 1, a - offset)
      elif a > 0xFFFFFFFF'u32 - offset:
        putLe32At(data, p + 1, a + fileSize)
      p += 5
    else:
      inc p

proc applyArm*(data: var string; start: int; len: int; fileStart: uint64) =
  ## Fixed 4-byte stride from region offset 0 (the encoder must place
  ## the region start so instructions land aligned; there is no
  ## alignment search on decode). Offset arithmetic wraps at 32 bits
  ## like the reference decoder: identical for files under 4 GiB.
  var p = start
  let stop = start + len
  let base = uint32(fileStart and 0xFFFFFFFF'u64)
  while p + 4 <= stop:
    if ord(data[p + 3]) == 0xEB:
      let offset = (base + uint32(p - start)) shr 2
      var v = le32At(data, p) - offset
      v = (v and 0x00FFFFFF'u32) or 0xEB000000'u32
      putLe32At(data, p, v)
    p += 4

proc applyFilters(data: var string; filters: seq[RarFilter]) =
  for f in filters:
    let s = int(f.start)
    let e = s + int(f.len)
    if f.len > rarMaxFilterLen.uint64 or e > data.len or s < 0:
      raise newException(RarCodecError, "rar: filter range invalid")
    case f.kind
    of fkDelta: applyDelta(data, s, int(f.len), f.channels)
    of fkE8: applyE8(data, s, int(f.len), f.start, false)
    of fkE8E9: applyE8(data, s, int(f.len), f.start, true)
    of fkArm: applyArm(data, s, int(f.len), f.start)

# ---------- decoder state ----------

type UnpackState* = ref object
  ## Retained across a solid group (nil window = fresh). Per-call object.
  window*: seq[byte]
  dictSize*: int
  wpos*: int
  total*: uint64 ## bytes produced in current group
  reps*: array[4, uint64]
  lastLen*: uint64
  mainT*, distT*, alignT*, lenT*: HuffTable
  tablesOk*: bool
  alignMode*: bool
  algoVer*: int  ## 0 = Unpack50, 1 = Unpack70

proc resetUnpack*(st: UnpackState; dictSize, algoVer: int) =
  st.window = newSeq[byte](dictSize)
  st.dictSize = dictSize
  st.wpos = 0
  st.total = 0
  st.reps = [0'u64, 0, 0, 0]
  st.lastLen = 0
  st.tablesOk = false
  st.alignMode = false
  st.algoVer = algoVer

proc emitByte(st: UnpackState; output: var string; b: byte) =
  output.add(char(b))
  st.window[st.wpos] = b
  st.wpos += 1
  if st.wpos >= st.dictSize:
    st.wpos = 0
  inc st.total

proc emitMatch(st: UnpackState; output: var string; dist, length: uint64;
    outLimit: uint64) =
  if output.len.uint64 + length > outLimit:
    raise newException(RarCodecError, "rar: match exceeds output limit")
  for _ in 0 ..< length:
    var b: byte = 0
    if dist != 0 and dist <= st.dictSize.uint64 and dist <= st.total:
      # wpos - dist lies in (-dictSize, dictSize): one add normalizes.
      var idx = st.wpos - int(dist)
      if idx < 0:
        idx += st.dictSize
      b = st.window[idx]
    output.add(char(b))
    st.window[st.wpos] = b
    st.wpos += 1
    if st.wpos >= st.dictSize:
      st.wpos = 0
    inc st.total

proc decodeMember*(st: UnpackState; data: pointer; dataLen: int;
    outLimit: uint64; algoVer: int): string =
  ## Decode one file's compressed stream (STORE excluded by caller).
  ## Stops at the last-block marker or when `outLimit` bytes are out;
  ## raises on truncation or structural errors.
  let bytes = cast[ptr UncheckedArray[byte]](data)
  var pos = 0
  var filters: seq[RarFilter] = @[]
  let distSyms = if algoVer == 1: rarDistSyms70 else: rarDistSyms50
  while true:
    if pos + 2 > dataLen:
      raise newException(RarCodecError, "rar: truncated block header")
    let flags = bytes[pos]
    let checksum = bytes[pos + 1]
    let nb =
      case (flags shr 3) and 3
      of 0: 1
      of 1: 2
      of 2: 3
      else: raise newException(RarCodecError, "rar: bad block size length")
    if pos + 2 + nb > dataLen:
      raise newException(RarCodecError, "rar: truncated block header")
    var acc = checksum xor flags
    var payloadSize = 0
    for i in 0 ..< nb:
      let b = bytes[pos + 2 + i]
      acc = acc xor b
      payloadSize = payloadSize or (int(b) shl (i * 8))
    if acc != 0x5A:
      raise newException(RarCodecError, "rar: block checksum mismatch")
    let isLast = (flags and 0x40) != 0
    let hasTables = (flags and 0x80) != 0
    let finalBits = min(int(flags and 7) + 1, 8)
    let payloadBits =
      if payloadSize == 0: 0
      else: (payloadSize - 1) * 8 + finalBits
    if pos + 2 + nb + payloadSize > dataLen:
      raise newException(RarCodecError, "rar: truncated block payload")
    var br = initBitReader(cast[pointer](addr bytes[pos + 2 + nb]),
      payloadSize)
    if hasTables:
      let lvl = readLevelLengths(br)
      let levelT = buildHuff(lvl)
      let totalLens = rarMainSyms + distSyms + rarAlignSyms + rarLenSyms
      let lens = decodeLengths(br, levelT, totalLens)
      var o = 0
      st.mainT = buildHuff(lens[o ..< o + rarMainSyms]); o += rarMainSyms
      st.distT = buildHuff(lens[o ..< o + distSyms]); o += distSyms
      let alens = lens[o ..< o + rarAlignSyms]; o += rarAlignSyms
      st.alignT = buildHuff(alens)
      st.lenT = buildHuff(lens[o ..< o + rarLenSyms])
      st.alignMode = false
      for L in alens:
        if L != 4:
          st.alignMode = true
          break
      st.tablesOk = true
      st.algoVer = algoVer
    elif not st.tablesOk:
      raise newException(RarCodecError, "rar: block reuses missing tables")
    while br.read < payloadBits and result.len.uint64 < outLimit:
      let s = decodeSym(st.mainT, br)
      if s < 256:
        if result.len.uint64 >= outLimit:
          raise newException(RarCodecError, "rar: exceeds output limit")
        st.emitByte(result, byte(s))
      elif s == 256:
        if filters.len >= rarMaxFilters:
          raise newException(RarCodecError, "rar: too many filters")
        let f = readFilter(br, result.len.uint64)
        if f.len > rarMaxFilterLen.uint64:
          raise newException(RarCodecError, "rar: filter too large")
        filters.add(f)
      elif s == 257:
        if st.lastLen != 0:
          st.emitMatch(result, st.reps[0], st.lastLen, outLimit)
      elif s <= 261:
        let repIdx = s - 258
        let d = st.reps[repIdx]
        let lslot = decodeSym(st.lenT, br)
        let lextra = br.readBits(lengthExtraBits(lslot))
        let length = lengthFromSlot(lslot, lextra)
        if d == 0:
          # Uninitialized rep: zero-fill per format rule.
          if result.len.uint64 + length > outLimit:
            raise newException(RarCodecError, "rar: exceeds output limit")
          for _ in 0 ..< length:
            st.emitByte(result, 0)
        else:
          for i in countdown(repIdx, 1):
            st.reps[i] = st.reps[i - 1]
          st.reps[0] = d
          st.lastLen = length
          st.emitMatch(result, d, length, outLimit)
      else:
        let lslot = s - 262
        let lextra = br.readBits(lengthExtraBits(lslot))
        var length = lengthFromSlot(lslot, lextra)
        let dslot = decodeSym(st.distT, br)
        if (algoVer == 0 and dslot >= rarDistSyms50) or
            dslot >= rarDistSyms70:
          raise newException(RarCodecError, "rar: bad distance slot")
        let nbits = distBitCount(dslot)
        if algoVer == 0 and nbits > 31:
          raise newException(RarCodecError, "rar: bad distance slot")
        var dextra: uint64
        if nbits >= 4 and st.alignMode:
          let high = br.readBitsWide(nbits - 4)
          let low = uint64(decodeSym(st.alignT, br))
          dextra = (high shl 4) or low
        else:
          dextra = br.readBitsWide(nbits)
        let dist = distFromSlot(dslot, nbits, dextra)
        length += lengthBonus(dist)
        for i in countdown(3, 1):
          st.reps[i] = st.reps[i - 1]
        st.reps[0] = dist
        st.lastLen = length
        st.emitMatch(result, dist, length, outLimit)
    pos += 2 + nb + payloadSize
    if isLast or result.len.uint64 >= outLimit:
      break
  applyFilters(result, filters)
