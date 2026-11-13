## LZMA range encoder + greedy match finder for the 7z LZMA2-solid writer.
##
## Clean-room implementation mirroring `szlzma.nim` (same probability
## models, state machine and bit-tree layouts, reversed). Emits literals
## and plain matches only (never rep/short-rep packets); the decoder
## handles that subset, and encoder/decoder stay in sync by applying
## identical state transitions and rep-ring rotation. Match finder is a
## 4-byte hash chain, depth-limited (fast level, v1).
##
## Raises ArchiveError with "7z: ..." messages.

import ../types
import ./szlzma

type LzmaEncError* = object of ArchiveError

const encProbInit = 1024'u16

type RangeEnc = object
  rng: uint32
  low: uint64
  cache: int
  cacheSize: int
  enc: string

proc encInit(): RangeEnc =
  RangeEnc(rng: 0xFFFFFFFF'u32, low: 0, cache: 0, cacheSize: 1,
    enc: "")

proc encShiftLow(rc: var RangeEnc) =
  let low32 = rc.low.uint32
  let high = int(rc.low shr 32)
  # NOTE: the shift wraps at 32 bits (UInt32 arithmetic); the high part
  # feeds the carry path only, it is not preserved into low.
  rc.low = (low32 shl 8).uint64
  if low32 < 0xFF000000'u32 or high != 0:
    var temp = rc.cache
    while true:
      rc.enc.add(chr((temp + high) and 0xFF))
      temp = 0xFF
      dec rc.cacheSize
      if rc.cacheSize == 0:
        break
    rc.cache = int(low32 shr 24)
  inc rc.cacheSize

proc encNormalize(rc: var RangeEnc) =
  if rc.rng < 0x01000000'u32:
    rc.rng = rc.rng shl 8
    encShiftLow(rc)

proc encBit(rc: var RangeEnc; prob: var uint16; bit: int) =
  let bound = (rc.rng shr 11) * prob.uint32
  if bit == 0:
    rc.rng = bound
    prob = prob + ((2048'u16 - prob) shr 5)
  else:
    rc.low = rc.low + bound.uint64
    rc.rng = rc.rng - bound
    prob = prob - (prob shr 5)
  encNormalize(rc)

proc encBitTree(rc: var RangeEnc; probs: var seq[uint16];
    numBits, base, value: int) =
  var node = 1
  for i in countdown(numBits - 1, 0):
    let b = (value shr i) and 1
    rc.encBit(probs[base + node], b)
    node = (node shl 1) or b

proc encReverse(rc: var RangeEnc; probs: var seq[uint16];
    numBits, base, value: int) =
  var node = 1
  for i in 0 ..< numBits:
    let b = (value shr i) and 1
    rc.encBit(probs[base + node], b)
    node = (node shl 1) or b

proc encDirect(rc: var RangeEnc; value, numBits: int) =
  for i in countdown(numBits - 1, 0):
    rc.rng = rc.rng shr 1
    if ((value shr i) and 1) != 0:
      rc.low = rc.low + rc.rng.uint64
    encNormalize(rc)

proc encFlush(rc: var RangeEnc) =
  for _ in 0 ..< 5:
    encShiftLow(rc)

const encIdxStart = [0, 2, 4, 8, 12, 20, 28, 44, 60, 92]

type LzmaEncoder* = object
  lc*, lp*, pb*: int
  posMask*, litPosMask*: int
  dictSize*: int
  state*: int
  reps*: array[4, int]
  isMatch*: seq[uint16]
  isRep*: seq[uint16]
  isRepG0*: seq[uint16]
  isRepG1*: seq[uint16]
  isRepG2*: seq[uint16]
  isRep0Long*: seq[uint16]
  distSlot*: seq[uint16]
  distSpecial*: seq[uint16]
  distAlign*: seq[uint16]
  lenChoice*: seq[uint16]
  lenLow*: seq[uint16]
  lenMid*: seq[uint16]
  lenHigh*: seq[uint16]
  litProbs*: seq[uint16]

proc initEncProbs(n: int): seq[uint16] =
  result = newSeq[uint16](n)
  for i in 0 ..< n:
    result[i] = encProbInit

proc lzmaEncoderInit*(lc, lp, pb, dictSize: int): LzmaEncoder =
  result.lc = lc
  result.lp = lp
  result.pb = pb
  result.posMask = if pb == 0: 0 else: (1 shl pb) - 1
  result.litPosMask = if lp == 0: 0 else: (1 shl lp) - 1
  result.dictSize = dictSize
  result.state = 0
  result.reps = [0, 0, 0, 0]
  result.isMatch = initEncProbs(12 * 16)
  result.isRep = initEncProbs(12)
  result.isRepG0 = initEncProbs(12)
  result.isRepG1 = initEncProbs(12)
  result.isRepG2 = initEncProbs(12)
  result.isRep0Long = initEncProbs(12 * 16)
  result.distSlot = initEncProbs(4 * 64)
  result.distSpecial = initEncProbs(124)
  result.distAlign = initEncProbs(16)
  result.lenChoice = initEncProbs(2)
  result.lenLow = initEncProbs(16 * 8)
  result.lenMid = initEncProbs(16 * 8)
  result.lenHigh = initEncProbs(256)
  result.litProbs = initEncProbs((1 shl (lc + lp)) * 768)

proc encLen(rc: var RangeEnc; enc: var LzmaEncoder; posState,
    length: int) =
  let m = length - 2
  if m < 8:
    rc.encBit(enc.lenChoice[0], 0)
    rc.encBitTree(enc.lenLow, 3, posState * 8, m)
  elif m < 16:
    rc.encBit(enc.lenChoice[0], 1)
    rc.encBit(enc.lenChoice[1], 0)
    rc.encBitTree(enc.lenMid, 3, posState * 8, m - 8)
  else:
    rc.encBit(enc.lenChoice[0], 1)
    rc.encBit(enc.lenChoice[1], 1)
    rc.encBitTree(enc.lenHigh, 8, 0, m - 16)

proc distSlotFor(dist: int): int =
  if dist < 4:
    return dist
  var s = 4
  while s < 63:
    let lim = (s shr 1) - 1
    let base = (2 or (s and 1)) shl lim
    let lim2 = ((s + 1) shr 1) - 1
    let nextBase = (2 or ((s + 1) and 1)) shl lim2
    if dist >= base and dist < nextBase:
      return s
    inc s
  63

proc encDist(rc: var RangeEnc; enc: var LzmaEncoder; length,
    dist: int) =
  let lenState = if length < 6: length - 2 else: 3
  let slot = distSlotFor(dist)
  rc.encBitTree(enc.distSlot, 6, lenState * 64, slot)
  if slot < 4:
    return
  let limit = (slot shr 1) - 1
  let base = (2 or (slot and 1)) shl limit
  let extra = dist - base
  if slot < 14:
    rc.encReverse(enc.distSpecial, limit, encIdxStart[slot - 4], extra)
  else:
    rc.encDirect(extra shr 4, limit - 4)
    rc.encReverse(enc.distAlign, 4, 0, extra and 0xF)

proc encLiteral(rc: var RangeEnc; enc: var LzmaEncoder; pos: int;
    prevByte, matchByte, symbol: int; useMatch: bool) =
  var subIdx = 0
  if enc.lc != 0:
    subIdx = ((pos and enc.litPosMask) shl enc.lc) +
      (prevByte shr (8 - enc.lc))
  else:
    subIdx = pos and enc.litPosMask
  let litBase = subIdx * 768
  var sym = 1
  if not useMatch:
    var cur = symbol
    for _ in 0 ..< 8:
      let b = (cur shr 7) and 1
      cur = (cur shl 1) and 0xFF
      rc.encBit(enc.litProbs[litBase + sym], b)
      sym = (sym shl 1) or b
  else:
    var mb = matchByte
    var offset = 0x100
    var cur = symbol
    for _ in 0 ..< 8:
      mb = mb shl 1
      let matchBit = mb and offset
      let idx = offset + matchBit + sym
      let b = (cur shr 7) and 1
      cur = (cur shl 1) and 0x1FF
      rc.encBit(enc.litProbs[litBase + idx], b)
      if ((matchBit != 0) != (b != 0)):
        offset = 0
      sym = (sym shl 1) or b

# ---------- greedy match finder + packet driver ----------

proc hash4(data: string; pos: int): int {.inline.} =
  let b0 = ord(data[pos]).uint32
  let b1 = ord(data[pos + 1]).uint32
  let b2 = ord(data[pos + 2]).uint32
  let b3 = ord(data[pos + 3]).uint32
  int(((b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) *
    0x9E3779B1'u32) shr 16)

proc matchLenAt(data: string; a, b, maxLen: int): int =
  var n = 0
  while n < maxLen and a + n < data.len and b + n < data.len and
      data[a + n] == data[b + n]:
    inc n
  n

proc lzmaEncodeChunk*(enc: var LzmaEncoder; rc: var RangeEnc;
    data: string; chunkStart, chunkEnd: int) =
  ## Encode data[chunkStart ..< chunkEnd] with persistent model state.
  ## History (match sources) spans the whole `data` prefix; matches are
  ## clipped to the chunk end and to the dictionary window.
  let n = data.len
  var heads = newSeq[int](1 shl 16)
  for i in 0 ..< heads.len:
    heads[i] = -1
  var prev = newSeq[int](n)
  for i in 0 ..< n:
    prev[i] = -1
  # Seed table with positions before the chunk (history only).
  var p = 0
  while p + 4 <= chunkStart:
    let h = hash4(data, p)
    prev[p] = heads[h]
    heads[h] = p
    inc p
  var pos = chunkStart
  while pos < chunkEnd:
    let posState = if enc.posMask == 0: 0 else: pos and enc.posMask
    var bestLen = 0
    var bestDist = 0
    if pos + 4 <= n:
      let h = hash4(data, pos)
      var cand = heads[h]
      var steps = 0
      let maxDist = min(pos - 0, enc.dictSize)
      while cand >= 0 and steps < 64:
        let dist = pos - cand - 1
        if dist >= maxDist:
          break
        if dist < 0:
          cand = prev[cand]
          inc steps
          continue
        var cap = 273
        if pos + cap > chunkEnd:
          cap = chunkEnd - pos
        if cap >= 2:
          let ml = matchLenAt(data, cand, pos, cap)
          if ml > bestLen:
            bestLen = ml
            bestDist = dist
            if ml >= 273 or (ml >= 64 and steps >= 8):
              break
        cand = prev[cand]
        inc steps
      prev[pos] = heads[h]
      heads[h] = pos
    if bestLen >= 3:
      # match packet
      rc.encBit(enc.isMatch[enc.state * 16 + posState], 1)
      rc.encBit(enc.isRep[enc.state], 0)
      encLen(rc, enc, posState, bestLen)
      encDist(rc, enc, bestLen, bestDist)
      enc.reps[3] = enc.reps[2]
      enc.reps[2] = enc.reps[1]
      enc.reps[1] = enc.reps[0]
      enc.reps[0] = bestDist
      if enc.state < 7: enc.state = 7 else: enc.state = 10
      # index skipped positions into the table for future matches
      var k = pos + 1
      while k + 4 <= min(pos + bestLen, n) and k < chunkEnd:
        let h = hash4(data, k)
        prev[k] = heads[h]
        heads[h] = k
        inc k
      pos += bestLen
    else:
      # literal packet
      rc.encBit(enc.isMatch[enc.state * 16 + posState], 0)
      let prevByte = if pos > 0: ord(data[pos - 1]) else: 0
      let useMatch = enc.state >= 7
      var matchByte = 0
      if useMatch:
        if pos > enc.reps[0]:
          matchByte = ord(data[pos - enc.reps[0] - 1])
        else:
          # no valid rep yet: fall back to plain literal path
          rc.encLiteral(enc, pos, prevByte, 0, ord(data[pos]), false)
          if enc.state < 4: enc.state = 0
          elif enc.state < 10: enc.state = enc.state - 3
          else: enc.state = enc.state - 6
          inc pos
          continue
      rc.encLiteral(enc, pos, prevByte, matchByte, ord(data[pos]),
        useMatch)
      if enc.state < 4: enc.state = 0
      elif enc.state < 10: enc.state = enc.state - 3
      else: enc.state = enc.state - 6
      inc pos

proc lzma2EncodeSolid*(data: string; dictProp: byte;
    maxDict: int): string =
  ## LZMA2 framing of one solid block. First chunk carries reset-dict +
  ## new props (0x5D: lc=3, lp=0, pb=2); following chunks are no-reset.
  ## LZMA chunks are capped at 32KiB unpacked so the payload always fits
  ## the 16-bit packed-size field (worst case ~1.5x input + 5 bytes).
  ## Empty input yields a single end marker.
  if maxDict != 0 and data.len > 4 * 1024 * 1024 * 1024:
    raise newException(LzmaEncError, "7z: solid block exceeds cap")
  result = ""
  if data.len == 0:
    result.add(chr(0))
    return
  let dictSize = dictSizeFromLzma2Prop(dictProp)
  if maxDict != 0 and dictSize > maxDict:
    raise newException(LzmaEncError, "7z: lzma dict exceeds cap")
  var enc = lzmaEncoderInit(3, 0, 2, dictSize)
  var pos = 0
  var first = true
  while pos < data.len:
    var want = data.len - pos
    if want > 32768:
      want = 32768
    var rc = encInit()
    lzmaEncodeChunk(enc, rc, data, pos, pos + want)
    encFlush(rc)
    let payload = rc.enc
    if payload.len < 5 or ord(payload[0]) != 0:
      raise newException(LzmaEncError, "7z: lzma range flush fault")
    if payload.len - 5 + 1 > 65536:
      raise newException(LzmaEncError, "7z: lzma chunk too large")
    let up = want - 1
    let pp = payload.len - 1
    if first:
      let ctrl = 0xE0 or ((up shr 16) and 0x1F)
      result.add(chr(ctrl))
      result.add(chr((up shr 8) and 0xFF))
      result.add(chr(up and 0xFF))
      result.add(chr((pp shr 8) and 0xFF))
      result.add(chr(pp and 0xFF))
      result.add(chr(0x5D))
    else:
      let ctrl = 0x80 or ((up shr 16) and 0x1F)
      result.add(chr(ctrl))
      result.add(chr((up shr 8) and 0xFF))
      result.add(chr(up and 0xFF))
      result.add(chr((pp shr 8) and 0xFF))
      result.add(chr(pp and 0xFF))
    result.add(payload)
    pos += want
    first = false
  result.add(chr(0))
  # dictProp selects the folder dictionary (writer passes 0x10 = 1MiB).
