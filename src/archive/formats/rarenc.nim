## RAR5/7.0 Unpack50/70 LZ+Huffman ENCODER (methods m1..m5).
##
## Clean-room implementation from the format specification: priced
## greedy parsing with optional 1-byte lazy lookahead, hash-chain match
## finder, optimal Huffman with Kraft repair (max 15 bits, §3.1 edge
## shapes), level-table RLE packing, and byte-aligned block framing.
## Filter-free streams (always valid; filters are pure ratio), fixed
## 64KB blocks with fresh tables each, non-solid groups.
##
## No globals; all state is per-call. Memory is bounded by the input
## plus the match-finder tables (hash chains are chunked so the `prev`
## array never exceeds the chunk). Empty input is the caller's STORE
## case: no valid compressed stream exists for zero bytes.

import std/bitops
import ../types
import ./rarcodec

const
  rarEncDict* = 1 shl 20
    ## Fixed dictionary (1 MiB, power 3). Keeps decode windows modest;
    ## larger dictionaries are a later tuning knob, not a format need.
  rarEncBlock* = 64 * 1024
    ## Input bytes per block (spec sweet spot 64-256 KB).
  rarEncMaxMatch* = 4100
    ## Longest representable match (slot 43 + length bonus 3).
  rarEncChunk* = 8 shl 20
    ## Match-finder chunk: hash chains never cross a chunk boundary,
    ## so `prev` stays bounded. Ratio-only effect, always valid.

type RarEncError* = object of ArchiveError

# ---------- MSB-first bit writer ----------

type BitWriter = object
  buf: seq[byte]
  acc: uint64
  nbits: int
  total: int

proc putBits(w: var BitWriter; v: uint64; n: int) =
  doAssert n >= 0 and n <= 32
  let mask =
    if n == 0: 0'u64
    elif n == 32: 0xFFFFFFFF'u64
    else: (1'u64 shl n) - 1
  w.acc = (w.acc shl n) or (v and mask)
  w.nbits += n
  w.total += n
  while w.nbits >= 8:
    w.nbits -= 8
    w.buf.add(byte((w.acc shr w.nbits) and 0xFF))

proc flushByte(w: var BitWriter) =
  ## Pad with zero bits to the next byte boundary.
  if w.nbits > 0:
    w.buf.add(byte((w.acc shl (8 - w.nbits)) and 0xFF))
    w.acc = 0
    w.nbits = 0

# ---------- length-limited Huffman (optimal + Kraft repair) ----------

proc huffmanLengths*(freqs: openArray[int]; maxLen = 15): seq[int] =
  ## Canonical lengths from frequencies. Optimal tree, then repair any
  ## Kraft overshoot by lengthening the rarest symbols first (each step
  ## strictly reduces the Kraft sum; terminates no later than all-15,
  ## which always fits). §3.1 edge shapes for 0/1 used symbols.
  let n = freqs.len
  result = newSeq[int](n)
  var used: seq[int] = @[]
  for i, f in freqs:
    if f > 0:
      used.add(i)
  if used.len == 0:
    if n > 1:
      result[0] = 1
      result[1] = 1
    elif n == 1:
      result[0] = 1
    return
  if used.len == 1:
    let s = used[0]
    result[s] = 1
    let d = if s == 0: 1 else: 0
    if d < n:
      result[d] = 1
    return
  # Optimal tree via repeated pairing (O(n^2), n <= 446).
  type Node = object
    weight: int64
    sym: int     # >= 0 leaf, -1 internal
    left, right: int
  var nodes: seq[Node] = @[]
  var active: seq[int] = @[]
  for s in used:
    nodes.add(Node(weight: freqs[s].int64, sym: s, left: -1, right: -1))
    active.add(nodes.len - 1)
  while active.len > 1:
    var b1 = 0
    for i in 1 ..< active.len:
      if (nodes[active[i]].weight, active[i]) < (nodes[active[b1]].weight, active[b1]):
        b1 = i
    let n1 = active[b1]
    active.del(b1)
    var b2 = 0
    for i in 1 ..< active.len:
      if (nodes[active[i]].weight, active[i]) < (nodes[active[b2]].weight, active[b2]):
        b2 = i
    let n2 = active[b2]
    active.del(b2)
    nodes.add(Node(weight: nodes[n1].weight + nodes[n2].weight, sym: -1,
      left: n1, right: n2))
    active.add(nodes.len - 1)
  let root = active[0]
  var depth = newSeq[int](nodes.len)
  var stack = @[root]
  depth[root] = 0
  var order: seq[int] = @[]
  while stack.len > 0:
    let nd = stack.pop()
    order.add(nd)
    if nodes[nd].left >= 0:
      depth[nodes[nd].left] = depth[nd] + 1
      depth[nodes[nd].right] = depth[nd] + 1
      stack.add(nodes[nd].left)
      stack.add(nodes[nd].right)
  for s in used:
    for ni in 0 ..< nodes.len:
      if nodes[ni].sym == s:
        result[s] = depth[ni]
        break
  # Kraft repair: lengthen rarest first until the sum fits.
  const Full = 1 shl 15
  while true:
    var sum = 0
    var worst = -1
    for s in used:
      if result[s] > maxLen:
        # Should not happen from optimal+capped path; clamp defensively.
        result[s] = maxLen
      sum += Full shr result[s]
    if sum <= Full:
      break
    var best = -1
    for s in used:
      if result[s] < maxLen and (best < 0 or (freqs[s], -result[s]) <
          (freqs[best], -result[best])):
        best = s
    if best < 0:
      raise newException(RarEncError, "rar: huffman repair stuck")
    inc result[best]

proc assignCodes*(lengths: openArray[int]; maxLen = 15): seq[tuple[code, len: int]] =
  ## DEFLATE-rule canonical codes (§4), indexed by symbol.
  result = newSeq[tuple[code, len: int]](lengths.len)
  var counts = newSeq[int](maxLen + 1)
  for L in lengths:
    if L < 0 or L > maxLen:
      raise newException(RarEncError, "rar: bad code length")
    if L != 0:
      inc counts[L]
  var code = 0
  var first = newSeq[int](maxLen + 1)
  var next = newSeq[int](maxLen + 1)
  for L in 1 .. maxLen:
    first[L] = code
    next[L] = code
    code = (code + counts[L]) shl 1
  for sym, L in lengths:
    if L != 0:
      result[sym] = (next[L], L)
      inc next[L]

# ---------- slot encoders (§11.11.4-5, inverse of the decode side) ----------

proc floorLog2(x: uint64): int =
  doAssert x > 0
  63 - countLeadingZeroBits(x)

proc encodeLenSlot(length: uint64): tuple[slot: int; extraBits: int; extra: uint64] =
  ## `length` is the encoder length (bonus already subtracted for new
  ## matches; raw for repeat matches). Minimum length 2.
  doAssert length >= 2
  let e = length - 2
  if e < 8:
    (e.int, 0, 0'u64)
  else:
    let nb = floorLog2(e) - 2
    let slot = (nb + 1) * 4 + int((e shr nb) and 3)
    (slot, nb, e and ((1'u64 shl nb) - 1))

proc encodeDistSlot(dist: uint64): tuple[slot: int; extraBits: int; extra: uint64] =
  doAssert dist >= 1
  let e = dist - 1
  if e < 4:
    (e.int, 0, 0'u64)
  else:
    let nb = floorLog2(e) - 1
    let slot = (nb + 1) * 2 + int((e shr nb) and 1)
    let base = ((2 or (slot and 1)) shl nb).uint64
    (slot, nb, e - base)

proc lengthBonusEnc(dist: uint64): uint64 =
  (if dist > 0x100'u64: 1'u64 else: 0) +
  (if dist > 0x2000'u64: 1'u64 else: 0) +
  (if dist > 0x40000'u64: 1'u64 else: 0)

# ---------- hash-chain match finder ----------

const HashBits = 16

type Matcher = object
  head: seq[int]
  prev: seq[int]
  base: int ## absolute position of prev[0]
  maxChain: int
  dictSize: int

proc initMatcher(maxChain, dictSize: int): Matcher =
  Matcher(head: newSeq[int](1 shl HashBits), prev: @[], base: -1,
    maxChain: maxChain, dictSize: dictSize)

proc hash4(p: ptr UncheckedArray[byte]): int =
  let v = p[0].uint32 or (p[1].uint32 shl 8) or (p[2].uint32 shl 16) or
    (p[3].uint32 shl 24)
  int((v * 2654435761'u32) shr (32 - HashBits))

proc startChunk(m: var Matcher; base, len: int) =
  ## (Re)build the chain table for [base, base+len). Chains never cross
  ## a chunk: ratio-only effect, always valid output.
  m.base = base
  m.prev = newSeq[int](len)
  for i in 0 ..< len:
    m.prev[i] = -1
  for i in 0 ..< m.head.len:
    m.head[i] = -1

proc insertPos(m: var Matcher; data: ptr UncheckedArray[byte]; dataLen,
    pos: int) =
  if pos < m.base or pos + 4 > dataLen:
    return
  let h = hash4(cast[ptr UncheckedArray[byte]](addr data[pos]))
  m.prev[pos - m.base] = m.head[h]
  m.head[h] = pos

proc bestAt(m: Matcher; data: ptr UncheckedArray[byte]; dataLen, pos: int;
    maxLen: int): tuple[len: int; dist: int] =
  result = (0, 0)
  if pos + 4 > dataLen:
    return
  let h = hash4(cast[ptr UncheckedArray[byte]](addr data[pos]))
  var chain = m.head[h]
  var steps = 0
  let lo = max(m.base, pos - m.dictSize)
  while chain >= lo and steps < m.maxChain:
    if chain < pos:
      var ln = 0
      let lim = min(maxLen, dataLen - pos)
      while ln < lim and data[chain + ln] == data[pos + ln]:
        inc ln
      if ln >= 2 and ln > result.len:
        result = (ln, pos - chain)
        if ln >= maxLen:
          break
    let nxt =
      if chain - m.base >= 0 and chain - m.base < m.prev.len:
        m.prev[chain - m.base]
      else: -1
    chain = nxt
    inc steps

# ---------- level-table RLE packing (§5.3) ----------

proc packLengths(lens: openArray[int]; outSyms: var seq[int];
    outExtra: var seq[tuple[bits, val: int]]) =
  var i = 0
  let n = lens.len
  while i < n:
    let v = lens[i]
    var run = 1
    while i + run < n and lens[i + run] == v:
      inc run
    if v == 0:
      var left = run
      while left > 0:
        if left < 3:
          outSyms.add(0)
          outExtra.add((0, 0))
          dec left
        elif left <= 10:
          outSyms.add(18)
          outExtra.add((3, left - 3))
          left = 0
        else:
          let take = min(left, 138)
          outSyms.add(19)
          outExtra.add((7, take - 11))
          left -= take
    else:
      outSyms.add(v)
      outExtra.add((0, 0))
      var left = run - 1
      while left > 0:
        if left < 3:
          for _ in 0 ..< left:
            outSyms.add(v)
            outExtra.add((0, 0))
          left = 0
        elif left <= 10:
          outSyms.add(16)
          outExtra.add((3, left - 3))
          left = 0
        else:
          let take = min(left, 138)
          outSyms.add(17)
          outExtra.add((7, take - 11))
          left -= take
    i += run

# ---------- block encoder ----------

type
  TokenKind = enum
    tkLit, tkRep, tkNew, tkLast, tkFilter
  RarFilterSpec* = object
    ## Encoder-side filter covering [start, start+len) of the file.
    start*: int
    len*: int
    kind*: int ## 0=DELTA, 1=E8, 2=E8E9, 3=ARM
    channels*: int ## DELTA only, 1..32
  Token = object
    case kind: TokenKind
    of tkLit:
      lit: int
    of tkRep:
      repIdx: int
      repSlot: int
      repExtraBits: int
      repExtra: uint64
    of tkNew:
      newSlot: int
      newExtraBits: int
      newExtra: uint64
      newDistSlot: int
      newDistBits: int
      newDistExtra: uint64
    of tkLast:
      discard
    of tkFilter:
      filtOff: uint64
      filtLen: uint64
      filtKind: int
      filtChannels: int

# ---------- forward filter transforms (encoder side) ----------

proc fwdDelta*(buf: string; channels: int): string =
  ## Forward DELTA: deinterleave channels, byte-to-byte deltas packed
  ## sequentially. Inverse of applyDelta in rarcodec.
  if channels <= 0 or channels > 32:
    raise newException(RarEncError, "rar: bad delta channels")
  let n = buf.len
  result = newString(n)
  var sp = 0
  for c in 0 ..< channels:
    var prev = 0
    var i = c
    while i < n:
      result[sp] = chr((prev - ord(buf[i])) and 0xFF)
      prev = ord(buf[i])
      inc sp
      i += channels

proc fwdE8Impl(buf: string; fileOff: uint64; e9: bool): string =
  const FS = 0x1000000'u32
  result = buf
  var pos = 0
  while pos + 5 <= result.len:
    let b = ord(result[pos])
    if (if e9: (b and 0xFE) == 0xE8 else: b == 0xE8):
      let disp = uint32(ord(result[pos+1])) or
        (uint32(ord(result[pos+2])) shl 8) or
        (uint32(ord(result[pos+3])) shl 16) or
        (uint32(ord(result[pos+4])) shl 24)
      let off = uint32((fileOff + uint64(pos) + 1) and (FS - 1))
      let a = disp + off
      if a < FS:
        let v = a
        result[pos+1] = chr(int(v and 0xFF))
        result[pos+2] = chr(int((v shr 8) and 0xFF))
        result[pos+3] = chr(int((v shr 16) and 0xFF))
        result[pos+4] = chr(int((v shr 24) and 0xFF))
      else:
        let bb = disp - FS
        if bb > 0xFFFFFFFF'u32 - off:
          let v = bb
          result[pos+1] = chr(int(v and 0xFF))
          result[pos+2] = chr(int((v shr 8) and 0xFF))
          result[pos+3] = chr(int((v shr 16) and 0xFF))
          result[pos+4] = chr(int((v shr 24) and 0xFF))
      pos += 5
    else:
      inc pos

proc fwdE8*(buf: string; fileOff: uint64): string =
  fwdE8Impl(buf, fileOff, false)

proc fwdE8E9*(buf: string; fileOff: uint64): string =
  fwdE8Impl(buf, fileOff, true)

proc fwdArm*(buf: string; fileOff: uint64): string =
  result = buf
  var pos = 0
  while pos + 4 <= result.len:
    if ord(result[pos+3]) == 0xEB:
      let insn = uint32(ord(result[pos])) or
        (uint32(ord(result[pos+1])) shl 8) or
        (uint32(ord(result[pos+2])) shl 16) or
        (uint32(ord(result[pos+3])) shl 24)
      let off = (pos.uint64 + fileOff) shr 2
      let low24 = (insn and 0x00FFFFFF'u32) + uint32(off and 0xFFFFFF'u64)
      let nv = (low24 and 0x00FFFFFF'u32) or 0xEB000000'u32
      result[pos] = chr(int(nv and 0xFF))
      result[pos+1] = chr(int((nv shr 8) and 0xFF))
      result[pos+2] = chr(int((nv shr 16) and 0xFF))
      result[pos+3] = chr(int((nv shr 24) and 0xFF))
    pos += 4

proc putReadU32(w: var BitWriter; v: uint64) =
  ## Filter-local ReadUInt32: 2 bits for byte count (1-4) + LE bytes.
  let nbytes =
    if v <= 0xFF: 1
    elif v <= 0xFFFF: 2
    elif v <= 0xFFFFFF: 3
    else: 4
  w.putBits(uint64(nbytes - 1), 2)
  for i in 0 ..< nbytes:
    w.putBits((v shr (8*i)) and 0xFF, 8)

proc putBitsWide(w: var BitWriter; v: uint64; n: int) =
  ## Emit up to 64 raw bits (for Unpack70 large distances, up to 38).
  var left = n
  var shift = 0
  # Emit low chunks first? No: MSB-first, so emit high chunks first.
  # Split into 16-bit pieces from the top.
  while left > 0:
    let take = min(left, 16)
    let sh = left - take
    w.putBits((v shr sh) and ((if take == 64: 0xFFFFFFFFFFFFFFFF'u64
      elif take == 32: 0xFFFFFFFF'u64 else: (1'u64 shl take) - 1)), take)
    left -= take

proc tokenizeBlock(data: ptr UncheckedArray[byte]; dataLen, blk: int;
    m: var Matcher; useLazy: bool; litCost: int;
    mainLens, lenLens, distLens: seq[int];
    reps: var array[4, int]; lastLen: var int;
    distSyms = rarDistSyms50): tuple[toks: seq[Token],
      freqMain, freqLen, freqDist: seq[int]] =
  ## Priced greedy (+optional lazy) parse over [blk, blkEnd). `reps` and
  ## `lastLen` persist across blocks of a file exactly like the decoder
  ## carries them. Costs come from the previous block's code lengths
  ## (adaptive); the first block uses static estimates from the caller.
  ## `distSyms` selects the Unpack50 (64) vs Unpack70 (80) distance
  ## alphabet; the slot codec itself is unchanged.
  var freqMain = newSeq[int](rarMainSyms)
  var freqLen = newSeq[int](rarLenSyms)
  var freqDist = newSeq[int](distSyms)
  var toks: seq[Token] = @[]
  let blkEnd = min(dataLen, blk + rarEncBlock)
  var pos = blk
  # code-length lookup with fallback estimates for missing tables
  proc mainLen(sym: int): int =
    if sym < mainLens.len and mainLens[sym] != 0: mainLens[sym] else: litCost
  proc lenLen(sym: int): int =
    if sym < lenLens.len and lenLens[sym] != 0: lenLens[sym] else: 6
  proc distLen(sym: int): int =
    if sym < distLens.len and distLens[sym] != 0: distLens[sym] else: 8
  while pos < blkEnd:
    var (mlen, mdist) = m.bestAt(data, dataLen, pos, rarEncMaxMatch)
    # Tile input exactly: a block's tokens must cover precisely its
    # input range, or output overshoots (decoder enforces the limit).
    mlen = min(mlen, blkEnd - pos)
    # Symbol 257 fast path: cheapest token in the alphabet.
    if lastLen != 0 and mlen == lastLen and mdist == reps[0] and mlen >= 2:
      toks.add(Token(kind: tkLast))
      inc freqMain[257]
      m.insertPos(data, dataLen, pos)
      # 257 covers mlen bytes; insert covered positions for chaining
      var k = pos + 1
      while k < min(pos + mlen, blkEnd):
        m.insertPos(data, dataLen, k)
        inc k
      pos += mlen
      continue
    var takeLazy = false
    if useLazy and mlen >= 3 and pos + 1 < blkEnd:
      let (mlen2raw, _) = m.bestAt(data, dataLen, pos + 1, rarEncMaxMatch)
      # Compare like-for-like: clamp the lookahead to the block just
      # like mlen, or the tail always looks longer (literal cascade).
      let mlen2 = min(mlen2raw, blkEnd - (pos + 1))
      if mlen2 > mlen:
        takeLazy = true
    if not takeLazy and mlen >= 2:
      # price the match with real code lengths
      var repIdx = -1
      for k in 0 .. 3:
        if reps[k] == mdist:
          repIdx = k
          break
      if repIdx >= 0:
        # Length table tops out at slot 43 (encoder length 4097);
        # longer runs continue on the next iteration.
        let useLen = min(mlen, 4097)
        let (slot, eb, ex) = encodeLenSlot(useLen.uint64)
        let cost = mainLen(258 + repIdx) + lenLen(slot) + eb
        if cost < litCost * useLen:
          toks.add(Token(kind: tkRep, repIdx: repIdx, repSlot: slot,
            repExtraBits: eb, repExtra: ex))
          inc freqMain[258 + repIdx]
          inc freqLen[slot]
          for k in countdown(repIdx, 1):
            reps[k] = reps[k - 1]
          reps[0] = mdist
          lastLen = useLen
          var k = pos
          while k < min(pos + useLen, blkEnd):
            m.insertPos(data, dataLen, k)
            inc k
          pos += useLen
          continue
      else:
        let bonus = lengthBonusEnc(mdist.uint64)
        # Encoder length needs slot space (min 2): skip matches that
        # would underflow after the bonus subtraction.
        if mlen.uint64 > bonus + 1:
          # Slot 43 caps the encoder length at 4097; the decoder adds
          # the bonus back, so longer runs continue next iteration.
          let useLen = min(mlen.uint64, 4097'u64 + bonus)
          let elen = useLen - bonus
          let (slot, eb, ex) = encodeLenSlot(elen)
          let (dslot, db, dex) = encodeDistSlot(mdist.uint64)
          let cost = mainLen(262 + slot) + eb + distLen(dslot) + db
          if cost < litCost * int(useLen) and 262 + slot < rarMainSyms and
              dslot < distSyms:
            toks.add(Token(kind: tkNew, newSlot: slot, newExtraBits: eb,
              newExtra: ex, newDistSlot: dslot, newDistBits: db,
              newDistExtra: dex))
            inc freqMain[262 + slot]
            inc freqDist[dslot]
            for k in countdown(3, 1):
              reps[k] = reps[k - 1]
            reps[0] = mdist
            lastLen = int(useLen)
            var k = pos
            while k < min(pos + int(useLen), blkEnd):
              m.insertPos(data, dataLen, k)
              inc k
            pos += int(useLen)
            continue
    # literal fallback
    toks.add(Token(kind: tkLit, lit: int(data[pos])))
    inc freqMain[int(data[pos])]
    m.insertPos(data, dataLen, pos)
    inc pos
  (toks, freqMain, freqLen, freqDist)

proc emitBlock(data: ptr UncheckedArray[byte]; toks: seq[Token];
    mainC, lenC, distC: seq[tuple[code, len: int]];
    w: var BitWriter) =
  for t in toks:
    case t.kind
    of tkLit:
      let c = mainC[t.lit]
      w.putBits(c.code.uint64, c.len)
    of tkLast:
      let c = mainC[257]
      w.putBits(c.code.uint64, c.len)
    of tkRep:
      let c = mainC[258 + t.repIdx]
      w.putBits(c.code.uint64, c.len)
      let lc = lenC[t.repSlot]
      w.putBits(lc.code.uint64, lc.len)
      if t.repExtraBits > 0:
        w.putBits(t.repExtra, t.repExtraBits)
    of tkNew:
      let c = mainC[262 + t.newSlot]
      w.putBits(c.code.uint64, c.len)
      if t.newExtraBits > 0:
        w.putBits(t.newExtra, t.newExtraBits)
      let dc = distC[t.newDistSlot]
      w.putBits(dc.code.uint64, dc.len)
      if t.newDistBits > 0:
        # Align table is all-4s so the decoder stays on the raw path;
        # emitting the low nibble raw is bit-identical to align codes.
        # Wide for Unpack70 (up to 38 bits).
        w.putBitsWide(t.newDistExtra, t.newDistBits)
    of tkFilter:
      let c = mainC[256]
      w.putBits(c.code.uint64, c.len)
      w.putReadU32(t.filtOff)
      w.putReadU32(t.filtLen)
      w.putBits(t.filtKind.uint64, 3)
      if t.filtKind == 0:
        w.putBits(uint64(t.filtChannels - 1), 5)

proc encodeLevelTable(levelLens: array[20, int]; w: var BitWriter) =
  ## Raw 4-bit lengths with the 15-escape for zero runs. Note 15,0 is
  ## literal 15 (not two zeros): the escape needs N = take-2 >= 1, so
  ## a 2-zero run is two literal zeros.
  var i = 0
  while i < 20:
    let v = levelLens[i]
    if v == 15:
      w.putBits(15, 4)
      w.putBits(0, 4)
      inc i
    elif v == 0:
      var run = 0
      while i + run < 20 and levelLens[i + run] == 0:
        inc run
      if run == 1:
        w.putBits(0, 4)
        inc i
      elif run == 2:
        w.putBits(0, 4)
        w.putBits(0, 4)
        i += 2
      else:
        let take = min(run, 17)
        w.putBits(15, 4)
        w.putBits(uint64(take - 2), 4)
        i += take
    else:
      w.putBits(v.uint64, 4)
      inc i

# ---------- entry API ----------

proc encodeRarMemberFiltered*(data: openArray[byte]; meth: int;
    dictSize = rarEncDict; filters: openArray[RarFilterSpec] = [];
    algoVer = 0): string =
  ## Compress one file's bytes into an Unpack50 (algoVer 0) or Unpack70
  ## (algoVer 1, 80-symbol distance alphabet) stream. `filters` are
  ## file-relative regions already forward-transformed in `data`; their
  ## triggers are emitted at the start of the first block (offsets
  ## relative to position 0). Fresh tables per 64KB block, non-solid.
  ## Raises on empty input (no valid empty compressed stream exists;
  ## the writer stores empties).
  if meth notin 1 .. 5:
    raise newException(RarEncError, "rar: unknown compression method")
  if algoVer notin [0, 1]:
    raise newException(RarEncError, "rar: unknown algorithm version")
  if data.len == 0:
    raise newException(RarEncError, "rar: cannot compress empty input")
  # Validate filters (must not overlap, within file, 4MB max each).
  var lastEnd = 0
  for f in filters:
    if f.kind notin 0 .. 3:
      raise newException(RarEncError, "rar: bad filter type")
    if f.len <= 0 or f.len > (1 shl 22):
      raise newException(RarEncError, "rar: bad filter length")
    if f.start < 0 or f.start + f.len > data.len:
      raise newException(RarEncError, "rar: filter range invalid")
    if f.start < lastEnd:
      raise newException(RarEncError, "rar: overlapping filters")
    lastEnd = f.start + f.len
    if f.kind == 0 and (f.channels < 1 or f.channels > 32):
      raise newException(RarEncError, "rar: bad delta channels")
  let distSyms = if algoVer == 1: rarDistSyms70 else: rarDistSyms50
  let maxChain =
    case meth
    of 1: 32
    of 2: 128
    of 3: 256
    of 4: 1024
    else: 4096
  let useLazy = meth >= 3
  var m = initMatcher(maxChain, dictSize)
  var outp: seq[byte] = @[]
  # adaptive costs: previous block's code lengths (static for block 0)
  var prevMain = newSeq[int](rarMainSyms)
  var prevLen = newSeq[int](rarLenSyms)
  var prevDist = newSeq[int](distSyms)
  # match state persists across blocks exactly like the decoder's
  var reps = [0, 0, 0, 0]
  var lastLen = 0
  var pos = 0
  var chunkStart = -1
  let dp = cast[ptr UncheckedArray[byte]](unsafeAddr data[0])
  while pos < data.len:
    if chunkStart < 0 or pos - chunkStart >= rarEncChunk:
      chunkStart = pos
      let clen = min(rarEncChunk, data.len - chunkStart)
      m.startChunk(chunkStart, clen)
      # Seed a short runway so matches can start immediately: chains
      # only see inserted positions.
      var r = max(chunkStart, pos - 4096)
      while r < pos:
        m.insertPos(dp, data.len, r)
        inc r
    var (toks, fMain, fLen, fDist) = tokenizeBlock(dp, data.len, pos, m,
      useLazy, 9, prevMain, prevLen, prevDist, reps, lastLen, distSyms)
    # Prepend filter triggers in the first block (curPos 0, so off=start).
    if pos == 0 and filters.len > 0:
      var filtToks: seq[Token] = @[]
      for f in filters:
        filtToks.add(Token(kind: tkFilter, filtOff: f.start.uint64,
          filtLen: f.len.uint64, filtKind: f.kind,
          filtChannels: if f.kind == 0: f.channels else: 1))
        inc fMain[256]
      toks = filtToks & toks
    let mainLens = huffmanLengths(fMain)
    let lenLens = huffmanLengths(fLen)
    let distLens = huffmanLengths(fDist)
    # Align table forced to all-4s (unused payload, but the all-4 shape
    # is what keeps the decoder on its raw direct-bit path).
    var aln4 = newSeq[int](rarAlignSyms)
    for i in 0 ..< rarAlignSyms:
      aln4[i] = 4
    let mainC = assignCodes(mainLens)
    let lenC = assignCodes(lenLens)
    let distC = assignCodes(distLens)
    prevMain = mainLens
    prevLen = lenLens
    prevDist = distLens
    # level RLE over concatenated lengths
    var concat: seq[int] = @[]
    for L in mainLens: concat.add(L)
    for L in distLens: concat.add(L)
    for L in aln4: concat.add(L)
    for L in lenLens: concat.add(L)
    var lvlSyms: seq[int] = @[]
    var lvlExtra: seq[tuple[bits, val: int]] = @[]
    packLengths(concat, lvlSyms, lvlExtra)
    var lvlFreq = newSeq[int](20)
    for s in lvlSyms:
      inc lvlFreq[s]
    let lvlLensArr = huffmanLengths(lvlFreq)
    var lvlLens: array[20, int]
    for i in 0 ..< 20:
      lvlLens[i] = if i < lvlLensArr.len: lvlLensArr[i] else: 0
    let lvlC = assignCodes(@lvlLens)
    # payload into scratch (two-pass: header needs the size)
    var w = BitWriter()
    encodeLevelTable(lvlLens, w)
    for i, s in lvlSyms:
      let c = lvlC[s]
      w.putBits(c.code.uint64, c.len)
      if lvlExtra[i].bits > 0:
        w.putBits(lvlExtra[i].val.uint64, lvlExtra[i].bits)
    emitBlock(dp, toks, mainC, lenC, distC, w)
    w.flushByte()
    let payloadBytes = w.buf.len
    let nSize =
      if payloadBytes <= 0xFF: 0
      elif payloadBytes <= 0xFFFF: 1
      else: 2
    if payloadBytes > 0xFFFFFF:
      raise newException(RarEncError, "rar: block too large")
    let isLast = pos + rarEncBlock >= data.len
    # Bits 3-4 carry the extra size-byte count; without them the
    # decoder reads one size byte and desyncs past 255-byte payloads.
    let flags = ((w.total - 1) and 7) or (nSize shl 3) or
      (if isLast: 0x40 else: 0) or 0x80
    var checksum = 0x5A'u8 xor byte(flags)
    var sizeBytes: array[3, byte]
    for i in 0 .. nSize:
      sizeBytes[i] = byte((payloadBytes shr (8 * i)) and 0xFF)
      checksum = checksum xor sizeBytes[i]
    outp.add(byte(flags))
    outp.add(checksum)
    for i in 0 .. nSize:
      outp.add(sizeBytes[i])
    for b in w.buf:
      outp.add(b)
    pos += rarEncBlock
  result = newString(outp.len)
  if outp.len > 0:
    copyMem(addr result[0], unsafeAddr outp[0], outp.len)

proc encodeRarMember*(data: openArray[byte]; meth: int;
    dictSize = rarEncDict): string =
  ## Back-compat: Unpack50, no filters.
  encodeRarMemberFiltered(data, meth, dictSize, [], 0)

proc rarCompInfo*(meth: int; dictSize = rarEncDict): uint64 =
  ## Compression Information vint for encoder-chosen settings (v0,
  ## non-solid). Dict decomposed per §11.11.10 (truncate, never round).
  ## Method 0 (STORE) carries no dictionary: CompInfo is plain zero.
  if meth notin 0 .. 5:
    raise newException(RarEncError, "rar: unknown compression method")
  if meth == 0:
    return 0
  const base0 = 128 * 1024
  var power = 0
  while power < 23 and base0 shl (power + 1) <= dictSize:
    inc power
  let base = base0 shl power
  let frac =
    if power <= 15: 0
    else: min(31, (dictSize - base) div (base div 32))
  result = (meth.uint64 shl 7) or (power.uint64 shl 10) or
    (frac.uint64 shl 15)

proc rarCompInfo70*(meth: int; dictSize = rarEncDict): uint64 =
  ## Unpack70 CompInfo (version 1, 80-symbol distance table). Same
  ## decomposition as v0 but with the version bit set; callers must pass
  ## a dictSize that actually needs v1 (non-power-of-2 or >4GiB) or force
  ## v1 for testing the 80-symbol path with a small dictionary.
  if meth notin 0 .. 5:
    raise newException(RarEncError, "rar: unknown compression method")
  if meth == 0:
    return 0
  const base0 = 128 * 1024
  var power = 0
  while power < 23 and base0 shl (power + 1) <= dictSize:
    inc power
  let base = base0 shl power
  let frac = min(31, (dictSize - base) div max(1, base div 32))
  result = 1'u64 or (meth.uint64 shl 7) or (power.uint64 shl 10) or
    (frac.uint64 shl 15)
