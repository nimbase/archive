## Bzip2 format ported from dsnet/compress semantics.
##
## Own block pipeline: RLE1, BWT (prefix-doubling suffix array with radix
## sort), MTF+RLE2, canonical Huffman (two-queue + length limiting, max
## 20 bits), unary selectors with MTF. CRC-32/BZIP2 (MSB-first,
## poly 0x04C11DB7) per block plus the combined stream checksum.
## Randomized blocks are rejected like the reference does.
## Works on `Input`/`Output`: no stream objects, no per-call output
## allocation when the caller reuses an Output.

import std/[algorithm]
import ./io
from std/os import removeFile

type Bz2Error* = object of CatchableError

const
  bzHdrMagic = 0x425a'u16 ## "BZ"
  bzBlkMagic = 0x314159265359'u64 ## BCD of PI
  bzEndMagic = 0x177245385090'u64 ## BCD of sqrt(PI)
  bzMinTrees = 2
  bzMaxTrees = 6
  bzMaxBits = 20
  bzBlockSyms = 50
  bzBlockSize = 100000

# ---------- CRC-32/BZIP2 (MSB-first, poly 0x04C11DB7) ----------

proc buildBzTable(): array[256, uint32] =
  for i in 0 .. 255:
    var c = i.uint32 shl 24
    for _ in 0 ..< 8:
      if (c and 0x80000000'u32) != 0:
        c = (c shl 1) xor 0x04C11DB7'u32
      else:
        c = c shl 1
    result[i] = c

const bzTable = buildBzTable()

proc bzCrcUpdate*(crc: uint32; p: pointer; length: int): uint32 =
  ## Running update, start with 0.
  result = crc
  let b = cast[ptr UncheckedArray[byte]](p)
  for i in 0 ..< length:
    result = bzTable[((result shr 24) xor b[i].uint32) and 0xFF] xor
      (result shl 8)

proc bzCrcUpdate*(crc: uint32; data: string): uint32 =
  if data.len == 0: crc
  else: bzCrcUpdate(crc, unsafeAddr data[0], data.len)

proc bzCrcChecksum*(data: string): uint32 =
  ## Canonical CRC-32/BZIP2 value (init and xor-out 0xFFFFFFFF).
  ## bzCrcChecksum("123456789") == 0xFC891918.
  bzCrcUpdate(0xFFFFFFFF'u32, data) xor 0xFFFFFFFF'u32

# ---------- bit reader (MSB-first, absolute over Input memory) ----------

type BzBits* = object
  base*: pointer
  totalBits*: int
  pos*: int

proc getBit*(br: var BzBits): int {.inline.} =
  if br.pos >= br.totalBits:
    raise newException(Bz2Error, "bzip2: truncated input")
  let bv = cast[ptr UncheckedArray[byte]](br.base)[br.pos shr 3]
  result = (bv.uint32 shr (7 - (br.pos and 7))).int and 1
  inc br.pos

proc getBE*(br: var BzBits; n: int): uint64 =
  ## Big-endian number: first bit is MSB (matches Go ReadBitsBE64).
  result = 0
  for _ in 0 ..< n:
    result = (result shl 1) or getBit(br).uint64

proc getRaw*(br: var BzBits; n: int): uint =
  ## LSB-first assembly: first bit is the LSB (matches Go ReadBits).
  result = 0
  for i in 0 ..< n:
    result = result or (getBit(br).uint shl i)

proc getUnary*(br: var BzBits; limit: int): int =
  ## Count of 1 bits before the terminating 0.
  result = 0
  while getBit(br) == 1:
    inc result
    if result > limit:
      raise newException(Bz2Error, "bzip2: invalid unary code")
  # terminating 0 consumed

# ---------- bit writer (MSB-first wire order) ----------

type BzWriter* = object
  dst*: Output
  cur: uint8
  nbits: int

proc putBit*(w: var BzWriter; b: int) {.inline.} =
  w.cur = (w.cur shl 1) or b.uint8
  inc w.nbits
  if w.nbits == 8:
    w.dst.writeByte(char(w.cur))
    w.cur = 0
    w.nbits = 0

proc putRaw*(w: var BzWriter; v: uint32; n: int) {.inline.} =
  ## LSB-first value bits (matches Go WriteBits under bigEndian).
  for i in 0 ..< n:
    putBit(w, ((v shr i) and 1).int)

proc putBE*(w: var BzWriter; v: uint64; n: int) {.inline.} =
  ## Big-endian number: MSB first.
  for i in countdown(n - 1, 0):
    putBit(w, ((v shr i) and 1).int)

proc putUnary*(w: var BzWriter; v: int) {.inline.} =
  for _ in 0 ..< v:
    putBit(w, 1)
  putBit(w, 0)

proc flushBits*(w: var BzWriter) {.inline.} =
  if w.nbits > 0:
    w.dst.writeByte(char(w.cur shl (8 - w.nbits)))
    w.cur = 0
    w.nbits = 0

# ---------- Huffman lengths: two-queue + length limiting ----------

type HuffSym* = object
  sym*: int
  cnt*: uint32
  len*: int

proc genLengths*(syms: var seq[HuffSym]; maxBits: int) =
  ## Port of prefix.GenerateLengths: package-merge style via two queues,
  ## then tree-rotation fix if any length exceeds maxBits. `syms` must be
  ## sorted by count ascending on entry; lengths returned in place.
  if syms.len <= 1:
    if syms.len == 1:
      syms[0].len = 0
    return
  type HNode = object
    cnt: uint32
    n0, n1: int # child node indices, -1 when leaf side
    c0, c1: int # leaf symbol indices into syms, -1 when internal
  var nodes = newSeq[HNode](syms.len)
  var nodeIdx = 0
  var freqs = 0 # index into syms of first unused leaf (syms is count-sorted)
  var queue = newSeq[int]() # indices into nodes of ready internal nodes
  var qhead = 0
  template qcnt(i: int): uint32 = nodes[queue[qhead + i]].cnt
  while (syms.len - freqs) + (queue.len - qhead) > 1:
    var n: HNode
    n.n0 = -1; n.n1 = -1; n.c0 = -1; n.c1 = -1
    if (queue.len - qhead) == 0 or
        (freqs < syms.len and syms[freqs].cnt <= qcnt(0)):
      n.c0 = freqs
      n.cnt += syms[freqs].cnt
      inc freqs
    else:
      n.cnt += qcnt(0)
      n.n0 = queue[qhead]
      inc qhead
    if (queue.len - qhead) == 0 or
        (freqs < syms.len and syms[freqs].cnt <= qcnt(0)):
      n.c1 = freqs
      n.cnt += syms[freqs].cnt
      inc freqs
    else:
      n.cnt += qcnt(0)
      n.n1 = queue[qhead]
      inc qhead
    nodes[nodeIdx] = n
    queue.add(nodeIdx)
    inc nodeIdx
  let rootIdx = nodeIdx - 1
  var fixBits = false
  proc explore(nodes: seq[HNode]; syms: var seq[HuffSym]; ri, level: int;
      maxBits: int; fixBits: var bool) =
    let r = nodes[ri]
    if r.c0 == -1:
      explore(nodes, syms, r.n0, level + 1, maxBits, fixBits)
    else:
      if level > maxBits:
        fixBits = true
      syms[r.c0].len = level
    if r.c1 == -1:
      explore(nodes, syms, r.n1, level + 1, maxBits, fixBits)
    else:
      if level > maxBits:
        fixBits = true
      syms[r.c1].len = level
  explore(nodes, syms, rootIdx, 1, maxBits, fixBits)
  if fixBits:
    var symBits = newSeq[uint32](maxBits + 2)
    for s in syms:
      while s.len >= symBits.len:
        symBits.add(0'u32)
      symBits[s.len] += 1
    proc rotate(symBits: var seq[uint32]; nb: int) =
      if symBits[nb - 1] == 0:
        rotate(symBits, nb - 1)
      symBits[nb - 1] -= 1
      symBits[nb] += 3
      symBits[nb + 1] -= 2
    var i = symBits.len - 1
    while i > maxBits:
      while symBits[i] > 0:
        rotate(symBits, i - 1)
      dec i
    var cs = 0 # syms sorted count-asc: shortest lengths go to the back
    var rest = syms.len
    for nb in 0 ..< symBits.len:
      let cnt = symBits[nb].int
      if cnt > 0:
        let pos = rest - cnt
        for j in pos ..< rest:
          syms[j].len = nb
        rest = pos
    cs = rest
    if cs != 0:
      raise newException(Bz2Error, "bzip2: length limiting failed")

# ---------- canonical codes (MSB-first) ----------

proc buildEncode*(lens: openArray[int]): seq[tuple[code: uint32, len: int]] =
  ## Canonical MSB-first codes from per-symbol lengths.
  let ls = @lens
  var order = newSeq[int](ls.len)
  for i in 0 ..< ls.len:
    order[i] = i
  order.sort(proc(a, b: int): int =
    if ls[a] != ls[b]: ls[a] - ls[b] else: a - b)
  result = newSeq[tuple[code: uint32, len: int]](ls.len)
  var code = 0'u32
  var prev = 0
  for s in order:
    let ln = ls[s]
    code = code shl (ln - prev)
    result[s] = (code, ln)
    inc code
    prev = ln

type HuffDec* = object
  counts*: array[bzMaxBits + 1, int]
  symbols*: seq[int]
  maxLen*: int

proc buildDecode*(lens: openArray[int]): HuffDec =
  for s, ln in lens:
    if ln < 1 or ln > bzMaxBits:
      raise newException(Bz2Error, "bzip2: invalid prefix bit-length")
    result.counts[ln] += 1
    if ln > result.maxLen:
      result.maxLen = ln
  var sum = 0
  for l in 1 .. result.maxLen:
    sum += result.counts[l] shl (result.maxLen - l)
  if sum != (1 shl result.maxLen):
    raise newException(Bz2Error, "bzip2: degenerate prefix tree")
  for l in 1 .. result.maxLen:
    for s, ln in lens:
      if ln == l:
        result.symbols.add(s)

proc decodeSym*(d: HuffDec; br: var BzBits): int =
  var code = 0
  var first = 0
  var index = 0
  for length in 1 .. d.maxLen:
    code = (code shl 1) or getBit(br)
    if code - first < d.counts[length]:
      return d.symbols[index + (code - first)]
    index += d.counts[length]
    first = (first + d.counts[length]) shl 1
  raise newException(Bz2Error, "bzip2: invalid huffman code")

# ---------- MTF + RLE2 ----------

proc mtfEncodeIdx*(dict: var array[256, byte]; dictLen: int; val: byte): int =
  ## Returns MTF index, moving val to front.
  for i in 0 ..< dictLen:
    if dict[i] == val:
      if i > 0:
        copyMem(addr dict[1], addr dict[0], i)
        dict[0] = val
      return i
  raise newException(Bz2Error, "bzip2: symbol outside alphabet")

proc mtfDecodeSymsReuse*(syms: openArray[int]; dict: openArray[byte];
    blkSize: int; outVals: var seq[byte]) =
  ## MTF+RLE2 decode into a reusable buffer (setLen(0) first, capacity
  ## retained across blocks so repeated blocks never reallocate).
  ## Same semantics as mtfDecodeSyms; see it for the format details.
  outVals.setLen(0)
  var d: array[256, byte]
  for i, v in dict:
    d[i] = v
  var lastCnt = 0
  var lastRun = 0'u32
  for sym in syms:
    if sym < 2:
      lastRun = lastRun or (sym.uint32 shl lastCnt)
      inc lastCnt
      continue
    if lastCnt > 0:
      let cnt = ((1'u32 shl lastCnt) or lastRun).int - 1
      if outVals.len + cnt > blkSize or lastCnt > 24:
        raise newException(Bz2Error,
          "bzip2: run-length decoding exceeded block size")
      for _ in 0 ..< cnt:
        outVals.add(d[0])
      lastCnt = 0
      lastRun = 0
    let idx = sym - 1
    if idx < 0 or idx >= dict.len:
      raise newException(Bz2Error, "bzip2: MTF index out of range")
    let val = d[idx]
    if idx > 0:
      copyMem(addr d[1], addr d[0], idx)
      d[0] = val
    if outVals.len >= blkSize:
      raise newException(Bz2Error,
        "bzip2: run-length decoding exceeded block size")
    outVals.add(val)
  if lastCnt > 0:
    let cnt = ((1'u32 shl lastCnt) or lastRun).int - 1
    if outVals.len + cnt > blkSize or lastCnt > 24:
      raise newException(Bz2Error,
        "bzip2: run-length decoding exceeded block size")
    for _ in 0 ..< cnt:
      outVals.add(d[0])

proc mtfDecodeSyms*(syms: openArray[int]; dict: openArray[byte];
    blkSize: int): seq[byte] =
  ## MTF+RLE2 decode with block-size bound. syms use 0=RUNA, 1=RUNB,
  ## 2.. as MTF index+1.
  mtfDecodeSymsReuse(syms, dict, blkSize, result)

proc mtfEncodeVals*(vals: openArray[byte]; dict: openArray[byte];
    blkSize: int): seq[int] =
  ## MTF+RLE2 encode. Returns symbols (0=RUNA, 1=RUNB, 2.. = idx+1).
  if vals.len > blkSize:
    raise newException(Bz2Error, "bzip2: exceeded block size")
  var d: array[256, byte]
  for i, v in dict:
    d[i] = v
  var lastNum = 0'u32
  for val in vals:
    let idx = mtfEncodeIdx(d, dict.len, val)
    if idx == 0:
      inc lastNum
      continue
    if lastNum > 0:
      var rc = lastNum + 1
      while rc != 1:
        result.add((rc and 1).int)
        rc = rc shr 1
      lastNum = 0
    result.add(idx + 1)
  if lastNum > 0:
    var rc = lastNum + 1
    while rc != 1:
      result.add((rc and 1).int)
      rc = rc shr 1

# ---------- RLE1 ----------

proc rle1DecodeInto*(buf: openArray[byte]; dst: Output; crc: var uint32) =
  ## First-stage RLE decode into `dst`, updating the bzip2 CRC.
  var lastVal = 0
  var lastCnt = 0
  var i = 0
  let n = buf.len
  while true:
    if lastCnt == -4:
      if i >= n:
        raise newException(Bz2Error,
          "bzip2: missing terminating run-length repeater")
      lastCnt = buf[i].int
      inc i
      if lastCnt > 0:
        dst.writeByte(char(lastVal))
        crc = bzCrcUpdate(crc, unsafeAddr lastVal, 1)
        dec lastCnt
        continue
    if lastCnt <= 0:
      if i >= n:
        return # done
      let b = buf[i].int
      inc i
      if b != lastVal:
        lastCnt = 0
        lastVal = b
    dst.writeByte(char(lastVal))
    crc = bzCrcUpdate(crc, unsafeAddr lastVal, 1)
    dec lastCnt

type Rle1Enc* = object
  buf*: seq[byte]
  cap*: int
  lastVal: int
  lastCnt: int

proc rle1Init*(cap: int): Rle1Enc =
  Rle1Enc(buf: newSeqOfCap[byte](min(cap, 1024)), cap: cap,
    lastVal: 0, lastCnt: 0)

proc rle1Put*(e: var Rle1Enc; b: byte) =
  ## Appends one byte; caller must ensure e.buf.len + 2 <= e.cap
  ## (a single input byte emits at most 2 RLE1 bytes).
  if e.lastVal != b.int:
    e.lastCnt = 0
  inc e.lastCnt
  e.lastVal = b.int
  case e.lastCnt
  of 1 .. 3:
    e.buf.add(b)
  of 4:
    e.buf.add(b)
    e.buf.add(0)
  else:
    if e.lastCnt < 256:
      e.buf[^1] = byte(e.buf[^1].int + 1)
    else:
      e.lastCnt = 1
      e.buf.add(b)

# ---------- BWT ----------

proc suffixArray(t: openArray[byte]): seq[int] =
  ## Prefix-doubling suffix array with LSD radix sort. Stable and
  ## deterministic; verified by round-trip + independent decoders.
  let m = t.len
  result = newSeq[int](m)
  for i in 0 ..< m:
    result[i] = i
  var rank = newSeq[int](m)
  for i in 0 ..< m:
    rank[i] = t[i].int
  var tmp = newSeq[int](m)
  var sa2 = newSeq[int](m)
  var cnt = newSeq[int](max(m + 2, 258))
  var k = 1
  var maxRank = 255
  while true:
    # sort by second key rank[i+k]+1 (0 = sentinel), then first key +1
    for i in 0 ..< maxRank + 3:
      cnt[i] = 0
    for i in 0 ..< m:
      let key = if result[i] + k < m: rank[result[i] + k] + 1 else: 0
      inc cnt[key]
    var s = 0
    for i in 0 ..< maxRank + 3:
      let c = cnt[i]
      cnt[i] = s
      s += c
    for i in 0 ..< m:
      let idx = result[i]
      let key = if idx + k < m: rank[idx + k] + 1 else: 0
      sa2[cnt[key]] = idx
      inc cnt[key]
    for i in 0 ..< maxRank + 3:
      cnt[i] = 0
    for i in 0 ..< m:
      inc cnt[rank[sa2[i]] + 1]
    s = 0
    for i in 0 ..< maxRank + 3:
      let c = cnt[i]
      cnt[i] = s
      s += c
    for i in 0 ..< m:
      let idx = sa2[i]
      let key = rank[idx] + 1
      result[cnt[key]] = idx
      inc cnt[key]
    tmp[result[0]] = 0
    var r = 0
    for i in 1 ..< m:
      let a = result[i]
      let b = result[i - 1]
      let ka = if a + k < m: rank[a + k] else: -1
      let kb = if b + k < m: rank[b + k] else: -1
      if rank[a] != rank[b] or ka != kb:
        inc r
      tmp[a] = r
    let rtmp = rank
    rank = tmp
    tmp = rtmp
    maxRank = r
    if r == m - 1:
      break
    k *= 2

proc bwtEncode*(buf: openArray[byte]): tuple[outp: seq[byte], origin: int] =
  ## BWT via doubled-string suffix array (mirrors dsnet's SA-IS approach).
  let n = buf.len
  if n == 0:
    return (@[], 0)
  var t = newSeq[byte](2 * n)
  for i in 0 ..< n:
    t[i] = buf[i]
    t[n + i] = buf[i]
  let sa = suffixArray(t)
  result.outp = newSeq[byte](n)
  var j = 0
  for i in sa:
    if i < n:
      var ii = i
      if ii == 0:
        result.origin = j
        ii = n
      result.outp[j] = t[n + ii - 1]
      inc j

proc bwtDecodeReuse*(buf: var seq[byte]; origin: int;
    perm: var seq[uint32]; outp: var seq[byte]) =
  ## LF-mapping inversion with caller-provided working buffers (reused
  ## across blocks; capacities retained). Same semantics as bwtDecode.
  let n = buf.len
  if n == 0:
    return
  if origin < 0 or origin >= n:
    raise newException(Bz2Error, "bzip2: origin pointer out of range")
  var cumm: array[256, int]
  for v in buf:
    inc cumm[v]
  var sum = 0
  for i in 0 .. 255:
    let c = cumm[i]
    cumm[i] = sum
    sum += c
  perm.setLen(n)
  for i, b in buf:
    perm[cumm[b]] = i.uint32
    inc cumm[b]
  outp.setLen(n)
  var i = perm[origin]
  for j in 0 ..< n:
    outp[j] = buf[i]
    i = perm[i]
  for j in 0 ..< n:
    buf[j] = outp[j]

proc bwtDecode*(buf: var seq[byte]; origin: int) =
  ## LF-mapping inversion, in place.
  var perm: seq[uint32]
  var outp: seq[byte]
  bwtDecodeReuse(buf, origin, perm, outp)

# ---------- block encode ----------

proc numTreesFor(symCount: int): int =
  result = bzMaxTrees
  const lims = [200, 600, 1200, 2400]
  for i, lim in lims:
    if symCount < lim:
      return bzMinTrees + i

proc encodeBlock(vals: openArray[byte]; blkCRC: uint32; w: var BzWriter) =
  w.putBE(bzBlkMagic, 48)
  w.putBE(blkCRC, 32)
  w.putBE(0, 1) # never randomized
  let (bwtBuf, origin) = bwtEncode(vals)
  w.putBE(origin.uint64, 24)
  var dictMap: array[256, bool]
  for c in bwtBuf:
    dictMap[c] = true
  var dict = newSeq[byte]()
  var bmapHi = 0'u32
  var bmapLo: array[16, uint32]
  for i in 0 .. 255:
    if dictMap[i]:
      dict.add(i.byte)
      bmapHi = bmapHi or (1'u32 shl (i shr 4))
      bmapLo[i shr 4] = bmapLo[i shr 4] or (1'u32 shl (i and 0xF))
  w.putRaw(bmapHi, 16)
  for m in bmapLo:
    if m != 0:
      w.putRaw(m, 16)
  var syms = mtfEncodeVals(bwtBuf, dict, vals.len)
  let numSyms = dict.len + 2
  if numSyms < 3:
    raise newException(Bz2Error, "bzip2: unable to encode EOB marker")
  syms.add(numSyms - 1) # EOB marker
  let numTrees = numTreesFor(syms.len)
  let numSels = (syms.len + bzBlockSyms - 1) div bzBlockSyms
  var treeSels = newSeq[int](numSels)
  for i in 0 ..< numSels:
    treeSels[i] = i mod numTrees
  # frequency counts per tree over 50-symbol groups
  var freqs = newSeq[seq[int]](numTrees)
  for t in 0 ..< numTrees:
    freqs[t] = newSeq[int](numSyms)
  var blkLen = 0
  var selIdx = 0
  for sym in syms:
    if blkLen == 0:
      blkLen = bzBlockSyms
      if selIdx >= numSels:
        raise newException(Bz2Error, "bzip2: selector overrun")
      inc selIdx
    dec blkLen
    freqs[treeSels[selIdx - 1]][sym] += 1
  var allLens = newSeq[seq[int]](numTrees)
  var encTables = newSeq[seq[tuple[code: uint32, len: int]]](numTrees)
  for t in 0 ..< numTrees:
    var hs = newSeq[HuffSym](numSyms)
    for s in 0 ..< numSyms:
      hs[s] = HuffSym(sym: s, cnt: freqs[t][s].uint32)
    hs.sort(proc(a, b: HuffSym): int =
      if a.cnt != b.cnt: (if a.cnt < b.cnt: -1 else: 1)
      else: (if a.sym < b.sym: -1 elif a.sym > b.sym: 1 else: 0))
    genLengths(hs, bzMaxBits)
    var lens = newSeq[int](numSyms)
    for h in hs:
      lens[h.sym] = h.len
    allLens[t] = lens
    encTables[t] = buildEncode(lens)
  w.putBE(numTrees.uint64, 3)
  w.putBE(numSels.uint64, 15)
  # MTF-encode a COPY of the selectors (Go: treeSelsMTF); the originals
  # are still needed below to pick trees for symbol groups.
  var selMTF = treeSels
  var mtfD: array[6, byte]
  for i in 0 ..< numTrees:
    mtfD[i] = i.byte
  for i in 0 ..< numSels:
    let v = selMTF[i]
    var idx = 0
    while mtfD[idx] != v.byte:
      inc idx
    if idx > 0:
      let tmp = mtfD[idx]
      for j in countdown(idx, 1):
        mtfD[j] = mtfD[j - 1]
      mtfD[0] = tmp
    selMTF[i] = idx
  for s in selMTF:
    w.putUnary(s)
  for t in 0 ..< numTrees:
    let lens = allLens[t]
    w.putBE(lens[0].uint64, 5)
    var clen = lens[0]
    for s in 0 ..< numSyms:
      while lens[s] < clen:
        w.putRaw(3, 2) # 11: decrement
        dec clen
      while lens[s] > clen:
        w.putRaw(1, 2) # 10: increment
        inc clen
      w.putRaw(0, 1)
  blkLen = 0
  selIdx = 0
  for sym in syms:
    if blkLen == 0:
      blkLen = bzBlockSyms
      if selIdx >= numSels:
        raise newException(Bz2Error, "bzip2: selector overrun")
      inc selIdx
    dec blkLen
    let (code, ln) = encTables[treeSels[selIdx - 1]][sym]
    w.putBE(code.uint64, ln)

# ---------- one-shot frame codec ----------

proc bz2CompressInto*(inp: Input; dst: Output; level = 6) =
  ## One-shot bzip2 compress. `level` 0 means default (6); 1..9 select
  ## the block size in units of 100k RLE1 bytes.
  let lvl = if level == 0: 6 else: level
  if lvl < 1 or lvl > 9:
    raise newException(Bz2Error, "bzip2: invalid compression level")
  let total = remaining(inp)
  let start = inputPos(inp)
  let base = basePointer(inp)
  var w = BzWriter(dst: dst)
  w.putBE(bzHdrMagic.uint64, 16)
  w.putBE(uint64('h'), 8)
  w.putBE(uint64('0'.ord + lvl), 8)
  var endCRC = 0'u32
  if total > 0:
    let b = cast[ptr UncheckedArray[byte]](base)
    var enc = rle1Init(lvl * bzBlockSize)
    var crc = 0xFFFFFFFF'u32
    var i = 0
    while i < total:
      if enc.buf.len + 2 > enc.cap:
        encodeBlock(enc.buf, crc xor 0xFFFFFFFF'u32, w)
        endCRC = ((endCRC shl 1) or (endCRC shr 31)) xor
          (crc xor 0xFFFFFFFF'u32)
        crc = 0xFFFFFFFF'u32
        enc = rle1Init(lvl * bzBlockSize)
      let by = b[start + i]
      crc = bzCrcUpdate(crc, unsafeAddr b[start + i], 1)
      rle1Put(enc, by)
      inc i
    if enc.buf.len > 0:
      encodeBlock(enc.buf, crc xor 0xFFFFFFFF'u32, w)
      endCRC = ((endCRC shl 1) or (endCRC shr 31)) xor
        (crc xor 0xFFFFFFFF'u32)
    seek(inp, start + total)
  w.putBE(bzEndMagic, 48)
  w.putBE(endCRC.uint64, 32)
  w.flushBits()

proc bz2Compress*(data: string; level = 6): string =
  ## Convenience: compress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput(data.len div 8 + 32)
  bz2CompressInto(inp, dst, level)
  take(dst)

proc decodeOneBlock(br: var BzBits; dst: Output; lvl: int;
    endCRC: var uint32; gotFooter: var bool) =
  let magic = br.getBE(48)
  if magic == bzEndMagic:
    let stored = br.getBE(32).uint32
    if stored != endCRC:
      raise newException(Bz2Error, "bzip2: mismatching stream checksum")
    endCRC = 0
    br.pos = (br.pos + 7) and not 7 # ReadPads: align, ignore value
    gotFooter = true
    return
  if magic != bzBlkMagic:
    raise newException(Bz2Error, "bzip2: invalid block or footer magic")
  let blkCRC = br.getBE(32).uint32
  if br.getBE(1) != 0:
    raise newException(Bz2Error,
      "bzip2: block randomization is not supported")
  let origin = br.getBE(24).int
  var dict = newSeq[byte]()
  let hi = br.getRaw(16).int
  for g in 0 ..< 16:
    if ((hi shr g) and 1) != 0:
      let lo = br.getRaw(16).int
      for j in 0 ..< 16:
        if ((lo shr j) and 1) != 0:
          dict.add(byte(g * 16 + j))
  var numSyms = dict.len + 2
  if numSyms < 3:
    raise newException(Bz2Error, "bzip2: not enough prefix symbols")
  let numTrees = br.getBE(3).int
  if numTrees < bzMinTrees or numTrees > bzMaxTrees:
    raise newException(Bz2Error, "bzip2: invalid number of prefix trees")
  let numSels = br.getBE(15).int
  var treeSels = newSeq[int](numSels)
  for i in 0 ..< numSels:
    let s = br.getUnary(bzMaxTrees)
    if s >= numTrees:
      raise newException(Bz2Error, "bzip2: invalid prefix tree selector")
    treeSels[i] = s
  # MTF-decode selectors over identity alphabet
  var mtfD = newSeq[byte](numTrees)
  for i in 0 ..< numTrees:
    mtfD[i] = i.byte
  for i in 0 ..< numSels:
    let idx = treeSels[i]
    if idx < 0 or idx >= numTrees:
      raise newException(Bz2Error, "bzip2: selector MTF out of range")
    let v = mtfD[idx]
    if idx > 0:
      for j in countdown(idx, 1):
        mtfD[j] = mtfD[j - 1]
      mtfD[0] = v
    treeSels[i] = v.int
  var decs = newSeq[HuffDec](numTrees)
  for t in 0 ..< numTrees:
    var clen = br.getBE(5).int
    if clen < 1 or clen > bzMaxBits:
      raise newException(Bz2Error, "bzip2: invalid prefix bit-length")
    var lens = newSeq[int](numSyms)
    for s in 0 ..< numSyms:
      while true:
        if br.getBE(1) == 0:
          break
        if br.getBE(1) == 0:
          inc clen
        else:
          dec clen
      if clen < 1 or clen > bzMaxBits:
        raise newException(Bz2Error, "bzip2: invalid prefix bit-length")
      lens[s] = clen
    decs[t] = buildDecode(lens)
  var syms = newSeq[int]()
  var blkLen = 0
  var selIdx = 0
  let blkCap = lvl * bzBlockSize
  while true:
    if blkLen == 0:
      blkLen = bzBlockSyms
      if selIdx >= numSels:
        raise newException(Bz2Error,
          "bzip2: not enough prefix tree selectors")
      inc selIdx
    dec blkLen
    let sym = decodeSym(decs[treeSels[selIdx - 1]], br)
    if sym == numSyms - 1:
      break # EOB
    if sym >= numSyms:
      raise newException(Bz2Error, "bzip2: invalid prefix symbol")
    if syms.len >= blkCap:
      raise newException(Bz2Error,
        "bzip2: number of prefix symbols exceeds block size")
    syms.add(sym)
  var vals = mtfDecodeSyms(syms, dict, blkCap)
  bwtDecode(vals, origin)
  var crc = 0xFFFFFFFF'u32
  rle1DecodeInto(vals, dst, crc)
  if (crc xor 0xFFFFFFFF'u32) != blkCRC:
    raise newException(Bz2Error, "bzip2: mismatching block checksum")
  endCRC = ((endCRC shl 1) or (endCRC shr 31)) xor blkCRC

proc bz2DecompressInto*(inp: Input; dst: Output) =
  ## Decompress concatenated bzip2 streams at the cursor into `dst`,
  ## verifying per-block and stream checksums. Raises Bz2Error.
  if remaining(inp) == 0:
    return
  var br = BzBits(base: basePointer(inp), totalBits: inputLen(inp) * 8,
    pos: inputPos(inp) * 8)
  var streams = 0
  while true:
    if br.pos >= br.totalBits:
      break
    if br.totalBits - br.pos < 32:
      if streams == 0:
        raise newException(Bz2Error, "bzip2: truncated stream header")
      break
    if br.getBE(16) != bzHdrMagic.uint64:
      if streams == 0:
        raise newException(Bz2Error, "bzip2: invalid stream magic")
      break
    let ver = br.getBE(8)
    if ver == uint64('0'):
      raise newException(Bz2Error, "bzip2: bzip1 format is not supported")
    if ver != uint64('h'):
      raise newException(Bz2Error, "bzip2: invalid version")
    let lvl = br.getBE(8).int - '0'.ord
    if lvl < 1 or lvl > 9:
      raise newException(Bz2Error, "bzip2: invalid block size")
    var endCRC = 0'u32
    while true:
      var gotFooter = false
      if br.pos >= br.totalBits:
        raise newException(Bz2Error, "bzip2: truncated block")
      decodeOneBlock(br, dst, lvl, endCRC, gotFooter)
      if gotFooter:
        break
    inc streams
  seek(inp, br.pos div 8)

proc bz2Decompress*(data: string): string =
  ## Convenience: decompress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  bz2DecompressInto(inp, dst)
  take(dst)

type FileBzReader = object
  ## Byte... bit-backed buffered file reader (MSB-first, like BzBits).
  ## Owns a fixed 64KB buffer; `bitPos` tracks consumed bits, `eof`
  ## set when file EOF reached. No globals; state explicit per call.
  f: File
  buf: string
  bufLen: int
  bitPos: int
  eof: bool

proc bzRefill(rdr: var FileBzReader) =
  let bi = rdr.bitPos div 8
  if bi < rdr.bufLen:
    let unread = rdr.bufLen - bi
    if bi > 0:
      moveMem(addr rdr.buf[0], addr rdr.buf[bi], unread)
    rdr.bufLen = unread
    rdr.bitPos = rdr.bitPos - bi * 8
  else:
    rdr.bufLen = 0
    rdr.bitPos = 0
  if not rdr.eof:
    let free = rdr.buf.len - rdr.bufLen
    if free > 0:
      let n = readBuffer(rdr.f, addr rdr.buf[rdr.bufLen], free)
      if n <= 0:
        rdr.eof = true
      else:
        rdr.bufLen += n

proc bzEnsureBits(rdr: var FileBzReader; n: int) =
  while (rdr.bufLen * 8 - rdr.bitPos) < n:
    let beforeLen = rdr.bufLen
    let beforeEof = rdr.eof
    bzRefill(rdr)
    if (rdr.bufLen * 8 - rdr.bitPos) < n:
      if rdr.eof:
        raise newException(Bz2Error, "bzip2: truncated input")
      if rdr.bufLen == beforeLen and rdr.eof == beforeEof:
        raise newException(Bz2Error, "bzip2: truncated input")

proc bzGetBit(rdr: var FileBzReader): int =
  bzEnsureBits(rdr, 1)
  let p = rdr.bitPos
  result = (cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[p shr 3].uint32 shr
    (7 - (p and 7))).int and 1
  inc rdr.bitPos

proc bzGetBE(rdr: var FileBzReader; n: int): uint64 =
  ## Big-endian number: first bit is MSB (matches BzBits.getBE).
  for _ in 0 ..< n:
    result = (result shl 1) or bzGetBit(rdr).uint64

proc bzGetRaw(rdr: var FileBzReader; n: int): uint =
  ## LSB-first assembly (matches BzBits.getRaw).
  for i in 0 ..< n:
    result = result or (bzGetBit(rdr).uint shl i)

proc bzGetUnary(rdr: var FileBzReader; limit: int): int =
  while bzGetBit(rdr) == 1:
    inc result
    if result > limit:
      raise newException(Bz2Error, "bzip2: invalid unary code")

proc bzDecodeSym(d: HuffDec; rdr: var FileBzReader): int =
  var code = 0
  var first = 0
  var index = 0
  for length in 1 .. d.maxLen:
    code = (code shl 1) or bzGetBit(rdr)
    if code - first < d.counts[length]:
      return d.symbols[index + (code - first)]
    index += d.counts[length]
    first = (first + d.counts[length]) shl 1
  raise newException(Bz2Error, "bzip2: invalid huffman code")

type BzBlockScratch* = object
  ## Reused per-block working buffers for file streaming decode.
  ## Capacities grow to the largest block seen (≤900KB block → syms
  ## ≤7.2MB ints, vals/perm/outp ≤ ~4.5MB) and are retained: no per-block
  ## allocation churn, so the ZCT never stacks multiple blocks' garbage.
  ## Capped by the format's max block size, never by file size.
  syms*: seq[int]
  vals*: seq[byte]
  perm*: seq[uint32]
  outp*: seq[byte]

proc decodeOneBlockFile(rdr: var FileBzReader; scratch: Output; lvl: int;
    endCRC: var uint32; gotFooter: var bool; bs: var BzBlockScratch) =
  ## File-backed mirror of decodeOneBlock: decodes one block into the
  ## bounded per-block `scratch` (≤900KB + slack, caller resets per
  ## block), verifies the block CRC, folds into `endCRC`. No full
  ## stream holding; callers flush `scratch` to disk after each block.
  let magic = bzGetBE(rdr, 48)
  if magic == bzEndMagic:
    let stored = bzGetBE(rdr, 32).uint32
    if stored != endCRC:
      raise newException(Bz2Error, "bzip2: mismatching stream checksum")
    endCRC = 0
    # ReadPads: align, ignore value.
    rdr.bitPos = (rdr.bitPos + 7) and not 7
    gotFooter = true
    return
  if magic != bzBlkMagic:
    raise newException(Bz2Error, "bzip2: invalid block or footer magic")
  let blkCRC = bzGetBE(rdr, 32).uint32
  if bzGetBE(rdr, 1) != 0:
    raise newException(Bz2Error,
      "bzip2: block randomization is not supported")
  let origin = bzGetBE(rdr, 24).int
  var dict = newSeq[byte]()
  let hi = bzGetRaw(rdr, 16).int
  for g in 0 ..< 16:
    if ((hi shr g) and 1) != 0:
      let lo = bzGetRaw(rdr, 16).int
      for j in 0 ..< 16:
        if ((lo shr j) and 1) != 0:
          dict.add(byte(g * 16 + j))
  var numSyms = dict.len + 2
  if numSyms < 3:
    raise newException(Bz2Error, "bzip2: not enough prefix symbols")
  let numTrees = bzGetBE(rdr, 3).int
  if numTrees < bzMinTrees or numTrees > bzMaxTrees:
    raise newException(Bz2Error, "bzip2: invalid number of prefix trees")
  let numSels = bzGetBE(rdr, 15).int
  var treeSels = newSeq[int](numSels)
  for i in 0 ..< numSels:
    let s = bzGetUnary(rdr, bzMaxTrees)
    if s >= numTrees:
      raise newException(Bz2Error, "bzip2: invalid prefix tree selector")
    treeSels[i] = s
  var mtfD = newSeq[byte](numTrees)
  for i in 0 ..< numTrees:
    mtfD[i] = i.byte
  for i in 0 ..< numSels:
    let idx = treeSels[i]
    if idx < 0 or idx >= numTrees:
      raise newException(Bz2Error, "bzip2: selector MTF out of range")
    let v = mtfD[idx]
    if idx > 0:
      for j in countdown(idx, 1):
        mtfD[j] = mtfD[j - 1]
      mtfD[0] = v
    treeSels[i] = v.int
  var decs = newSeq[HuffDec](numTrees)
  for t in 0 ..< numTrees:
    var clen = bzGetBE(rdr, 5).int
    if clen < 1 or clen > bzMaxBits:
      raise newException(Bz2Error, "bzip2: invalid prefix bit-length")
    var lens = newSeq[int](numSyms)
    for s in 0 ..< numSyms:
      while true:
        if bzGetBE(rdr, 1) == 0:
          break
        if bzGetBE(rdr, 1) == 0:
          inc clen
        else:
          dec clen
      if clen < 1 or clen > bzMaxBits:
        raise newException(Bz2Error, "bzip2: invalid prefix bit-length")
      lens[s] = clen
    decs[t] = buildDecode(lens)
  bs.syms.setLen(0)
  var blkLen = 0
  var selIdx = 0
  let blkCap = lvl * bzBlockSize
  while true:
    if blkLen == 0:
      blkLen = bzBlockSyms
      if selIdx >= numSels:
        raise newException(Bz2Error,
          "bzip2: not enough prefix tree selectors")
      inc selIdx
    dec blkLen
    let sym = bzDecodeSym(decs[treeSels[selIdx - 1]], rdr)
    if sym == numSyms - 1:
      break # EOB
    if sym >= numSyms:
      raise newException(Bz2Error, "bzip2: invalid prefix symbol")
    if bs.syms.len >= blkCap:
      raise newException(Bz2Error,
        "bzip2: number of prefix symbols exceeds block size")
    bs.syms.add(sym)
  mtfDecodeSymsReuse(bs.syms, dict, blkCap, bs.vals)
  bwtDecodeReuse(bs.vals, origin, bs.perm, bs.outp)
  var crc = 0xFFFFFFFF'u32
  rle1DecodeInto(bs.vals, scratch, crc)
  if (crc xor 0xFFFFFFFF'u32) != blkCRC:
    raise newException(Bz2Error, "bzip2: mismatching block checksum")
  endCRC = ((endCRC shl 1) or (endCRC shr 31)) xor blkCRC

proc bz2DecompressFile*(srcPath, dstPath: string) =
  ## Streaming file-to-file decompress with bounded memory: 64KB input
  ## buffer + ≤900KB per-block scratch (reused, capped at 1MB), flushed
  ## to disk after each block. No full compressed or uncompressed
  ## holding. Preserves Bz2Error checks (per-block and stream CRCs).
  ## Partial output deleted on failure.
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(Bz2Error, "bzip2: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(Bz2Error, "bzip2: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var rdr = FileBzReader(f: rf, buf: newString(StreamChunkSize),
      bufLen: 0, bitPos: 0, eof: false)
    let scratch = newOutput(MaxScratchCap)
    var bs: BzBlockScratch
    var streams = 0
    while true:
      # Need at least 32 bits to decide: EOF vs next stream magic.
      var haveBits = false
      try:
        bzEnsureBits(rdr, 32)
        haveBits = true
      except Bz2Error:
        haveBits = false
      if not haveBits:
        if streams == 0:
          raise newException(Bz2Error, "bzip2: truncated stream header")
        break
      # Peek 16 bits without consuming for the magic check.
      let bi = rdr.bitPos div 8
      let bb = cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])
      # Ensure the 2 peeked bytes are buffered (they are: >=32 bits).
      let magic16 = (bb[bi].uint64 shl 8) or bb[bi + 1].uint64
      if magic16 != bzHdrMagic.uint64:
        if streams == 0:
          raise newException(Bz2Error, "bzip2: invalid stream magic")
        break
      # Consume "BZh" + version + level.
      discard bzGetBE(rdr, 16)
      let ver = bzGetBE(rdr, 8)
      if ver == uint64('0'):
        raise newException(Bz2Error, "bzip2: bzip1 format is not supported")
      if ver != uint64('h'):
        raise newException(Bz2Error, "bzip2: invalid version")
      let lvl = bzGetBE(rdr, 8).int - '0'.ord
      if lvl < 1 or lvl > 9:
        raise newException(Bz2Error, "bzip2: invalid block size")
      # Pre-size block working sets once per stream (capacities retained
      # across blocks/streams, bounded by the format's 900KB max block):
      # avoids first-block geometric-growth transients.
      let blkCapNow = lvl * bzBlockSize
      if bs.syms.len < blkCapNow:
        bs.syms.setLen(blkCapNow)
        bs.syms.setLen(0)
      if bs.vals.len < blkCapNow:
        bs.vals.setLen(blkCapNow)
        bs.vals.setLen(0)
      if bs.perm.len < blkCapNow:
        bs.perm.setLen(blkCapNow)
        bs.perm.setLen(0)
      if bs.outp.len < blkCapNow:
        bs.outp.setLen(blkCapNow)
        bs.outp.setLen(0)
      var endCRC = 0'u32
      while true:
        resetBounded(scratch)
        var gotFooter = false
        decodeOneBlockFile(rdr, scratch, lvl, endCRC, gotFooter, bs)
        if gotFooter:
          break
        # Flush the decoded block; no window needed (no cross-block refs).
        let ob = outputBytes(scratch)
        var off = 0
        while off < ob.len:
          let n = writeBuffer(wf,
            cast[pointer](cast[int](ob.p) + off), ob.len - off)
          if n <= 0:
            raise newException(Bz2Error, "bzip2: short write")
          off += n
      inc streams
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard
