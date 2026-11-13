## LZMA1 + LZMA2 decoders, clean-room implementation.
##
## Covers the LZMA range coder, literal/match/rep state machines, length
## and distance decoding, and LZMA2 chunk framing (dict resets, unpacked
## chunks, stateful mode). No globals, per-call state only. Passwords and
## caps flow per call. Raises ArchiveError with "7z: ..." messages; the
## 7z container layer re-wraps these as SzError.
##
## Oracle: zesven spec pages (method IDs, properties, filter chaining)
## plus 7z-written fixtures as ground truth. Bitstream details follow the
## public-domain LZMA algorithm (range coder with 11-bit probs).

import ../types

type LzmaError* = object of ArchiveError

const
  lzProbInit = 1024'u16
  lzTopValue = 0x01000000'u32

proc dictSizeFromLzma2Prop*(b: byte): int =
  ## LZMA2 1-byte dict size. 0..39 formula, 40 = 4GiB-1, 41+ rejected.
  let v = int(b)
  if v <= 39:
    let base = 2 + (v and 1)
    let shift = (v div 2) + 11
    base shl shift
  elif v == 40:
    0xFFFFFFFF
  else:
    raise newException(LzmaError, "7z: bad LZMA2 dict property")

proc parseLzma1Props*(props: string): tuple[lc, lp, pb, dict: int] =
  if props.len < 5:
    raise newException(LzmaError, "7z: truncated LZMA props")
  let pb0 = ord(props[0])
  if pb0 > 224:
    raise newException(LzmaError, "7z: bad LZMA props byte")
  let pb = pb0 div 45
  let rem = pb0 - pb * 45
  let lp = rem div 9
  let lc = rem - lp * 9
  if lc > 8 or lp > 4 or pb > 4 or lc + lp > 4:
    raise newException(LzmaError, "7z: bad LZMA lc/lp/pb")
  var d = ord(props[1]) or (ord(props[2]) shl 8) or
    (ord(props[3]) shl 16) or (ord(props[4]) shl 24)
  if d < 4096:
    d = 4096
  # normalize like reference: (size+15) & ~15, clamped later by caller
  d = (d + 15) and (not 15)
  (lc, lp, pb, d)

type RangeDec = object
  data: string
  pos: int
  rng: uint32
  code: uint32

proc rcInit(data: string): RangeDec =
  if data.len < 5:
    raise newException(LzmaError, "7z: truncated lzma stream")
  if ord(data[0]) != 0:
    raise newException(LzmaError, "7z: bad lzma range init")
  let c = (ord(data[1]).uint32 shl 24) or (ord(data[2]).uint32 shl 16) or
    (ord(data[3]).uint32 shl 8) or ord(data[4]).uint32
  RangeDec(data: data, pos: 5, rng: 0xFFFFFFFF'u32, code: c)

proc rcNormalize(rc: var RangeDec) =
  if rc.rng < lzTopValue:
    if rc.pos >= rc.data.len:
      raise newException(LzmaError, "7z: truncated lzma stream")
    rc.code = (rc.code shl 8) or ord(rc.data[rc.pos]).uint32
    inc rc.pos
    rc.rng = rc.rng shl 8

proc rcBit(rc: var RangeDec; prob: var uint16): int {.inline.} =
  let bound = (rc.rng shr 11) * prob.uint32
  if rc.code < bound:
    rc.rng = bound
    prob = prob + ((2048'u16 - prob) shr 5)
    result = 0
  else:
    rc.rng = rc.rng - bound
    rc.code = rc.code - bound
    prob = prob - (prob shr 5)
    result = 1
  rcNormalize(rc)

proc rcBitTree(rc: var RangeDec; probs: var seq[uint16];
    numBits: int; base: int = 0): int {.inline.} =
  ## Forward bit-tree, MSB first. probs[base+1 .. base+(1<<numBits)-1]
  ## used (index 0 unused). Returns value in 0..(1<<numBits)-1.
  var sym = 1
  for _ in 0 ..< numBits:
    let b = rcBit(rc, probs[base + sym])
    sym = (sym shl 1) or b
  sym - (1 shl numBits)

proc rcReverse(rc: var RangeDec; probs: var seq[uint16];
    numBits: int; base: int = 0): int {.inline.} =
  ## Reverse bit-tree, LSB first. Same tree walk, result assembled LE.
  var node = 1
  result = 0
  for i in 0 ..< numBits:
    let b = rcBit(rc, probs[base + node])
    node = (node shl 1) or b
    result = result or (b shl i)

proc rcDirect(rc: var RangeDec; numBits: int): int {.inline.} =
  result = 0
  for _ in 0 ..< numBits:
    rc.rng = rc.rng shr 1
    if rc.code >= rc.rng:
      rc.code = rc.code - rc.rng
      result = (result shl 1) or 1
    else:
      result = result shl 1
    rcNormalize(rc)

type LzmaState = object
  lc, lp, pb: int
  posMask: int
  litPosMask: int
  dictSize: int
  dictBase: int  ## output offset before which matches may not reach
  state: int
  reps: array[4, int]
  isMatch: seq[uint16]    ## 12*16
  isRep: seq[uint16]      ## 12
  isRepG0: seq[uint16]
  isRepG1: seq[uint16]
  isRepG2: seq[uint16]
  isRep0Long: seq[uint16] ## 12*16
  distSlot: seq[uint16]   ## 4*64
  distSpecial: seq[uint16] ## 124
  distAlign: seq[uint16]  ## 16
  lenChoice: seq[uint16]  ## 2
  lenLow: seq[uint16]     ## 16*8
  lenMid: seq[uint16]     ## 16*8
  lenHigh: seq[uint16]    ## 256
  repChoice: seq[uint16]
  repLow: seq[uint16]
  repMid: seq[uint16]
  repHigh: seq[uint16]
  litProbs: seq[uint16]   ## subCount*768

proc initProbs(n: int): seq[uint16] =
  result = newSeq[uint16](n)
  for i in 0 ..< n:
    result[i] = lzProbInit

proc lzmaStateInit(lc, lp, pb, dictSize: int): LzmaState =
  result.lc = lc
  result.lp = lp
  result.pb = pb
  result.posMask = if pb == 0: 0 else: (1 shl pb) - 1
  result.litPosMask = if lp == 0: 0 else: (1 shl lp) - 1
  result.dictSize = dictSize
  result.dictBase = 0
  result.state = 0
  result.reps = [0, 0, 0, 0]
  result.isMatch = initProbs(12 * 16)
  result.isRep = initProbs(12)
  result.isRepG0 = initProbs(12)
  result.isRepG1 = initProbs(12)
  result.isRepG2 = initProbs(12)
  result.isRep0Long = initProbs(12 * 16)
  result.distSlot = initProbs(4 * 64)
  result.distSpecial = initProbs(124)
  result.distAlign = initProbs(16)
  result.lenChoice = initProbs(2)
  result.lenLow = initProbs(16 * 8)
  result.lenMid = initProbs(16 * 8)
  result.lenHigh = initProbs(256)
  result.repChoice = initProbs(2)
  result.repLow = initProbs(16 * 8)
  result.repMid = initProbs(16 * 8)
  result.repHigh = initProbs(256)
  let subCount = 1 shl (lc + lp)
  result.litProbs = initProbs(subCount * 768)

proc resetStateProbs(st: var LzmaState) =
  ## Reset probs/state/reps for LZMA2 reset-state (dict preserved).
  let lc = st.lc
  let lp = st.lp
  let pb = st.pb
  let ds = st.dictSize
  let db = st.dictBase
  let fresh = lzmaStateInit(lc, lp, pb, ds)
  st.state = fresh.state
  st.reps = fresh.reps
  st.isMatch = fresh.isMatch
  st.isRep = fresh.isRep
  st.isRepG0 = fresh.isRepG0
  st.isRepG1 = fresh.isRepG1
  st.isRepG2 = fresh.isRepG2
  st.isRep0Long = fresh.isRep0Long
  st.distSlot = fresh.distSlot
  st.distSpecial = fresh.distSpecial
  st.distAlign = fresh.distAlign
  st.lenChoice = fresh.lenChoice
  st.lenLow = fresh.lenLow
  st.lenMid = fresh.lenMid
  st.lenHigh = fresh.lenHigh
  st.repChoice = fresh.repChoice
  st.repLow = fresh.repLow
  st.repMid = fresh.repMid
  st.repHigh = fresh.repHigh
  st.litProbs = fresh.litProbs
  st.dictBase = db

proc setLcLpPb(st: var LzmaState; lc, lp, pb: int) =
  if lc > 8 or lp > 4 or pb > 4 or lc + lp > 4:
    raise newException(LzmaError, "7z: bad LZMA lc/lp/pb")
  st.lc = lc
  st.lp = lp
  st.pb = pb
  st.posMask = if pb == 0: 0 else: (1 shl pb) - 1
  st.litPosMask = if lp == 0: 0 else: (1 shl lp) - 1
  let subCount = 1 shl (lc + lp)
  st.litProbs = initProbs(subCount * 768)

const distIdxStart = [0, 2, 4, 8, 12, 20, 28, 44, 60, 92]
const distIdxEnd = [2, 4, 8, 12, 20, 28, 44, 60, 92, 124]

proc decodeLen(rc: var RangeDec; st: var LzmaState; posState: int;
    isRep: bool): int =
  var choice = if isRep: st.repChoice else: st.lenChoice
  # NOTE: choice is a copy; write back via index. Use direct access.
  var c0: uint16 = if isRep: st.repChoice[0] else: st.lenChoice[0]
  let b0 = rcBit(rc, c0)
  if isRep: st.repChoice[0] = c0 else: st.lenChoice[0] = c0
  if b0 == 0:
    if isRep:
      result = rcBitTree(rc, st.repLow, 3, posState * 8) + 2
    else:
      result = rcBitTree(rc, st.lenLow, 3, posState * 8) + 2
    return
  var c1: uint16 = if isRep: st.repChoice[1] else: st.lenChoice[1]
  let b1 = rcBit(rc, c1)
  if isRep: st.repChoice[1] = c1 else: st.lenChoice[1] = c1
  if b1 == 0:
    if isRep:
      result = rcBitTree(rc, st.repMid, 3, posState * 8) + 2 + 8
    else:
      result = rcBitTree(rc, st.lenMid, 3, posState * 8) + 2 + 8
  else:
    if isRep:
      result = rcBitTree(rc, st.repHigh, 8, 0) + 2 + 8 + 8
    else:
      result = rcBitTree(rc, st.lenHigh, 8, 0) + 2 + 8 + 8
  discard choice

proc decodeDist(rc: var RangeDec; st: var LzmaState; len: int): int =
  let lenState = if len < 6: len - 2 else: 3
  let slot = rcBitTree(rc, st.distSlot, 6, lenState * 64)
  if slot < 4:
    st.reps[0] = slot
    return slot
  let limit = (slot shr 1) - 1
  var dist = (2 or (slot and 1)) shl limit
  if slot < 14:
    let si = slot - 4
    let sBase = distIdxStart[si]
    dist += rcReverse(rc, st.distSpecial, limit, sBase)
  else:
    dist += rcDirect(rc, limit - 4) shl 4
    dist += rcReverse(rc, st.distAlign, 4, 0)
  st.reps[0] = dist
  dist

proc lzmaDecodeLoop(rc: var RangeDec; st: var LzmaState;
    output: var string; outPos: var int; wantLen: int) =
  ## Decode until outPos reaches wantLen. output must have capacity.
  while outPos < wantLen:
    let posState = if st.posMask == 0: 0 else: outPos and st.posMask
    let imIdx = st.state * 16 + posState
    let bMatch = rcBit(rc, st.isMatch[imIdx])
    if bMatch == 0:
      # literal
      var prevByte = 0
      if outPos > 0:
        prevByte = ord(output[outPos - 1])
      var subIdx2: int
      if st.lc == 0:
        subIdx2 = outPos and st.litPosMask
      else:
        subIdx2 = ((outPos and st.litPosMask) shl st.lc) +
          (prevByte shr (8 - st.lc))
      let litBase = subIdx2 * 768
      var symbol = 1
      if st.state < 7:
        while symbol < 0x100:
          let b = rcBit(rc, st.litProbs[litBase + symbol])
          symbol = (symbol shl 1) or b
      else:
        var matchByte = 0
        if outPos > st.reps[0]:
          matchByte = ord(output[outPos - st.reps[0] - 1])
        else:
          # no valid rep yet: fall back to plain
          while symbol < 0x100:
            let b = rcBit(rc, st.litProbs[litBase + symbol])
            symbol = (symbol shl 1) or b
          output[outPos] = chr(symbol - 0x100)
          inc outPos
          if st.state < 4: st.state = 0
          elif st.state < 10: st.state = st.state - 3
          else: st.state = st.state - 6
          continue
        var mb = matchByte
        var offset = 0x100
        while symbol < 0x100:
          mb = mb shl 1
          let matchBit = mb and offset
          let idx = offset + matchBit + symbol
          let b = rcBit(rc, st.litProbs[litBase + idx])
          symbol = (symbol shl 1) or b
          if ((matchBit != 0) != (b != 0)):
            offset = 0
        # end while
      output[outPos] = chr(symbol - 0x100)
      inc outPos
      if st.state < 4: st.state = 0
      elif st.state < 10: st.state = st.state - 3
      else: st.state = st.state - 6
    else:
      # match or rep
      let bRep = rcBit(rc, st.isRep[st.state])
      if bRep == 0:
        # match: rotate reps, decode len + dist
        st.reps[3] = st.reps[2]
        st.reps[2] = st.reps[1]
        st.reps[1] = st.reps[0]
        let mlen = decodeLen(rc, st, posState, false)
        let dist = decodeDist(rc, st, mlen)
        if st.state < 7: st.state = 7 else: st.state = 10
        # copy
        if dist >= outPos - st.dictBase:
          raise newException(LzmaError, "7z: bad lzma distance")
        if outPos + mlen > wantLen:
          raise newException(LzmaError, "7z: lzma length overflow")
        for _ in 0 ..< mlen:
          output[outPos] = output[outPos - dist - 1]
          inc outPos
      else:
        let bG0 = rcBit(rc, st.isRepG0[st.state])
        if bG0 == 0:
          let rlIdx = st.state * 16 + posState
          let bLong = rcBit(rc, st.isRep0Long[rlIdx])
          if bLong == 0:
            # short rep: len 1, no rotate
            if st.state < 7: st.state = 9 else: st.state = 11
            if st.reps[0] >= outPos - st.dictBase:
              raise newException(LzmaError, "7z: bad lzma distance")
            if outPos + 1 > wantLen:
              raise newException(LzmaError, "7z: lzma length overflow")
            output[outPos] = output[outPos - st.reps[0] - 1]
            inc outPos
          else:
            let mlen = decodeLen(rc, st, posState, true)
            if st.state < 7: st.state = 8 else: st.state = 11
            if st.reps[0] >= outPos - st.dictBase:
              raise newException(LzmaError, "7z: bad lzma distance")
            if outPos + mlen > wantLen:
              raise newException(LzmaError, "7z: lzma length overflow")
            for _ in 0 ..< mlen:
              output[outPos] = output[outPos - st.reps[0] - 1]
              inc outPos
        else:
          let bG1 = rcBit(rc, st.isRepG1[st.state])
          var idx: int
          if bG1 == 0:
            idx = st.reps[1]
          else:
            let bG2 = rcBit(rc, st.isRepG2[st.state])
            if bG2 == 0:
              idx = st.reps[2]
            else:
              idx = st.reps[3]
              st.reps[3] = st.reps[2]
            st.reps[2] = st.reps[1]
          st.reps[1] = st.reps[0]
          st.reps[0] = idx
          let mlen = decodeLen(rc, st, posState, true)
          if st.state < 7: st.state = 8 else: st.state = 11
          if st.reps[0] >= outPos - st.dictBase:
            raise newException(LzmaError, "7z: bad lzma distance")
          if outPos + mlen > wantLen:
            raise newException(LzmaError, "7z: lzma length overflow")
          for _ in 0 ..< mlen:
            output[outPos] = output[outPos - st.reps[0] - 1]
            inc outPos

proc lzma1Decode*(props: string; pack: string; outLen: int;
    maxDict: int): string =
  ## One-shot LZMA1 (for 03 01 01 folders). outLen from unpackSize.
  if outLen < 0:
    raise newException(LzmaError, "7z: bad unpack size")
  if maxDict != 0 and outLen > 4 * 1024 * 1024 * 1024:
    raise newException(LzmaError, "7z: entry exceeds unpack cap")
  let (lc, lp, pb, dict) = parseLzma1Props(props)
  if maxDict != 0 and dict > maxDict:
    raise newException(LzmaError, "7z: lzma dict exceeds cap")
  if outLen == 0:
    return ""
  result = newString(outLen)
  var st = lzmaStateInit(lc, lp, pb, dict)
  var rc = rcInit(pack)
  var pos = 0
  lzmaDecodeLoop(rc, st, result, pos, outLen)
  if pos != outLen:
    raise newException(LzmaError, "7z: lzma short output")

proc lzma2Decode*(pack: string; unpackSize: int; dictProp: byte;
    maxDict: int): string =
  ## LZMA2 stream decode. dictProp is the folder's 1-byte dict size.
  let dictSize = dictSizeFromLzma2Prop(dictProp)
  if maxDict != 0 and dictSize > maxDict:
    raise newException(LzmaError, "7z: lzma dict exceeds cap")
  if maxDict != 0 and unpackSize > 4 * 1024 * 1024 * 1024:
    raise newException(LzmaError, "7z: entry exceeds unpack cap")
  if unpackSize == 0:
    if pack.len == 1 and ord(pack[0]) == 0:
      return ""
    if pack.len == 0:
      return ""
    raise newException(LzmaError, "7z: bad empty lzma2 stream")
  result = newString(unpackSize)
  var outPos = 0
  var st = lzmaStateInit(3, 0, 2, dictSize)
  var haveState = false
  var pos = 0
  while true:
    if pos >= pack.len:
      raise newException(LzmaError, "7z: truncated lzma2 stream")
    let ctrl = ord(pack[pos])
    inc pos
    if ctrl == 0:
      break
    elif ctrl == 1 or ctrl == 2:
      if pos + 2 > pack.len:
        raise newException(LzmaError, "7z: truncated lzma2 chunk")
      let sz = (ord(pack[pos]) shl 8) or ord(pack[pos + 1])
      pos += 2
      let chunkLen = sz + 1
      if pos + chunkLen > pack.len:
        raise newException(LzmaError, "7z: truncated lzma2 chunk")
      if ctrl == 1:
        st.dictBase = outPos
      if outPos + chunkLen > unpackSize:
        raise newException(LzmaError, "7z: lzma2 unpack overflow")
      for i in 0 ..< chunkLen:
        result[outPos] = pack[pos]
        inc outPos
        inc pos
      # unpacked chunks leave LZMA probs/state alone
    elif ctrl >= 0x80:
      let resetDict = ctrl >= 0xE0
      let newProps = ctrl >= 0xC0
      let resetState = ctrl >= 0xA0
      if pos + 4 > pack.len:
        raise newException(LzmaError, "7z: truncated lzma2 chunk")
      let upLow = (ord(pack[pos]) shl 8) or ord(pack[pos + 1])
      let packHi = ord(pack[pos + 2])
      let packLo = ord(pack[pos + 3])
      pos += 4
      let chunkOut = ((ctrl and 0x1F) shl 16) or upLow
      let want = chunkOut + 1
      let packSize = (packHi shl 8) or packLo
      let have = packSize + 1
      if newProps:
        if pos >= pack.len:
          raise newException(LzmaError, "7z: truncated lzma2 props")
        let pb0 = ord(pack[pos])
        inc pos
        if pb0 > 224:
          raise newException(LzmaError, "7z: bad LZMA props byte")
        let npb = pb0 div 45
        let nrem = pb0 - npb * 45
        let nlp = nrem div 9
        let nlc = nrem - nlp * 9
        st.setLcLpPb(nlc, nlp, npb)
        if resetState or resetDict:
          st.resetStateProbs()
        haveState = true
      else:
        if not haveState and outPos == 0:
          raise newException(LzmaError, "7z: lzma2 missing props")
        if resetState or resetDict:
          st.resetStateProbs()
      if resetDict:
        st.dictBase = outPos
      if pos + have > pack.len:
        raise newException(LzmaError, "7z: truncated lzma2 chunk")
      let payload = pack[pos ..< pos + have]
      pos += have
      if outPos + want > unpackSize:
        raise newException(LzmaError, "7z: lzma2 unpack overflow")
      # decode `want` bytes from payload into result at outPos
      var rc = rcInit(payload)
      var p = outPos
      let target = outPos + want
      lzmaDecodeLoop(rc, st, result, p, target)
      if p != target:
        raise newException(LzmaError, "7z: lzma2 short chunk")
      outPos = target
      haveState = true
    else:
      raise newException(LzmaError, "7z: bad lzma2 control byte")
  if outPos != unpackSize:
    raise newException(LzmaError, "7z: lzma2 size mismatch")
