## LZ4 frame format ported from pierrec/lz4 semantics.
##
## Own block compressor (fast LZ4, 12-bit hash table, forward + backward
## match extension) and decompressor, plus the frame container: magic,
## FLG/BD descriptors, header checksum, stored/compressed blocks,
## EndMark, xxHash32 content verification. Skippable frames are skipped,
## concatenated frames decoded in sequence. Works on `Input`/`Output`:
## no stream objects, no per-call output allocation when the caller
## reuses an Output.

import ./io
import ./simd

type Lz4Error* = object of CatchableError

const
  lz4Magic* = 0x184D2204'u32 ## on-disk bytes 04 22 4D 18 (little-endian)
  lz4SkipLo = 0x184D2A50'u32
  lz4SkipHi = 0x184D2A5F'u32
  lz4BlockMax = 64 * 1024
  lz4MinMatch = 4
  lz4MaxOffset = 0xFFFF
  lz4HashBits = 12
  lz4HashSize = 1 shl lz4HashBits

# ---------- xxHash32 (seed 0), scalar ----------

proc xxh32*(p: pointer; length: int; seed = 0'u32): uint32 =
  ## Standard xxHash32. Safe on empty input (no dereference).
  const P1 = 2654435761'u32
  const P2 = 2246822519'u32
  const P3 = 3266489917'u32
  const P4 = 668265263'u32
  const P5 = 374761393'u32
  let b = cast[ptr UncheckedArray[byte]](p)
  template u32le(off: int): uint32 =
    b[off].uint32 or (b[off + 1].uint32 shl 8) or
      (b[off + 2].uint32 shl 16) or (b[off + 3].uint32 shl 24)
  template rol(x: uint32; r: int): uint32 =
    (x shl r) or (x shr (32 - r))
  template rnd(acc, v: uint32): uint32 =
    rol(acc + v * P2, 13) * P1
  var h: uint32
  var i = 0
  if length >= 16:
    var v1 = seed + P1 + P2
    var v2 = seed + P2
    var v3 = seed
    var v4 = seed - P1
    while i + 16 <= length:
      v1 = rnd(v1, u32le(i)); i += 4
      v2 = rnd(v2, u32le(i)); i += 4
      v3 = rnd(v3, u32le(i)); i += 4
      v4 = rnd(v4, u32le(i)); i += 4
    h = rol(v1, 1) + rol(v2, 7) + rol(v3, 12) + rol(v4, 18)
    # NOTE: XXH32 has no per-lane merge round here (unlike XXH64):
    # the rotated sum feeds straight into the length mix below.
  else:
    h = seed + P5
  h += length.uint32
  while i + 4 <= length:
    h = rol(h + u32le(i) * P3, 17) * P4
    i += 4
  while i < length:
    h = rol(h + b[i].uint32 * P5, 11) * P1
    inc i
  h = (h xor (h shr 15)) * P2
  h = (h xor (h shr 13)) * P3
  h xor (h shr 16)

proc xxh32*(data: string; seed = 0'u32): uint32 =
  if data.len == 0:
    xxh32(nil, 0, seed)
  else:
    xxh32(unsafeAddr data[0], data.len, seed)

# ---------- block codec ----------

proc writeExt(dst: Output; n: int) {.inline.} =
  var k = n
  while k >= 255:
    dst.writeByte(char(255))
    k -= 255
  dst.writeByte(char(k))

proc lz4Hash32(p: pointer; pos: int): int {.inline.} =
  let b = cast[ptr UncheckedArray[byte]](p)
  let v = b[pos].uint32 or (b[pos + 1].uint32 shl 8) or
    (b[pos + 2].uint32 shl 16) or (b[pos + 3].uint32 shl 24)
  ((v * 2654435761'u32) shr (32 - lz4HashBits)).int

proc lz4DecompressBlock*(blk: Span; dst: Output) =
  ## Decompress one raw LZ4 block into `dst`. Raises Lz4Error.
  ## Output may exceed the block size; offsets reach back into all
  ## previously decoded content (dependent blocks supported).
  let b = cast[ptr UncheckedArray[byte]](blk.p)
  var pos = 0
  let n = blk.len
  while pos < n:
    let token = b[pos]
    inc pos
    var litLen = (token shr 4).int
    if litLen == 15:
      while true:
        if pos >= n:
          raise newException(Lz4Error, "lz4: truncated literal length")
        let e = b[pos].int
        inc pos
        litLen += e
        if e != 255:
          break
    if pos + litLen > n:
      raise newException(Lz4Error, "lz4: literals past block end")
    if litLen > 0:
      writeBytes(dst, unsafeAddr b[pos], litLen)
      pos += litLen
    if pos >= n:
      break # trailing literals end the block
    if pos + 2 > n:
      raise newException(Lz4Error, "lz4: truncated offset")
    let offset = b[pos].int or (b[pos + 1].int shl 8)
    pos += 2
    if offset == 0 or offset > lz4MaxOffset:
      raise newException(Lz4Error, "lz4: bad offset")
    let dpos = dst.len
    if offset > dpos:
      raise newException(Lz4Error, "lz4: offset past decoded start")
    var mLen = (token and 0x0F).int + lz4MinMatch
    if (token and 0x0F) == 15:
      while true:
        if pos >= n:
          raise newException(Lz4Error, "lz4: truncated match length")
        let e = b[pos].int
        inc pos
        mLen += e
        if e != 255:
          break
    discard reserve(dst, mLen)
    advance(dst, mLen)
    let ob = outputBytes(dst) # span AFTER growth: stable during copy
    copyMatchSimd(cast[pointer](cast[int](ob.p) + dpos),
      cast[pointer](cast[int](ob.p) + dpos - offset), mLen, offset)

proc lz4CompressBlock*(src: pointer; len: int; dst: Output) =
  ## Fast LZ4 block compressor (hash table + forward/backward match
  ## extension). Emits raw block bytes without any size prefix.
  if len == 0:
    return
  let b = cast[ptr UncheckedArray[byte]](src)
  var table = newSeq[int](lz4HashSize)
  for i in 0 ..< lz4HashSize:
    table[i] = -1
  var anchor = 0
  var pos = 0
  # Parsing restrictions (lz4_Block_format.md): matches may only START at
  # least MFLIMIT (12) bytes before the end, and may only EXTEND to at
  # least LASTLITERALS (5) bytes before the end, so every block ends with
  # a literals-only sequence of >= 5 bytes. Conformant decoders (liblz4)
  # reject blocks that violate this.
  const mflimit = 12
  const lastLits = 5
  while pos + mflimit <= len:
    let h = lz4Hash32(src, pos)
    let cand = table[h]
    table[h] = pos
    if cand >= 0 and pos - cand <= lz4MaxOffset and
        b[cand] == b[pos] and b[cand + 1] == b[pos + 1] and
        b[cand + 2] == b[pos + 2] and b[cand + 3] == b[pos + 3]:
      var c = cand
      var p = pos
      let offset = p - c # fixed before extension; stays positive
      while p > anchor and c > 0 and b[c - 1] == b[p - 1]:
        dec p
        dec c
      let litLen = p - anchor
      let maxTotal = (len - lastLits) - p # never run into the last 5 bytes
      let mLen = min(lz4MinMatch + matchLenSimd(
        cast[pointer](cast[int](src) + c + 4),
        cast[pointer](cast[int](src) + p + 4), len - (p + 4)), maxTotal)
      let tok = byte((min(litLen, 15) shl 4) or min(mLen - lz4MinMatch, 15))
      dst.writeByte(char(tok))
      if litLen >= 15:
        writeExt(dst, litLen - 15)
      if litLen > 0:
        writeBytes(dst, unsafeAddr b[anchor], litLen)
      dst.writeByte(char(offset and 0xFF))
      dst.writeByte(char((offset shr 8) and 0xFF))
      if mLen - lz4MinMatch >= 15:
        writeExt(dst, mLen - lz4MinMatch - 15)
      let newPos = p + mLen
      if newPos - 2 >= 0 and newPos - 2 + lz4MinMatch <= len:
        table[lz4Hash32(src, newPos - 2)] = newPos - 2
      if newPos - 1 >= 0 and newPos - 1 + lz4MinMatch <= len:
        table[lz4Hash32(src, newPos - 1)] = newPos - 1
      anchor = newPos
      pos = newPos
    else:
      inc pos
  let tail = len - anchor
  if tail > 0:
    dst.writeByte(char(min(tail, 15) shl 4))
    if tail >= 15:
      writeExt(dst, tail - 15)
    writeBytes(dst, unsafeAddr b[anchor], tail)

# ---------- frame codec ----------

proc writeU32le(dst: Output; v: uint32) {.inline.} =
  for i in 0 ..< 4:
    dst.writeByte(char((v shr (8 * i)) and 0xFF))

proc readU32le(inp: Input): uint32 =
  let s = readSpan(inp, 4)
  if spanLen(s) != 4:
    raise newException(Lz4Error, "lz4: truncated input")
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint32 or (b[1].uint32 shl 8) or
    (b[2].uint32 shl 16) or (b[3].uint32 shl 24)

proc peekU32le(inp: Input): uint32 =
  ## Caller must ensure at least 4 bytes remain.
  let s = peek(inp, 4)
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint32 or (b[1].uint32 shl 8) or
    (b[2].uint32 shl 16) or (b[3].uint32 shl 24)

proc lz4CompressInto*(inp: Input; dst: Output; level = 0) =
  ## One-shot LZ4 frame compress. `level` accepted for API parity with
  ## Go (fast path always). Writes FLG 0x64 / BD 0x40: independent
  ## blocks, content checksum, 64KB blocks, no content size.
  let total = remaining(inp)
  let base = basePointer(inp)
  let start = inputPos(inp)
  const flg = 0x64'u8
  const bd = 0x40'u8
  dst.writeByte(char(0x04))
  dst.writeByte(char(0x22))
  dst.writeByte(char(0x4D))
  dst.writeByte(char(0x18))
  dst.writeByte(char(flg))
  dst.writeByte(char(bd))
  var desc = [flg, bd]
  dst.writeByte(char((xxh32(addr desc[0], 2) shr 8) and 0xFF))
  let ps = peek(inp, total)
  let contentHash = xxh32(ps.p, ps.len)
  let tmp = newOutput(lz4BlockMax div 4)
  var off = 0
  while off < total:
    let chunkLen = min(lz4BlockMax, total - off)
    reset(tmp)
    lz4CompressBlock(cast[pointer](cast[int](base) + start + off),
      chunkLen, tmp)
    if tmp.len > 0 and tmp.len < chunkLen:
      writeU32le(dst, tmp.len.uint32)
      let ts = outputBytes(tmp)
      writeBytes(dst, ts.p, ts.len)
    else:
      writeU32le(dst, chunkLen.uint32 or 0x80000000'u32)
      writeBytes(dst, cast[pointer](cast[int](base) + start + off),
        chunkLen)
    off += chunkLen
  writeU32le(dst, 0) # EndMark
  writeU32le(dst, contentHash)
  seek(inp, start + total)

proc lz4Compress*(data: string; level = 0): string =
  ## Convenience: compress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput(data.len div 8 + 32)
  lz4CompressInto(inp, dst, level)
  take(dst)

proc lz4DecompressInto*(inp: Input; dst: Output) =
  ## Decompress concatenated LZ4 frames at the cursor into `dst`,
  ## verifying header/block/content checksums. Skippable frames are
  ## skipped. Raises Lz4Error on any corruption.
  if remaining(inp) == 0:
    return
  var frames = 0
  while true:
    if remaining(inp) < 4:
      if frames == 0:
        raise newException(Lz4Error, "lz4: truncated magic")
      break
    let magic = peekU32le(inp)
    if magic >= lz4SkipLo and magic <= lz4SkipHi:
      if remaining(inp) < 8:
        raise newException(Lz4Error, "lz4: truncated skippable frame")
      discard readSpan(inp, 4)
      let sz = readU32le(inp).int
      if remaining(inp) < sz:
        raise newException(Lz4Error, "lz4: truncated skippable frame")
      skip(inp, sz)
      continue
    if magic != lz4Magic:
      if frames == 0:
        raise newException(Lz4Error, "lz4: not an LZ4 frame")
      break
    if remaining(inp) < 7:
      raise newException(Lz4Error, "lz4: truncated header")
    discard readSpan(inp, 4) # magic
    let flg = readByte(inp)
    if (flg.uint8 shr 6) != 1:
      raise newException(Lz4Error, "lz4: unsupported version")
    if (flg.uint8 and 0x02) != 0:
      raise newException(Lz4Error, "lz4: reserved flag set")
    if (flg.uint8 and 0x01) != 0:
      raise newException(Lz4Error, "lz4: dictionary not supported")
    let blockSum = (flg.uint8 and 0x10) != 0
    let hasContentSize = (flg.uint8 and 0x08) != 0
    let hasContentSum = (flg.uint8 and 0x04) != 0
    let bd = readByte(inp)
    if (bd.uint8 and 0x8F) != 0:
      raise newException(Lz4Error, "lz4: reserved BD bits set")
    let blockMaxId = (bd.uint8 shr 4) and 0x07
    if blockMaxId < 4 or blockMaxId > 7:
      raise newException(Lz4Error, "lz4: bad block size id")
    var dbuf: array[14, byte]
    dbuf[0] = flg.uint8
    dbuf[1] = bd.uint8
    var dlen = 2
    var declared: uint64 = 0
    if hasContentSize:
      if remaining(inp) < 8:
        raise newException(Lz4Error, "lz4: truncated content size")
      let cs = readSpan(inp, 8)
      let cb = cast[ptr UncheckedArray[byte]](cs.p)
      for i in 0 ..< 8:
        dbuf[2 + i] = cb[i]
        declared = declared or (cb[i].uint64 shl (8 * i))
      dlen = 10
    if ((xxh32(addr dbuf[0], dlen) shr 8) and 0xFF) != readByte(inp).uint32:
      raise newException(Lz4Error, "lz4: bad header checksum")
    let frameOutStart = dst.len
    while true:
      if remaining(inp) < 4:
        raise newException(Lz4Error, "lz4: truncated block size")
      let rawSize = readU32le(inp)
      if rawSize == 0:
        break # EndMark
      let size = (rawSize and 0x7FFFFFFF'u32).int
      if remaining(inp) < size:
        raise newException(Lz4Error, "lz4: truncated block")
      let blk = readSpan(inp, size)
      if (rawSize and 0x80000000'u32) != 0:
        writeBytes(dst, blk.p, blk.len)
      else:
        lz4DecompressBlock(blk, dst)
      if blockSum:
        if remaining(inp) < 4:
          raise newException(Lz4Error, "lz4: truncated block checksum")
        if xxh32(blk.p, blk.len) != readU32le(inp):
          raise newException(Lz4Error, "lz4: block checksum mismatch")
    let produced = (dst.len - frameOutStart).uint64
    if hasContentSize and declared != produced:
      raise newException(Lz4Error, "lz4: content size mismatch")
    if hasContentSum:
      if remaining(inp) < 4:
        raise newException(Lz4Error, "lz4: truncated content checksum")
      let want = readU32le(inp)
      let ob = outputBytes(dst)
      let got =
        if produced == 0: xxh32(nil, 0)
        else: xxh32(cast[pointer](cast[int](ob.p) + frameOutStart),
          dst.len - frameOutStart)
      if got != want:
        raise newException(Lz4Error, "lz4: content checksum mismatch")
    inc frames
    if remaining(inp) == 0:
      break

proc lz4Decompress*(data: string): string =
  ## Convenience: decompress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  lz4DecompressInto(inp, dst)
  take(dst)
