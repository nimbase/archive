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
import std/strutils
from std/os import removeFile

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

const
  xxhP1 = 2654435761'u32
  xxhP2 = 2246822519'u32
  xxhP3 = 3266489917'u32
  xxhP4 = 668265263'u32
  xxhP5 = 374761393'u32

type Xxh32Stream* = object
  ## Streaming xxHash32 (seed 0) for bounded content verification.
  ## Fixed 16-byte tail buffer; peak stays constant regardless of
  ## frame size. Digest matches one-shot xxh32 over the same bytes.
  total: uint64
  v1, v2, v3, v4: uint32
  mem: array[16, byte]
  memsize: int

proc xxh32Init*(): Xxh32Stream =
  result.total = 0
  result.v1 = xxhP1 + xxhP2
  result.v2 = xxhP2
  result.v3 = 0
  result.v4 = 0 - xxhP1
  result.memsize = 0

template xxhRol(x: uint32; r: int): uint32 =
  (x shl r) or (x shr (32 - r))

template xxhRnd(acc, v: uint32): uint32 =
  xxhRol(acc + v * xxhP2, 13) * xxhP1

proc xxh32Update*(s: var Xxh32Stream; p: pointer; len: int) =
  ## Feed `len` bytes. Safe on empty input (nil with 0 length skipped).
  if len <= 0:
    return
  let b = cast[ptr UncheckedArray[byte]](p)
  var off = 0
  var left = len
  s.total += len.uint64
  if s.memsize + left < 16:
    for i in 0 ..< left:
      s.mem[s.memsize + i] = b[off + i]
    s.memsize += left
    return
  if s.memsize > 0:
    let need = 16 - s.memsize
    for i in 0 ..< need:
      s.mem[s.memsize + i] = b[off + i]
    off += need
    left -= need
    s.v1 = xxhRnd(s.v1, s.mem[0].uint32 or (s.mem[1].uint32 shl 8) or
      (s.mem[2].uint32 shl 16) or (s.mem[3].uint32 shl 24))
    s.v2 = xxhRnd(s.v2, s.mem[4].uint32 or (s.mem[5].uint32 shl 8) or
      (s.mem[6].uint32 shl 16) or (s.mem[7].uint32 shl 24))
    s.v3 = xxhRnd(s.v3, s.mem[8].uint32 or (s.mem[9].uint32 shl 8) or
      (s.mem[10].uint32 shl 16) or (s.mem[11].uint32 shl 24))
    s.v4 = xxhRnd(s.v4, s.mem[12].uint32 or (s.mem[13].uint32 shl 8) or
      (s.mem[14].uint32 shl 16) or (s.mem[15].uint32 shl 24))
    s.memsize = 0
  while left >= 16:
    s.v1 = xxhRnd(s.v1, b[off].uint32 or (b[off + 1].uint32 shl 8) or
      (b[off + 2].uint32 shl 16) or (b[off + 3].uint32 shl 24))
    s.v2 = xxhRnd(s.v2, b[off + 4].uint32 or (b[off + 5].uint32 shl 8) or
      (b[off + 6].uint32 shl 16) or (b[off + 7].uint32 shl 24))
    s.v3 = xxhRnd(s.v3, b[off + 8].uint32 or (b[off + 9].uint32 shl 8) or
      (b[off + 10].uint32 shl 16) or (b[off + 11].uint32 shl 24))
    s.v4 = xxhRnd(s.v4, b[off + 12].uint32 or (b[off + 13].uint32 shl 8) or
      (b[off + 14].uint32 shl 16) or (b[off + 15].uint32 shl 24))
    off += 16
    left -= 16
  for i in 0 ..< left:
    s.mem[i] = b[off + i]
  s.memsize = left

proc xxh32Digest*(s: Xxh32Stream): uint32 =
  ## Finalize. Matches one-shot xxh32 over the fed bytes (seed 0).
  var h: uint32
  if s.total >= 16:
    h = xxhRol(s.v1, 1) + xxhRol(s.v2, 7) + xxhRol(s.v3, 12) + xxhRol(s.v4, 18)
  else:
    h = xxhP5
  h += s.total.uint32
  var i = 0
  while i + 4 <= s.memsize:
    let v = s.mem[i].uint32 or (s.mem[i + 1].uint32 shl 8) or
      (s.mem[i + 2].uint32 shl 16) or (s.mem[i + 3].uint32 shl 24)
    h = xxhRol(h + v * xxhP3, 17) * xxhP4
    i += 4
  while i < s.memsize:
    h = xxhRol(h + s.mem[i].uint32 * xxhP5, 11) * xxhP1
    inc i
  h = (h xor (h shr 15)) * xxhP2
  h = (h xor (h shr 13)) * xxhP3
  h xor (h shr 16)

const
  lz4FileWindow = 65536
    ## Max LZ4 match distance: retain this much history across flushes.
  lz4FileBufCap = 131072
    ## Fixed output scratch (64KB working + 64KB window), reused.
  lz4InBufCap = 65536
    ## Fixed compressed-input buffer, reused.

type Lz4FileReader = object
  ## Byte-aligned buffered file reader for frame parsing. Owns a fixed
  ## 64KB buffer; leftover bytes preserved across blocks/frames.
  f: File
  buf: string
  bufLen, pos: int
  eof: bool

proc lz4Refill(rdr: var Lz4FileReader) =
  if rdr.pos < rdr.bufLen:
    let unread = rdr.bufLen - rdr.pos
    if rdr.pos > 0:
      moveMem(addr rdr.buf[0], addr rdr.buf[rdr.pos], unread)
    rdr.bufLen = unread
    rdr.pos = 0
  else:
    rdr.bufLen = 0
    rdr.pos = 0
  if not rdr.eof:
    let free = rdr.buf.len - rdr.bufLen
    if free > 0:
      let n = readBuffer(rdr.f, addr rdr.buf[rdr.bufLen], free)
      if n <= 0:
        rdr.eof = true
      else:
        rdr.bufLen += n

proc lz4Ensure(rdr: var Lz4FileReader; n: int) =
  while rdr.bufLen - rdr.pos < n:
    let beforeLen = rdr.bufLen
    let beforePos = rdr.pos
    let beforeEof = rdr.eof
    lz4Refill(rdr)
    if rdr.bufLen - rdr.pos < n:
      if rdr.eof:
        raise newException(Lz4Error, "lz4: truncated input")
      if rdr.bufLen == beforeLen and rdr.pos == beforePos and
          rdr.eof == beforeEof:
        raise newException(Lz4Error, "lz4: truncated input")

proc lz4GetByte(rdr: var Lz4FileReader): byte =
  lz4Ensure(rdr, 1)
  result = cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[rdr.pos]
  inc rdr.pos

proc lz4Skip(rdr: var Lz4FileReader; n: int) =
  var left = n
  while left > 0:
    if rdr.pos >= rdr.bufLen:
      lz4Refill(rdr)
      if rdr.pos >= rdr.bufLen:
        raise newException(Lz4Error, "lz4: truncated input")
      continue
    let avail = min(left, rdr.bufLen - rdr.pos)
    rdr.pos += avail
    left -= avail

proc lz4ReadU32le(rdr: var Lz4FileReader): uint32 =
  let b0 = lz4GetByte(rdr).uint32
  let b1 = lz4GetByte(rdr).uint32
  let b2 = lz4GetByte(rdr).uint32
  let b3 = lz4GetByte(rdr).uint32
  b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)

proc lz4HasData(rdr: var Lz4FileReader): bool =
  ## True when buffered or file bytes remain.
  if rdr.pos < rdr.bufLen:
    return true
  if rdr.eof:
    return false
  lz4Refill(rdr)
  rdr.pos < rdr.bufLen

proc lz4DecompressFile*(srcPath, dstPath: string) =
  ## Streaming file-to-file decompress with bounded memory: 64KB input
  ## buffer + 128KB output window (64KB working + 64KB history for
  ## dependent blocks), reused across all blocks. Handles any block
  ## size id (64KB..4MB) via token streaming — never holds a full block
  ## or frame. Verifies header/block/content checksums (streaming
  ## xxHash32). Partial output deleted on failure.
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(Lz4Error, "lz4: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(Lz4Error, "lz4: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var rdr = Lz4FileReader(f: rf, buf: newString(lz4InBufCap),
      bufLen: 0, pos: 0, eof: false)
    let scratch = newOutput(lz4FileBufCap)
    var frames = 0
    while true:
      if not lz4HasData(rdr):
        if frames == 0:
          raise newException(Lz4Error, "lz4: truncated input")
        break
      # Peek magic without consuming trailing garbage on break paths:
      # read it (consumed either way); non-frame trailing after >=1
      # frame is ignored, matching the mmap version.
      var magic: uint32
      try:
        magic = lz4ReadU32le(rdr)
      except Lz4Error:
        if frames == 0:
          raise newException(Lz4Error, "lz4: truncated input")
        break
      if magic >= lz4SkipLo and magic <= lz4SkipHi:
        var sz: uint32
        try:
          sz = lz4ReadU32le(rdr)
        except Lz4Error:
          raise newException(Lz4Error, "lz4: truncated skippable frame")
        try:
          lz4Skip(rdr, sz.int)
        except Lz4Error:
          raise newException(Lz4Error, "lz4: truncated skippable frame")
        continue
      if magic != lz4Magic:
        if frames == 0:
          raise newException(Lz4Error, "lz4: not an LZ4 frame")
        break
      # Frame header.
      var flg, bd: byte
      try:
        flg = lz4GetByte(rdr)
        if (flg and 0x40) shr 6 != 1:
          raise newException(Lz4Error, "lz4: unsupported version")
        if (flg and 0x02) != 0:
          raise newException(Lz4Error, "lz4: reserved flag set")
        if (flg and 0x01) != 0:
          raise newException(Lz4Error, "lz4: dictionary not supported")
        bd = lz4GetByte(rdr)
        if (bd and 0x8F) != 0:
          raise newException(Lz4Error, "lz4: reserved BD bits set")
      except Lz4Error as e:
        if e.msg.startsWith("lz4:"):
          raise
        raise newException(Lz4Error, "lz4: truncated header")
      except CatchableError:
        raise newException(Lz4Error, "lz4: truncated header")
      let blockSum = (flg and 0x10) != 0
      let hasContentSize = (flg and 0x08) != 0
      let hasContentSum = (flg and 0x04) != 0
      let blockMaxId = (bd shr 4) and 0x07
      if blockMaxId < 4 or blockMaxId > 7:
        raise newException(Lz4Error, "lz4: bad block size id")
      var dbuf: array[14, byte]
      dbuf[0] = flg
      dbuf[1] = bd
      var dlen = 2
      var declared: uint64 = 0
      if hasContentSize:
        try:
          for i in 0 ..< 8:
            let b = lz4GetByte(rdr)
            dbuf[2 + i] = b
            declared = declared or (b.uint64 shl (8 * i))
          dlen = 10
        except Lz4Error:
          raise newException(Lz4Error, "lz4: truncated content size")
      var hc: byte
      try:
        hc = lz4GetByte(rdr)
      except Lz4Error:
        raise newException(Lz4Error, "lz4: truncated header")
      if ((xxh32(addr dbuf[0], dlen) shr 8) and 0xFF) != hc.uint32:
        raise newException(Lz4Error, "lz4: bad header checksum")
      # Blocks for this frame.
      var contentHash = xxh32Init()
      var produced: uint64 = 0

      template outNeed(n: int) =
        if scratch.len + n > lz4FileBufCap:
          let toWrite = scratch.len - lz4FileWindow
          if toWrite > 0:
            xxh32Update(contentHash, outputBaseAddr(scratch), toWrite)
          produced += flushKeepWindowNoCrc(scratch, wf,
            lz4FileWindow).uint64

      template outFlush() =
        if scratch.len >= lz4InBufCap + lz4FileWindow:
          let toWrite = scratch.len - lz4FileWindow
          if toWrite > 0:
            xxh32Update(contentHash, outputBaseAddr(scratch), toWrite)
          produced += flushKeepWindowNoCrc(scratch, wf,
            lz4FileWindow).uint64

      # Per-block compressed bytes also feed the optional block
      # checksum: track via a second streaming hash reset per block.
      var blkHash = xxh32Init()
      var blkHashing = false
      template inByte(): byte =
        block:
          let b = lz4GetByte(rdr)
          if blkHashing:
            xxh32Update(blkHash, unsafeAddr b, 1)
          b
      template inSkip(n: int) =
        # Skip without hashing (used only outside checksummed regions;
        # block bodies always go through inByte/inCopy for hashing).
        lz4Skip(rdr, n)
      template inCopy(n: int) =
        # Copy n block bytes to output (literals/stored data): feeds
        # block hash and writes through the windowed scratch.
        var left = n
        while left > 0:
          if rdr.pos >= rdr.bufLen:
            lz4Refill(rdr)
            if rdr.pos >= rdr.bufLen:
              raise newException(Lz4Error, "lz4: truncated block")
            continue
          let avail = min(left, rdr.bufLen - rdr.pos)
          if blkHashing:
            xxh32Update(blkHash, addr rdr.buf[rdr.pos], avail)
          outNeed(avail)
          writeBytes(scratch, addr rdr.buf[rdr.pos], avail)
          rdr.pos += avail
          left -= avail
          outFlush()

      while true:
        var rawSize: uint32
        try:
          rawSize = lz4ReadU32le(rdr)
        except Lz4Error:
          raise newException(Lz4Error, "lz4: truncated block size")
        if rawSize == 0:
          break # EndMark
        let size = (rawSize and 0x7FFFFFFF'u32).int
        let stored = (rawSize and 0x80000000'u32) != 0
        blkHash = xxh32Init()
        blkHashing = blockSum
        # Feed the 4 size bytes themselves? No: checksum covers the
        # block content only (matches mmap version xxh32(blk.p, blk.len)
        # over the size-stripped payload).
        if stored:
          # Stored (uncompressed) block: stream payload to output.
          var left = size
          while left > 0:
            if rdr.pos >= rdr.bufLen:
              lz4Refill(rdr)
              if rdr.pos >= rdr.bufLen:
                raise newException(Lz4Error, "lz4: truncated block")
              continue
            let avail = min(left, rdr.bufLen - rdr.pos)
            if blkHashing:
              xxh32Update(blkHash, addr rdr.buf[rdr.pos], avail)
            outNeed(avail)
            writeBytes(scratch, addr rdr.buf[rdr.pos], avail)
            rdr.pos += avail
            left -= avail
            outFlush()
        else:
          # Compressed block: token streaming; budget tracks the
          # exact compressed size so overruns are detected.
          var budget = size
          template takeByte(): byte =
            block:
              if budget <= 0:
                raise newException(Lz4Error, "lz4: block overrun")
              let b = inByte()
              dec budget
              b
          while budget > 0:
            let token = takeByte()
            var litLen = (token shr 4).int
            if litLen == 15:
              while true:
                let e = takeByte().int
                litLen += e
                if e != 255:
                  break
            if litLen > 0:
              if litLen > budget:
                raise newException(Lz4Error, "lz4: literals past block end")
              inCopy(litLen)
              budget -= litLen
            if budget == 0:
              break # trailing literals end the block
            # Match: 2-byte LE offset + optional extended length.
            if budget < 2:
              raise newException(Lz4Error, "lz4: truncated offset")
            let lo = takeByte().int
            let hi = takeByte().int
            let offset = lo or (hi shl 8)
            if offset == 0 or offset > lz4MaxOffset:
              raise newException(Lz4Error, "lz4: bad offset")
            let dpos = scratch.len
            if offset > dpos:
              raise newException(Lz4Error, "lz4: offset past decoded start")
            var mLen = (token and 0x0F).int + lz4MinMatch
            if (token and 0x0F) == 15:
              while true:
                let e = takeByte().int
                mLen += e
                if e != 255:
                  break
            # Chunk long matches so scratch never exceeds its cap.
            var mLeft = mLen
            while mLeft > 0:
              let piece = min(mLeft, lz4InBufCap)
              outNeed(piece)
              discard reserve(scratch, piece)
              advance(scratch, piece)
              let ob = outputBytes(scratch)
              copyMatchSimd(
                cast[pointer](cast[int](ob.p) + dpos + (mLen - mLeft)),
                cast[pointer](cast[int](ob.p) + dpos + (mLen - mLeft) - offset),
                piece, offset)
              mLeft -= piece
              outFlush()
          if budget != 0:
            raise newException(Lz4Error, "lz4: block overrun")
        if blockSum:
          var wantBlk: uint32
          try:
            wantBlk = lz4ReadU32le(rdr)
          except Lz4Error:
            raise newException(Lz4Error, "lz4: truncated block checksum")
          if xxh32Digest(blkHash) != wantBlk:
            raise newException(Lz4Error, "lz4: block checksum mismatch")
      # End of blocks: flush window remainder for the frame.
      let tail = scratch.len
      if tail > 0:
        xxh32Update(contentHash, outputBaseAddr(scratch), tail)
      produced += flushAllNoCrc(scratch, wf).uint64
      if hasContentSize and declared != produced:
        raise newException(Lz4Error, "lz4: content size mismatch")
      if hasContentSum:
        var want: uint32
        try:
          want = lz4ReadU32le(rdr)
        except Lz4Error:
          raise newException(Lz4Error, "lz4: truncated content checksum")
        if xxh32Digest(contentHash) != want:
          raise newException(Lz4Error, "lz4: content checksum mismatch")
      inc frames
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard
