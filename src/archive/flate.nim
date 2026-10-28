## DEFLATE (RFC 1951) ported from Go compress/flate.
##
## Inflate supports all block types: stored, fixed Huffman and dynamic
## Huffman. Deflate emits stored-empty plus fixed-Huffman blocks with a
## hash-chain LZ77 matcher. All entry points work on raw pointers and
## reusable `Output` buffers: no stream objects, no per-call output
## allocation when the caller reuses an Output. Match copies and match
## search use archive/simd kernels when the `nimsimd` feature is on.

import ./io
import ./simd

type FlateError* = object of CatchableError

# ---------- bit reader (LSB-first, pointer based) ----------

type BitReader = object
  p: pointer
  len: int # bytes available
  bitPos: int

proc getBits(br: var BitReader; n: int): int {.inline.} =
  ## Read n bits LSB-first. Raises FlateError on truncation.
  result = 0
  for i in 0 ..< n:
    let p = br.bitPos + i
    if p div 8 >= br.len:
      raise newException(FlateError, "flate: truncated input")
    if (cast[ptr UncheckedArray[byte]](br.p)[p div 8] and
        byte(1 shl (p mod 8))) != 0:
      result = result or (1 shl i)
  br.bitPos += n

proc alignToByte(br: var BitReader) {.inline.} =
  br.bitPos = (br.bitPos + 7) and not 7

proc readRawSpan(br: var BitReader; n: int): Span {.inline.} =
  ## Borrowed view of n raw bytes (stored blocks: zero-copy).
  br.alignToByte()
  let start = br.bitPos div 8
  if start + n > br.len:
    raise newException(FlateError, "flate: truncated stored block")
  result = Span(p: cast[pointer](cast[int](br.p) + start), len: n)
  br.bitPos += n * 8

# ---------- canonical Huffman decoder (zlib-style ranges) ----------

type HuffDec = object
  counts: array[16, int] # counts[len] for len 1..15
  symbols: seq[int]      # symbols sorted by (len, symbol)
  maxLen: int

proc initHuffDec(lengths: openArray[int]): HuffDec =
  for l in lengths:
    if l < 0 or l > 15:
      raise newException(FlateError, "flate: bad code length")
    if l > 0:
      result.counts[l] += 1
      if l > result.maxLen:
        result.maxLen = l
  for l in 1 .. 15:
    for sym, ll in lengths:
      if ll == l:
        result.symbols.add(sym)

proc decode(d: HuffDec; br: var BitReader): int {.inline.} =
  ## Decode one symbol. Wire bits accumulate MSB-first; canonical codes
  ## of equal length are consecutive, so the classic first/index range
  ## walk applies (equivalent to Go's reversed-code chunk tables).
  var code = 0
  var first = 0
  var index = 0
  for length in 1 .. d.maxLen:
    code = (code shl 1) or getBits(br, 1)
    let count = d.counts[length]
    if code - first < count:
      return d.symbols[index + (code - first)]
    index += count
    first = (first + count) shl 1
  raise newException(FlateError, "flate: invalid huffman code")

# ---------- length / distance base tables (RFC 1951 3.2.5) ----------

const
  lenBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
  lenExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3,
    3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
  distBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
    16385, 24577]
  distExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
    8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

proc fixedLitLengths(): array[288, int] =
  for i in 0 .. 143:
    result[i] = 8
  for i in 144 .. 255:
    result[i] = 9
  for i in 256 .. 279:
    result[i] = 7
  for i in 280 .. 287:
    result[i] = 8

proc fixedDistLengths(): array[32, int] =
  for i in 0 .. 31:
    result[i] = 5

# Fixed tables are built per use (cheap: a few hundred iterations)
# so every flate entry point stays GC-safe for Stream impls.
# Module-level `let` tables would break gcsafe.

proc fixedLitDec(): HuffDec = initHuffDec(fixedLitLengths())
proc fixedDistDec(): HuffDec = initHuffDec(fixedDistLengths())

# ---------- output helpers (direct into reusable Output) ----------

proc putByte(dst: Output; c: byte) {.inline.} =
  let w = reserve(dst, 1)
  cast[ptr UncheckedArray[byte]](w)[0] = c
  advance(dst, 1)

proc putSpan(dst: Output; s: Span) {.inline.} =
  if s.len > 0:
    writeBytes(dst, s.p, s.len)

proc putMatch(dst: Output; dist, length: int) {.inline.} =
  ## Overlap-safe match copy from already-written bytes.
  let dpos = dst.len
  let src = dpos - dist
  if dist <= 0 or src < 0:
    raise newException(FlateError, "flate: distance too far back")
  discard reserve(dst, length)
  advance(dst, length)
  let ob = outputBytes(dst) # span AFTER growth: stable during copy
  copyMatchSimd(cast[pointer](cast[int](ob.p) + dpos),
    cast[pointer](cast[int](ob.p) + src), length, dist)

# ---------- block decoding ----------

proc decodeBlock(br: var BitReader; lit, dist: HuffDec; output: Output) =
  while true:
    let sym = decode(lit, br)
    if sym < 256:
      putByte(output, byte(sym))
    elif sym == 256:
      return
    else:
      let li = sym - 257
      if li < 0 or li > 28:
        raise newException(FlateError, "flate: bad length code")
      let length = lenBase[li] + getBits(br, lenExtra[li])
      let dsym = decode(dist, br)
      if dsym < 0 or dsym > 29:
        raise newException(FlateError, "flate: bad distance code")
      let distance = distBase[dsym] + getBits(br, distExtra[dsym])
      putMatch(output, distance, length)

const clOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
  14, 1, 15]

proc readDynamicTables(br: var BitReader): tuple[lit, dist: HuffDec] =
  let hlit = getBits(br, 5) + 257
  let hdist = getBits(br, 5) + 1
  let hclen = getBits(br, 4) + 4
  var clLens = newSeq[int](19)
  for i in 0 ..< hclen:
    clLens[clOrder[i]] = getBits(br, 3)
  let cl = initHuffDec(clLens)
  let total = hlit + hdist
  var lens = newSeq[int](total)
  var i = 0
  while i < total:
    let sym = decode(cl, br)
    case sym
    of 0 .. 15:
      lens[i] = sym
      inc i
    of 16:
      if i == 0:
        raise newException(FlateError, "flate: repeat with no previous")
      let rep = getBits(br, 2) + 3
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = lens[i - 1]
        inc i
    of 17:
      let rep = getBits(br, 3) + 3
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = 0
        inc i
    of 18:
      let rep = getBits(br, 7) + 11
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = 0
        inc i
    else:
      raise newException(FlateError, "flate: bad code-length code")
  let lit = initHuffDec(lens[0 ..< hlit])
  let dist =
    if hdist == 1 and lens[hlit] == 0:
      initHuffDec(newSeq[int](1))
    else:
      initHuffDec(lens[hlit ..< total])
  (lit, dist)

proc inflateBlocks(br: var BitReader; output: Output) =
  var done = false
  while not done:
    done = getBits(br, 1) == 1
    let btype = getBits(br, 2)
    case btype
    of 0: # stored: zero-copy straight into output
      br.alignToByte()
      let length = getBits(br, 16)
      let inv = getBits(br, 16)
      if (length xor 0xFFFF) != inv:
        raise newException(FlateError, "flate: stored length mismatch")
      putSpan(output, readRawSpan(br, length))
    of 1: # fixed Huffman
      decodeBlock(br, fixedLitDec(), fixedDistDec(), output)
    of 2: # dynamic Huffman
      let (lit, dist) = readDynamicTables(br)
      decodeBlock(br, lit, dist, output)
    else:
      raise newException(FlateError, "flate: reserved block type")

proc inflateStreamPtr*(base: pointer; totalLen, startBit: int;
    output: Output): int =
  ## Decompress one DEFLATE member; return the bit offset just past it.
  var br = BitReader(p: base, len: totalLen, bitPos: startBit)
  inflateBlocks(br, output)
  br.bitPos

proc inflateInto*(inp: Input; output: Output) =
  ## Decompress the stream at the cursor into `output` (reused buffer),
  ## advancing the cursor past the final block (callers round the bit
  ## offset up for trailers).
  let endBit = inflateStreamPtr(basePointer(inp), inputLen(inp),
    inputPos(inp) * 8, output)
  seek(inp, (endBit + 7) div 8)

proc inflateIntoFile*(inp: Input; f: File; scratch: Output):
    tuple[bytes: int, crc: uint32] =
  ## Streaming inflate directly to a file with bounded memory.
  ## `scratch` is a reusable buffer capped at StreamBufCap (~96KB);
  ## only a 32KB window is retained across flushes so matches stay
  ## valid. Returns (bytes written, IEEE CRC32). Raises FlateError on
  ## corruption, IoError on short writes. Advances `inp` past the
  ## deflate stream like inflateInto.
  ## No intermediate full-output buffer: peak heap is the fixed scratch
  ## plus tiny Huffman tables, not the uncompressed size.
  ensureFixedCap(scratch, StreamBufCap)
  # Caller reuses scratch across entries; start each entry empty.
  # Defensive: if a previous error left data, flush it out first would
  # corrupt the new file, so require empty (resetBounded between entries).
  if scratch.len != 0:
    resetBounded(scratch)
  var crc: uint32 = 0xFFFFFFFF'u32
  var total = 0
  var br = BitReader(p: basePointer(inp), len: inputLen(inp),
    bitPos: inputPos(inp) * 8)
  # Input page release: consumed compressed prefix is never re-read
  # (BitReader moves strictly forward), so drop it in 1MB chunks to
  # keep RSS bounded even for a single huge entry.
  let inBase = basePointer(inp)
  var releasedUpTo = 0

  template needRoom(n: int) =
    if scratch.len + n > StreamBufCap:
      flushKeepWindow(scratch, f, StreamWindowSize, crc, total)

  template maybeFlush() =
    if scratch.len >= StreamChunkSize + StreamWindowSize:
      flushKeepWindow(scratch, f, StreamWindowSize, crc, total)

  template maybeReleaseInput() =
    let byteIdx = br.bitPos div 8
    let pageEnd = byteIdx and not 4095
    if pageEnd - releasedUpTo >= ReleaseGranularity:
      let p = cast[pointer](cast[int](inBase) + releasedUpTo)
      releaseSpanPages(Span(p: p, len: pageEnd - releasedUpTo))
      releasedUpTo = pageEnd

  var done = false
  while not done:
    done = getBits(br, 1) == 1
    let btype = getBits(br, 2)
    case btype
    of 0: # stored: zero-copy from input, chunked through scratch
      br.alignToByte()
      let length = getBits(br, 16)
      let inv = getBits(br, 16)
      if (length xor 0xFFFF) != inv:
        raise newException(FlateError, "flate: stored length mismatch")
      let span = readRawSpan(br, length)
      # Route through scratch in bounded pieces so the window stays
      # valid for later matches; never holds the whole stored block
      # beyond StreamBufCap.
      var off = 0
      while off < span.len:
        let piece = min(span.len - off, StreamChunkSize)
        needRoom(piece)
        writeBytes(scratch,
          cast[pointer](cast[int](span.p) + off), piece)
        off += piece
        maybeFlush()
      maybeReleaseInput()
    of 1:
      let lit = fixedLitDec()
      let dist = fixedDistDec()
      while true:
        let sym = decode(lit, br)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + getBits(br, lenExtra[li])
          let dsym = decode(dist, br)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + getBits(br, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
      maybeReleaseInput()
    of 2:
      let (lit, dist) = readDynamicTables(br)
      while true:
        let sym = decode(lit, br)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + getBits(br, lenExtra[li])
          let dsym = decode(dist, br)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + getBits(br, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
      maybeReleaseInput()
    else:
      raise newException(FlateError, "flate: reserved block type")

  seek(inp, (br.bitPos + 7) div 8)
  flushAllToFile(scratch, f, crc, total)
  result = (total, crc xor 0xFFFFFFFF'u32)

proc inflateFileRange*(rf: File, compLen: int, wf: File, scratch: Output,
    inBuf: var string): tuple[bytes: int, crc: uint32] =
  ## Streaming inflate from a file range (current position, `compLen`
  ## bytes) directly to `wf` with bounded memory. `rf` must be positioned
  ## at the start of the deflate stream; exactly `compLen` bytes are
  ## consumed. `scratch` is the fixed ~96KB output window (reused),
  ## `inBuf` the fixed 64KB compressed-input buffer (reused). Peak heap
  ## is buffers + tiny Huffman tables, never the entry size. Raises
  ## FlateError on corruption, IoError on I/O failure. Gcsafe, no globals.
  ensureFixedCap(scratch, StreamBufCap)
  if scratch.len != 0:
    resetBounded(scratch)
  if inBuf.len < StreamChunkSize:
    inBuf = newString(StreamChunkSize)
  var bufLen = 0
  var bitPos = 0
  var remaining = compLen
  var crc: uint32 = 0xFFFFFFFF'u32
  var total = 0

  template needRoom(n: int) =
    if scratch.len + n > StreamBufCap:
      flushKeepWindow(scratch, wf, StreamWindowSize, crc, total)

  template maybeFlush() =
    if scratch.len >= StreamChunkSize + StreamWindowSize:
      flushKeepWindow(scratch, wf, StreamWindowSize, crc, total)

  template refill() =
    let bi = bitPos div 8
    if bi < bufLen:
      let unread = bufLen - bi
      if bi > 0 and unread > 0:
        moveMem(addr inBuf[0], addr inBuf[bi], unread)
      bufLen = unread
      bitPos = bitPos - bi * 8
    else:
      bufLen = 0
      bitPos = 0
    if remaining > 0:
      let free = inBuf.len - bufLen
      let toRead = min(free, remaining)
      if toRead > 0:
        let n = readBuffer(rf, addr inBuf[bufLen], toRead)
        if n <= 0:
          raise newException(FlateError, "flate: truncated input")
        bufLen += n
        remaining -= n

  template ensureBits(nbits: int) =
    while (bufLen * 8 - bitPos) < nbits:
      let beforeLen = bufLen
      let beforeRem = remaining
      refill()
      if (bufLen * 8 - bitPos) < nbits:
        if remaining == 0 and bufLen * 8 - bitPos < nbits:
          # No more bytes to read and still short: truncated.
          # Avoid infinite loop when refill made no progress.
          if bufLen == beforeLen and remaining == beforeRem:
            raise newException(FlateError, "flate: truncated input")
        # Otherwise loop again (refill may have made partial progress).

  template fGetBits(n: int): int =
    block:
      ensureBits(n)
      var res = 0
      for i in 0 ..< n:
        let p = bitPos + i
        if (cast[ptr UncheckedArray[byte]](unsafeAddr inBuf[0])[p div 8] and
            byte(1 shl (p mod 8))) != 0:
          res = res or (1 shl i)
      bitPos += n
      res

  template fAlignToByte() =
    bitPos = (bitPos + 7) and not 7

  template fDecode(d: HuffDec): int =
    block:
      var code = 0
      var first = 0
      var index = 0
      var sym = -1
      for length in 1 .. d.maxLen:
        code = (code shl 1) or fGetBits(1)
        let count = d.counts[length]
        if code - first < count:
          sym = d.symbols[index + (code - first)]
          break
        index += count
        first = (first + count) shl 1
      if sym < 0:
        raise newException(FlateError, "flate: invalid huffman code")
      sym

  template fReadDynamicTables(): tuple[lit, dist: HuffDec] =
    block:
      let hlit = fGetBits(5) + 257
      let hdist = fGetBits(5) + 1
      let hclen = fGetBits(4) + 4
      var clLens = newSeq[int](19)
      for i in 0 ..< hclen:
        clLens[clOrder[i]] = fGetBits(3)
      let cl = initHuffDec(clLens)
      let totalLens = hlit + hdist
      var lens = newSeq[int](totalLens)
      var ii = 0
      while ii < totalLens:
        let sym = fDecode(cl)
        case sym
        of 0 .. 15:
          lens[ii] = sym
          inc ii
        of 16:
          if ii == 0:
            raise newException(FlateError, "flate: repeat with no previous")
          let rep = fGetBits(2) + 3
          for _ in 0 ..< rep:
            if ii >= totalLens:
              raise newException(FlateError, "flate: too many lengths")
            lens[ii] = lens[ii - 1]
            inc ii
        of 17:
          let rep = fGetBits(3) + 3
          for _ in 0 ..< rep:
            if ii >= totalLens:
              raise newException(FlateError, "flate: too many lengths")
            lens[ii] = 0
            inc ii
        of 18:
          let rep = fGetBits(7) + 11
          for _ in 0 ..< rep:
            if ii >= totalLens:
              raise newException(FlateError, "flate: too many lengths")
            lens[ii] = 0
            inc ii
        else:
          raise newException(FlateError, "flate: bad code-length code")
      let lit = initHuffDec(lens[0 ..< hlit])
      let dist =
        if hdist == 1 and lens[hlit] == 0:
          initHuffDec(newSeq[int](1))
        else:
          initHuffDec(lens[hlit ..< totalLens])
      (lit, dist)

  var done = false
  while not done:
    done = fGetBits(1) == 1
    let btype = fGetBits(2)
    case btype
    of 0: # stored: copy bytes from file stream through scratch window
      fAlignToByte()
      let length = fGetBits(16)
      let inv = fGetBits(16)
      if (length xor 0xFFFF) != inv:
        raise newException(FlateError, "flate: stored length mismatch")
      var toCopy = length
      while toCopy > 0:
        let bi = bitPos div 8
        if bi >= bufLen:
          refill()
          if bitPos div 8 >= bufLen:
            raise newException(FlateError, "flate: truncated stored block")
          continue
        let avail = min(toCopy, bufLen - bi)
        needRoom(avail)
        writeBytes(scratch, addr inBuf[bi], avail)
        bitPos += avail * 8
        toCopy -= avail
        maybeFlush()
    of 1:
      let lit = fixedLitDec()
      let dist = fixedDistDec()
      while true:
        let sym = fDecode(lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fGetBits(lenExtra[li])
          let dsym = fDecode(dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fGetBits(distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    of 2:
      let (lit, dist) = fReadDynamicTables()
      while true:
        let sym = fDecode(lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fGetBits(lenExtra[li])
          let dsym = fDecode(dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fGetBits(distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    else:
      raise newException(FlateError, "flate: reserved block type")

  flushAllToFile(scratch, wf, crc, total)
  result = (total, crc xor 0xFFFFFFFF'u32)

type FileInflateReader* = object
  ## Reusable file-backed bit reader (LSB-first) for streaming inflate.
  ## Owns a fixed 64KB input buffer; `bufLen` tracks valid bytes,
  ## `bitPos` bits consumed, `eof` set when file EOF reached. No globals,
  ## all state explicit so any thread can use it. Preserves leftover
  ## buffered bytes across members (no pushback loss) for gzip/zlib
  ## multistream handling.
  f*: File
  buf*: string
  bufLen*: int
  bitPos*: int
  eof*: bool

proc initFileInflateReader*(f: File): FileInflateReader =
  ## Allocate the fixed 64KB input buffer once per file.
  result.f = f
  result.buf = newString(StreamChunkSize)
  result.bufLen = 0
  result.bitPos = 0
  result.eof = false

proc fileRefill(rdr: var FileInflateReader) =
  ## Compact unread bytes to front, read more from file (up to cap).
  ## Sets eof when file returns 0 bytes. Never raises except I/O errors
  ## from readBuffer (which are IoError, preserved).
  let bi = rdr.bitPos div 8
  if bi < rdr.bufLen:
    let unread = rdr.bufLen - bi
    if bi > 0 and unread > 0:
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

proc fileEnsureBits*(rdr: var FileInflateReader; nbits: int) =
  ## Ensure at least nbits available from bitPos, refilling as needed.
  ## Raises FlateError on truncation (EOF with insufficient bits).
  while (rdr.bufLen * 8 - rdr.bitPos) < nbits:
    let beforeLen = rdr.bufLen
    let beforeEof = rdr.eof
    fileRefill(rdr)
    if (rdr.bufLen * 8 - rdr.bitPos) < nbits:
      if rdr.eof:
        raise newException(FlateError, "flate: truncated input")
      if rdr.bufLen == beforeLen and rdr.eof == beforeEof:
        raise newException(FlateError, "flate: truncated input")

proc fileGetBits*(rdr: var FileInflateReader; n: int): int =
  ## Read n bits LSB-first from file stream. Refills as needed.
  fileEnsureBits(rdr, n)
  result = 0
  for i in 0 ..< n:
    let p = rdr.bitPos + i
    if (cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[p div 8] and
        byte(1 shl (p mod 8))) != 0:
      result = result or (1 shl i)
  rdr.bitPos += n

proc fileGetByte*(rdr: var FileInflateReader): byte =
  ## Byte-aligned read (caller must have aligned). Refills as needed.
  fileEnsureBits(rdr, 8)
  let bi = rdr.bitPos div 8
  result = cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[bi]
  rdr.bitPos += 8

proc fileAlignToByte*(rdr: var FileInflateReader) =
  rdr.bitPos = (rdr.bitPos + 7) and not 7

proc fileSkipBytes*(rdr: var FileInflateReader; n: int) =
  ## Skip n bytes (byte-aligned). Refills across buffer boundaries.
  var left = n
  while left > 0:
    let bi = rdr.bitPos div 8
    if bi >= rdr.bufLen:
      fileRefill(rdr)
      if rdr.bitPos div 8 >= rdr.bufLen:
        raise newException(FlateError, "flate: truncated input")
      continue
    let avail = min(left, rdr.bufLen - bi)
    rdr.bitPos += avail * 8
    left -= avail

proc fileDecode*(rdr: var FileInflateReader; d: HuffDec): int =
  ## Huffman decode one symbol from file stream.
  var code = 0
  var first = 0
  var index = 0
  for length in 1 .. d.maxLen:
    code = (code shl 1) or fileGetBits(rdr, 1)
    let count = d.counts[length]
    if code - first < count:
      return d.symbols[index + (code - first)]
    index += count
    first = (first + count) shl 1
  raise newException(FlateError, "flate: invalid huffman code")

proc fileReadDynamicTables*(rdr: var FileInflateReader):
    tuple[lit, dist: HuffDec] =
  let hlit = fileGetBits(rdr, 5) + 257
  let hdist = fileGetBits(rdr, 5) + 1
  let hclen = fileGetBits(rdr, 4) + 4
  var clLens = newSeq[int](19)
  for i in 0 ..< hclen:
    clLens[clOrder[i]] = fileGetBits(rdr, 3)
  let cl = initHuffDec(clLens)
  let total = hlit + hdist
  var lens = newSeq[int](total)
  var i = 0
  while i < total:
    let sym = fileDecode(rdr, cl)
    case sym
    of 0 .. 15:
      lens[i] = sym
      inc i
    of 16:
      if i == 0:
        raise newException(FlateError, "flate: repeat with no previous")
      let rep = fileGetBits(rdr, 2) + 3
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = lens[i - 1]
        inc i
    of 17:
      let rep = fileGetBits(rdr, 3) + 3
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = 0
        inc i
    of 18:
      let rep = fileGetBits(rdr, 7) + 11
      for _ in 0 ..< rep:
        if i >= total:
          raise newException(FlateError, "flate: too many lengths")
        lens[i] = 0
        inc i
    else:
      raise newException(FlateError, "flate: bad code-length code")
  let lit = initHuffDec(lens[0 ..< hlit])
  let dist =
    if hdist == 1 and lens[hlit] == 0:
      initHuffDec(newSeq[int](1))
    else:
      initHuffDec(lens[hlit ..< total])
  (lit, dist)

proc inflateFileMember*(rdr: var FileInflateReader; wf: File;
    scratch: Output): tuple[bytes: int, crc: uint32] =
  ## Inflate one deflate member from file stream to `wf` with bounded
  ## memory (64KB input buffer in `rdr` + ~96KB `scratch` window).
  ## Preserves `rdr` buffer state (leftover trailer/next-header bytes stay
  ## buffered for caller). Returns (bytes, IEEE CRC32). Raises FlateError
  ## on corruption, IoError on short writes.
  ensureFixedCap(scratch, StreamBufCap)
  if scratch.len != 0:
    resetBounded(scratch)
  var crc: uint32 = 0xFFFFFFFF'u32
  var total = 0

  template needRoom(n: int) =
    if scratch.len + n > StreamBufCap:
      flushKeepWindow(scratch, wf, StreamWindowSize, crc, total)

  template maybeFlush() =
    if scratch.len >= StreamChunkSize + StreamWindowSize:
      flushKeepWindow(scratch, wf, StreamWindowSize, crc, total)

  var done = false
  while not done:
    done = fileGetBits(rdr, 1) == 1
    let btype = fileGetBits(rdr, 2)
    case btype
    of 0: # stored: copy bytes from file stream through scratch window
      fileAlignToByte(rdr)
      let length = fileGetBits(rdr, 16)
      let inv = fileGetBits(rdr, 16)
      if (length xor 0xFFFF) != inv:
        raise newException(FlateError, "flate: stored length mismatch")
      var toCopy = length
      while toCopy > 0:
        let bi = rdr.bitPos div 8
        if bi >= rdr.bufLen:
          fileRefill(rdr)
          if rdr.bitPos div 8 >= rdr.bufLen:
            raise newException(FlateError, "flate: truncated stored block")
          continue
        let avail = min(toCopy, rdr.bufLen - bi)
        needRoom(avail)
        writeBytes(scratch, addr rdr.buf[bi], avail)
        rdr.bitPos += avail * 8
        toCopy -= avail
        maybeFlush()
    of 1:
      let lit = fixedLitDec()
      let dist = fixedDistDec()
      while true:
        let sym = fileDecode(rdr, lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fileGetBits(rdr, lenExtra[li])
          let dsym = fileDecode(rdr, dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fileGetBits(rdr, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    of 2:
      let (lit, dist) = fileReadDynamicTables(rdr)
      while true:
        let sym = fileDecode(rdr, lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fileGetBits(rdr, lenExtra[li])
          let dsym = fileDecode(rdr, dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fileGetBits(rdr, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    else:
      raise newException(FlateError, "flate: reserved block type")

  flushAllToFile(scratch, wf, crc, total)
  result = (total, crc xor 0xFFFFFFFF'u32)

proc inflateFileMemberGeneric*(rdr: var FileInflateReader; wf: File;
    scratch: Output;
    update: proc (crc: uint32, p: pointer, len: int): uint32 {.nimcall.};
    initCrc: uint32): tuple[bytes: int, crc: uint32] =
  ## Checksum-generic variant of inflateFileMember for codecs with their
  ## own running checksum (zlib Adler-32). `update` folds each flushed
  ## chunk into the running value starting from `initCrc`; returns the
  ## running value un-finalized so callers apply their own finalization
  ## (gzip xors, Adler does not). Buffering, window retention and error
  ## behavior are otherwise identical to inflateFileMember.
  ensureFixedCap(scratch, StreamBufCap)
  if scratch.len != 0:
    resetBounded(scratch)
  var crc = initCrc
  var total = 0

  template needRoom(n: int) =
    if scratch.len + n > StreamBufCap:
      let toWrite = scratch.len - StreamWindowSize
      if toWrite > 0:
        crc = update(crc, outputBaseAddr(scratch), toWrite)
      total += flushKeepWindowNoCrc(scratch, wf, StreamWindowSize)

  template maybeFlush() =
    if scratch.len >= StreamChunkSize + StreamWindowSize:
      let toWrite = scratch.len - StreamWindowSize
      if toWrite > 0:
        crc = update(crc, outputBaseAddr(scratch), toWrite)
      total += flushKeepWindowNoCrc(scratch, wf, StreamWindowSize)

  var done = false
  while not done:
    done = fileGetBits(rdr, 1) == 1
    let btype = fileGetBits(rdr, 2)
    case btype
    of 0: # stored: copy bytes from file stream through scratch window
      fileAlignToByte(rdr)
      let length = fileGetBits(rdr, 16)
      let inv = fileGetBits(rdr, 16)
      if (length xor 0xFFFF) != inv:
        raise newException(FlateError, "flate: stored length mismatch")
      var toCopy = length
      while toCopy > 0:
        let bi = rdr.bitPos div 8
        if bi >= rdr.bufLen:
          fileRefill(rdr)
          if rdr.bitPos div 8 >= rdr.bufLen:
            raise newException(FlateError, "flate: truncated stored block")
          continue
        let avail = min(toCopy, rdr.bufLen - bi)
        needRoom(avail)
        writeBytes(scratch, addr rdr.buf[bi], avail)
        rdr.bitPos += avail * 8
        toCopy -= avail
        maybeFlush()
    of 1:
      let lit = fixedLitDec()
      let dist = fixedDistDec()
      while true:
        let sym = fileDecode(rdr, lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fileGetBits(rdr, lenExtra[li])
          let dsym = fileDecode(rdr, dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fileGetBits(rdr, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    of 2:
      let (lit, dist) = fileReadDynamicTables(rdr)
      while true:
        let sym = fileDecode(rdr, lit)
        if sym < 256:
          needRoom(1)
          putByte(scratch, byte(sym))
          maybeFlush()
        elif sym == 256:
          break
        else:
          let li = sym - 257
          if li < 0 or li > 28:
            raise newException(FlateError, "flate: bad length code")
          let length = lenBase[li] + fileGetBits(rdr, lenExtra[li])
          let dsym = fileDecode(rdr, dist)
          if dsym < 0 or dsym > 29:
            raise newException(FlateError, "flate: bad distance code")
          let distance = distBase[dsym] + fileGetBits(rdr, distExtra[dsym])
          needRoom(length)
          putMatch(scratch, distance, length)
          maybeFlush()
    else:
      raise newException(FlateError, "flate: reserved block type")

  let tail = scratch.len
  if tail > 0:
    crc = update(crc, outputBaseAddr(scratch), tail)
  total += flushAllNoCrc(scratch, wf)
  result = (total, crc)

proc inflateAll*(data: string): string =
  ## Convenience: decompress a raw DEFLATE stream to a fresh string.
  let dst = newOutput()
  if data.len > 0:
    let inp = openInputString(data)
    inflateInto(inp, dst)
  take(dst)

# ---------- bit writer (LSB-first, into reusable Output) ----------

type BitWriter = object
  dst: Output
  acc: uint32
  nbits: int

proc writeBits(w: var BitWriter; code, n: int) {.inline.} =
  w.acc = w.acc or (code.uint32 shl w.nbits)
  w.nbits += n
  while w.nbits >= 8:
    putByte(w.dst, byte(w.acc and 0xFF))
    w.acc = w.acc shr 8
    w.nbits -= 8

proc flushBits(w: var BitWriter) {.inline.} =
  if w.nbits > 0:
    putByte(w.dst, byte(w.acc and 0xFF))
    w.acc = 0
    w.nbits = 0

proc reverseBits(code, n: int): int =
  for i in 0 ..< n:
    if (code and (1 shl i)) != 0:
      result = result or (1 shl (n - 1 - i))

proc canonicalEncodeCodes(lens: openArray[int]): seq[tuple[code, len: int]] =
  var count = newSeq[int](17)
  for l in lens:
    if l > 0:
      if l > 16:
        raise newException(FlateError, "flate: code too long")
      count[l] += 1
  var next = newSeq[int](17)
  var code = 0
  for bits in 1 .. 16:
    code = (code + count[bits - 1]) shl 1
    next[bits] = code
  result = newSeq[tuple[code, len: int]](lens.len)
  for sym, l in lens:
    if l > 0:
      result[sym] = (reverseBits(next[l], l), l)
      next[l] += 1

proc fixedLitEnc(): seq[tuple[code, len: int]] =
  canonicalEncodeCodes(fixedLitLengths())
proc fixedDistEnc(): seq[tuple[code, len: int]] =
  canonicalEncodeCodes(fixedDistLengths())

# ---------- LZ77 matcher (hash chains) ----------

const
  windowSize = 32768
  minMatchLen = 3
  maxMatchLen = 258
  hashBits = 15
  hashSize = 1 shl hashBits
  maxChainLen = 256

proc hash3(p: pointer; pos: int): int {.inline.} =
  let b = cast[ptr UncheckedArray[byte]](p)
  (b[pos].int xor (b[pos + 1].int shl 5) xor
    (b[pos + 2].int shl 10)) and (hashSize - 1)

proc lengthCode(length: int): tuple[code, extra, extraBits: int] =
  if length == 258:
    return (285, 0, 0)
  var li = 0
  while li < 28 and length >= lenBase[li + 1]:
    inc li
  (257 + li, length - lenBase[li], lenExtra[li])

proc distCode(dist: int): tuple[code, extra, extraBits: int] =
  var di = 0
  while di < 29 and dist >= distBase[di + 1]:
    inc di
  (di, dist - distBase[di], distExtra[di])

proc deflateInto*(inp: Input; output: Output) =
  ## Compress the remaining input bytes with fixed-Huffman blocks.
  let flc = fixedLitEnc()
  let fdc = fixedDistEnc()
  let base = basePointer(inp)
  let total = remaining(inp)
  var w = BitWriter(dst: output)
  w.writeBits(1, 1) # BFINAL
  w.writeBits(1, 2) # BTYPE fixed
  if total == 0:
    let (ecode, elen) = flc[256]
    w.writeBits(ecode, elen)
    w.flushBits()
    return
  let start = inputPos(inp)
  let bp = cast[pointer](cast[int](base) + start)
  var head = newSeq[int](hashSize)
  for i in 0 ..< hashSize:
    head[i] = -1
  # Circular predecessor ring: O(windowSize) instead of O(total).
  # Slot collisions are safe: stale entries fail the `pos - cand`
  # window check below, wrong-turn detours are bounded by maxChainLen,
  # and every emitted match is byte-verified, so output stays valid
  # (same tradeoff as zlib's own w_size prev table; ratio-only effect).
  const prevMask = windowSize - 1
  var prev = newSeq[int](windowSize)
  for i in 0 ..< windowSize:
    prev[i] = -1
  var pos = 0
  while pos < total:
    var bestLen = 0
    var bestDist = 0
    if pos + minMatchLen <= total:
      let h = hash3(bp, pos)
      var cand = head[h]
      var chain = 0
      let maxLen = min(maxMatchLen, total - pos)
      while cand >= 0 and pos - cand <= windowSize and chain < maxChainLen:
        let ln = matchLenSimd(
          cast[pointer](cast[int](bp) + cand),
          cast[pointer](cast[int](bp) + pos), maxLen)
        if ln > bestLen:
          bestLen = ln
          bestDist = pos - cand
          if ln == maxLen:
            break
        cand = prev[cand and prevMask]
        inc chain
      prev[pos and prevMask] = head[h]
      head[h] = pos
    if bestLen >= minMatchLen:
      let (lc, lextra, lebits) = lengthCode(bestLen)
      let (dc, dextra, debits) = distCode(bestDist)
      let (lcode, llen) = flc[lc]
      let (dcode, dlen) = fdc[dc]
      w.writeBits(lcode, llen)
      if lebits > 0:
        w.writeBits(lextra, lebits)
      w.writeBits(dcode, dlen)
      if debits > 0:
        w.writeBits(dextra, debits)
      pos += bestLen
    else:
      let b = cast[ptr UncheckedArray[byte]](
        cast[int](bp) + pos)[0]
      let (lcode, llen) = flc[b.int]
      w.writeBits(lcode, llen)
      inc pos
  seek(inp, start + total)
  let (ecode, elen) = flc[256]
  w.writeBits(ecode, elen)
  w.flushBits()

proc deflateFixed*(data: string): string =
  ## Convenience: compress to a fresh string.
  let dst = newOutput(data.len div 2 + 64)
  let inp = openInputString(data)
  deflateInto(inp, dst)
  take(dst)
