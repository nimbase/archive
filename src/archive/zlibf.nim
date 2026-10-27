## zlib framing (RFC 1950) ported from Go compress/zlib semantics.
##
## Thin wrapper over our own flate (RFC 1951): 2-byte header, raw DEFLATE
## body, 4-byte big-endian Adler-32 trailer. Works on `Input`/`Output`:
## header/trailer parsed from borrowed spans (zero-copy), body inflated
## straight into the caller's reusable buffer.

import ./io
import ./flate
from std/os import removeFile

type ZlibError* = object of CatchableError

const
  zlibCMDeflate = 8
  zlibCInfoMax = 7
  modAdler = 65521'u32
  nmaxAdler = 5552

proc isValidZlibHeader*(first, second: byte): bool =
  ## Procedural equivalent of Go's 32-entry validHeaders table:
  ## CM must be deflate, CINFO <= 7, FDICT clear, FCHECK valid.
  if (first and 0x0F) != byte(zlibCMDeflate):
    return false
  if (first shr 4) > byte(zlibCInfoMax):
    return false
  if (second and 0x20) != 0:
    return false
  let combined = (first.uint16 shl 8) or second.uint16
  combined mod 31 == 0

proc adler32Update*(adler: uint32; p: pointer; length: int): uint32 =
  ## Running Adler-32 update (start with 1). Scalar; NMAX chunking
  ## keeps s1/s2 in range without per-byte modulo.
  var s1 = adler and 0xFFFF
  var s2 = (adler shr 16) and 0xFFFF
  let b = cast[ptr UncheckedArray[byte]](p)
  var off = 0
  var left = length
  while left > 0:
    let chunk = min(left, nmaxAdler)
    for i in 0 ..< chunk:
      s1 += b[off + i].uint32
      s2 += s1
    s1 = s1 mod modAdler
    s2 = s2 mod modAdler
    off += chunk
    left -= chunk
  (s2 shl 16) or s1

proc adler32Update*(adler: uint32; data: string): uint32 =
  if data.len == 0:
    adler
  else:
    adler32Update(adler, unsafeAddr data[0], data.len)

proc adler32Update*(adler: uint32; data: openArray[byte]): uint32 =
  if data.len == 0:
    adler
  else:
    adler32Update(adler, unsafeAddr data[0], data.len)

proc adler32Checksum*(data: string): uint32 =
  adler32Update(1'u32, data)

proc adler32Checksum*(data: openArray[byte]): uint32 =
  adler32Update(1'u32, data)

proc zlibHeaderForLevel*(level: int): tuple[cmf, flg: byte] =
  ## Header bytes for a compression level, mirroring Go's writer:
  ## fastest -> 78 01, default -> 78 9C, best -> 78 DA.
  if level == 1:
    (0x78'u8, 0x01'u8)
  elif level >= 9:
    (0x78'u8, 0xDA'u8)
  else:
    (0x78'u8, 0x9C'u8)

proc zlibCompressInto*(inp: Input; dst: Output; level = 6) =
  ## One-shot zlib compress of the remaining input. Level follows Go:
  ## 1 fastest, 9 best, 0 maps to default.
  let plain = peek(inp, remaining(inp))
  let adler =
    if spanLen(plain) == 0: 1'u32
    else: adler32Update(1'u32, plain.p, plain.len)
  let (cmf, flg) = zlibHeaderForLevel(level)
  dst.writeByte(char(cmf))
  dst.writeByte(char(flg))
  deflateInto(inp, dst)
  for i in countdown(3, 0): # ADLER32 BE
    dst.writeByte(char((adler shr (8 * i)) and 0xFF))

proc zlibCompress*(data: string; level = 6): string =
  ## Convenience: compress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput(data.len div 2 + 16)
  zlibCompressInto(inp, dst, level)
  take(dst)

proc zlibDecompressInto*(inp: Input; dst: Output) =
  ## Decompress one zlib member at the cursor into `dst`, advancing
  ## past the trailer. Raises ZlibError on any corruption.
  if remaining(inp) < 2:
    raise newException(ZlibError, "zlib: truncated header")
  let hdr = peek(inp, 2)
  let hb = cast[ptr UncheckedArray[byte]](hdr.p)
  if not isValidZlibHeader(hb[0], hb[1]):
    raise newException(ZlibError, "zlib: invalid header")
  discard readSpan(inp, 2)
  if remaining(inp) < 1:
    raise newException(ZlibError, "zlib: truncated body")
  let bodyStart = inputPos(inp)
  let outStart = dst.len
  let endBit =
    try: inflateStreamPtr(basePointer(inp), inputLen(inp),
      bodyStart * 8, dst)
    except FlateError as e:
      raise newException(ZlibError, "zlib: corrupt deflate: " & e.msg)
  seek(inp, (endBit + 7) div 8)
  if remaining(inp) < 4:
    raise newException(ZlibError, "zlib: truncated checksum")
  let t = readSpan(inp, 4)
  let tb = cast[ptr UncheckedArray[byte]](t.p)
  var want: uint32 = 0
  for i in 0 ..< 4:
    want = (want shl 8) or tb[i].uint32
  let ob = outputBytes(dst)
  let newBytes = Span(p: cast[pointer](cast[int](ob.p) + outStart),
    len: dst.len - outStart)
  let got =
    if newBytes.len == 0: 1'u32
    else: adler32Update(1'u32, newBytes.p, newBytes.len)
  if got != want:
    raise newException(ZlibError, "zlib: checksum mismatch")

proc zlibDecompress*(data: string): string =
  ## Convenience: decompress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  zlibDecompressInto(inp, dst)
  take(dst)

proc adlerUpdateNimcall(crc: uint32, p: pointer, len: int): uint32 {.nimcall.} =
  ## Exact-signature wrapper so the generic file inflate can take it as
  ## a proc value without overload ambiguity.
  adler32Update(crc, p, len)

proc zlibDecompressFile*(srcPath, dstPath: string) =
  ## Streaming file-to-file decompress with bounded memory: 64KB input
  ## buffer in the reader + ~96KB output window, reused. No full
  ## compressed or uncompressed holding. Preserves ZlibError checks
  ## (header, Adler-32). Partial output deleted on failure.
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(ZlibError, "zlib: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(ZlibError, "zlib: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var rdr = initFileInflateReader(rf)
    let scratch = newOutput(StreamBufCap)
    # 2-byte header.
    var h0, h1: byte
    try:
      h0 = fileGetByte(rdr)
      h1 = fileGetByte(rdr)
    except FlateError:
      raise newException(ZlibError, "zlib: truncated header")
    if not isValidZlibHeader(h0, h1):
      raise newException(ZlibError, "zlib: invalid header")
    # Body: single deflate member with running Adler-32 (init 1, no xor).
    var res: tuple[bytes: int, crc: uint32]
    try:
      res = inflateFileMemberGeneric(rdr, wf, scratch, adlerUpdateNimcall, 1'u32)
    except FlateError as e:
      raise newException(ZlibError, "zlib: corrupt deflate: " & e.msg)
    # Trailer: 4-byte BE Adler-32 (may already be buffered).
    # Starts at the next byte boundary after the deflate bit stream.
    fileAlignToByte(rdr)
    var want: uint32 = 0
    try:
      for _ in 0 ..< 4:
        want = (want shl 8) or fileGetByte(rdr).uint32
    except FlateError:
      raise newException(ZlibError, "zlib: truncated checksum")
    if res.crc != want:
      raise newException(ZlibError, "zlib: checksum mismatch")
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard
