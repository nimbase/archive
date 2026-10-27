## gzip framing (RFC 1952) ported from Go compress/gzip semantics.
##
## Works on `Input`/`Output`: header/trailer parsed from borrowed spans
## (zero-copy), body inflated straight into the caller's reusable buffer.

import ./io
import ./flate
import ./crc32
import std/strutils
from std/os import removeFile

type GzipError* = object of CatchableError

const
  gzMagic0 = 0x1f'u8
  gzMagic1 = 0x8b'u8
  gzDeflate = 8

proc gzipCompressInto*(inp: Input; output: Output; level = 6) =
  ## One-shot gzip compress of the remaining input. Level follows Go:
  ## <=1 fastest, >=9 best, 0 maps to default (6 here).
  let plain = peek(inp, remaining(inp))
  let crc = (if spanLen(plain) == 0: 0'u32
    else: crc32Update(0xFFFFFFFF'u32, plain.p, plain.len) xor 0xFFFFFFFF'u32)
  let isize = plain.len.uint32
  output.writeByte(char(gzMagic0))
  output.writeByte(char(gzMagic1))
  output.writeByte(char(gzDeflate))
  output.writeByte(char(0)) # FLG
  for _ in 0 ..< 4:
    output.writeByte(char(0)) # MTIME
  let xfl =
    if level >= 9: 2
    elif level <= 1: 4
    else: 0
  output.writeByte(char(xfl))
  output.writeByte(char(3)) # OS = Unix
  deflateInto(inp, output)
  for i in 0 ..< 4: # CRC32 LE
    output.writeByte(char((crc shr (8 * i)) and 0xFF))
  for i in 0 ..< 4: # ISIZE LE
    output.writeByte(char((isize shr (8 * i)) and 0xFF))

proc gzipCompress*(data: string; level = 6): string =
  ## Convenience: compress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput(data.len div 2 + 32)
  gzipCompressInto(inp, dst, level)
  take(dst)

proc gzipDecompressInto*(inp: Input; output: Output; multistream = true) =
  ## Decompress members at the cursor into `output`, advancing past
  ## each trailer. Raises GzipError on any corruption.
  var members = 0
  while true:
    if remaining(inp) < 18:
      if members == 0:
        raise newException(GzipError, "gzip: truncated input")
      break
    let magic = peek(inp, 2)
    if spanLen(magic) < 2 or
        cast[ptr UncheckedArray[byte]](magic.p)[0] != gzMagic0 or
        cast[ptr UncheckedArray[byte]](magic.p)[1] != gzMagic1:
      if members == 0:
        raise newException(GzipError,
          "gzip: failed identification values check")
      break
    discard readSpan(inp, 2)
    if readByte(inp) != byte(gzDeflate):
      raise newException(GzipError, "gzip: unsupported compression method")
    let flg = readByte(inp).int
    if (flg and 0xE0) != 0:
      raise newException(GzipError, "gzip: reserved flag bits set")
    discard readSpan(inp, 4) # MTIME
    discard readSpan(inp, 1) # XFL
    discard readSpan(inp, 1) # OS
    if (flg and 0x04) != 0: # FEXTRA
      let xlen = peek(inp, 2)
      if spanLen(xlen) < 2:
        raise newException(GzipError, "gzip: truncated header")
      let b = cast[ptr UncheckedArray[byte]](xlen.p)
      discard readSpan(inp, 2 + b[0].int + (b[1].int shl 8))
    if (flg and 0x08) != 0: # FNAME
      while remaining(inp) > 0 and readByte(inp) != 0:
        discard
    if (flg and 0x10) != 0: # FCOMMENT
      while remaining(inp) > 0 and readByte(inp) != 0:
        discard
    if (flg and 0x02) != 0: # FHCRC
      discard readSpan(inp, 2)
    if remaining(inp) < 8:
      raise newException(GzipError, "gzip: truncated body")
    let bodyStart = inputPos(inp)
    let outStart = output.len
    let endBit =
      try: inflateStreamPtr(basePointer(inp), inputLen(inp),
        bodyStart * 8, output)
      except FlateError as e:
        raise newException(GzipError, "gzip: corrupt deflate: " & e.msg)
    seek(inp, (endBit + 7) div 8)
    if remaining(inp) < 8:
      raise newException(GzipError, "gzip: truncated trailer")
    let t = readSpan(inp, 8)
    let tb = cast[ptr UncheckedArray[byte]](t.p)
    var wantCrc: uint32 = 0
    var wantSize: uint32 = 0
    for i in 0 ..< 4:
      wantCrc = wantCrc or (tb[i].uint32 shl (8 * i))
      wantSize = wantSize or (tb[4 + i].uint32 shl (8 * i))
    # CRC over the bytes just produced.
    let ob = outputBytes(output)
    let newBytes = Span(p: cast[pointer](cast[int](ob.p) + outStart),
      len: output.len - outStart)
    var crc = crc32Update(0xFFFFFFFF'u32, newBytes.p, newBytes.len) xor
      0xFFFFFFFF'u32
    if crc != wantCrc:
      raise newException(GzipError, "gzip: checksum mismatch")
    if newBytes.len.uint32 != wantSize:
      raise newException(GzipError, "gzip: size mismatch")
    inc members
    if not multistream:
      break
    if remaining(inp) == 0:
      break

proc gzipDecompress*(data: string; multistream = true): string =
  ## Convenience: decompress to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  gzipDecompressInto(inp, dst, multistream)
  take(dst)

proc gzipDecompressFile*(srcPath, dstPath: string; multistream = true) =
  ## Streaming file-to-file decompress with bounded memory: 64KB input
  ## buffer + ~96KB output window, reused across members. No full
  ## compressed or uncompressed holding. Preserves GzipError checks.
  ## Partial output deleted on failure (no file on error, like writeFile).
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(GzipError, "gzip: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(GzipError, "gzip: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var rdr = initFileInflateReader(rf)
    let scratch = newOutput(StreamBufCap)
    var members = 0
    while true:
      # Detect clean EOF (no buffered data and file EOF) before member.
      if rdr.eof and (rdr.bufLen * 8 - rdr.bitPos) == 0:
        if members == 0:
          raise newException(GzipError, "gzip: truncated input")
        break
      # Peek magic (2 bytes) with truncation mapping.
      var m0, m1: byte
      try:
        # Ensure at least 2 bytes for magic check without consuming
        # trailing garbage: read ahead, but if insufficient and members>0,
        # break (ignore trailing) to mirror mmap version.
        fileEnsureBits(rdr, 16)
        let bi = rdr.bitPos div 8
        m0 = cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[bi]
        m1 = cast[ptr UncheckedArray[byte]](unsafeAddr rdr.buf[0])[bi + 1]
      except FlateError:
        if members == 0:
          raise newException(GzipError, "gzip: truncated input")
        break
      if m0 != gzMagic0 or m1 != gzMagic1:
        if members == 0:
          raise newException(GzipError,
            "gzip: failed identification values check")
        break
      # Consume magic.
      try:
        discard fileGetBits(rdr, 16)
        if fileGetBits(rdr, 8) != gzDeflate.int:
          raise newException(GzipError, "gzip: unsupported compression method")
        let flg = fileGetBits(rdr, 8)
        if (flg and 0xE0) != 0:
          raise newException(GzipError, "gzip: reserved flag bits set")
        # MTIME(4) XFL(1) OS(1)
        for _ in 0 ..< 6:
          discard fileGetBits(rdr, 8)
        if (flg and 0x04) != 0: # FEXTRA
          let xl0 = fileGetBits(rdr, 8)
          let xl1 = fileGetBits(rdr, 8)
          fileSkipBytes(rdr, xl0 + (xl1 shl 8))
        if (flg and 0x08) != 0: # FNAME, null-terminated, lenient on EOF
          while true:
            var b: byte
            try:
              b = fileGetByte(rdr)
            except FlateError:
              break
            if b == 0:
              break
            if rdr.eof and (rdr.bufLen * 8 - rdr.bitPos) == 0:
              break
        if (flg and 0x10) != 0: # FCOMMENT, same leniency
          while true:
            var b: byte
            try:
              b = fileGetByte(rdr)
            except FlateError:
              break
            if b == 0:
              break
            if rdr.eof and (rdr.bufLen * 8 - rdr.bitPos) == 0:
              break
        if (flg and 0x02) != 0: # FHCRC
          fileSkipBytes(rdr, 2)
      except FlateError as e:
        # Map bit-reader truncation during header to GzipError.
        # Preserve specific GzipError messages already raised above;
        # only map raw FlateError (truncated input).
        if e.msg.startsWith("flate:"):
          raise newException(GzipError, "gzip: truncated header")
        raise
      except GzipError:
        raise
      except CatchableError as e:
        raise newException(GzipError, "gzip: truncated header: " & e.msg)
      # Body: one deflate member streaming to file.
      var res: tuple[bytes: int, crc: uint32]
      try:
        res = inflateFileMember(rdr, wf, scratch)
      except FlateError as e:
        raise newException(GzipError, "gzip: corrupt deflate: " & e.msg)
      # Trailer: 8 bytes LE (crc + isize), may already be buffered.
      # Starts at the next byte boundary after the deflate bit stream.
      fileAlignToByte(rdr)
      var wantCrc: uint32 = 0
      var wantSize: uint32 = 0
      try:
        for i in 0 ..< 4:
          wantCrc = wantCrc or (fileGetBits(rdr, 8).uint32 shl (8 * i))
        for i in 0 ..< 4:
          wantSize = wantSize or (fileGetBits(rdr, 8).uint32 shl (8 * i))
      except FlateError:
        raise newException(GzipError, "gzip: truncated trailer")
      if res.crc != wantCrc:
        raise newException(GzipError, "gzip: checksum mismatch")
      if res.bytes.uint32 != wantSize:
        raise newException(GzipError, "gzip: size mismatch")
      inc members
      if not multistream:
        break
      # Loop continues: next member header uses same buffer state
      # (leftover read-ahead preserved, no pushback loss).
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard

proc gzipMagic*(inp: Input): bool =
  ## Peek check for the 1f 8b magic (bounds-safe).
  let s = peek(inp, 2)
  spanLen(s) == 2 and
    cast[ptr UncheckedArray[byte]](s.p)[0] == gzMagic0 and
    cast[ptr UncheckedArray[byte]](s.p)[1] == gzMagic1
