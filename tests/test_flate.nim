import std/[unittest, strutils]
import archive/io
import archive/flate
import archive/zlibf

suite "flate":
  test "empty":
    check(inflateAll("") == "")
    check(inflateAll(deflateFixed("")) == "")

  test "round trip text":
    let payload = "hello world. ".repeat(50)
    check(inflateAll(deflateFixed(payload)) == payload)

  test "round trip all byte values":
    var s = newString(256)
    for i in 0 ..< 256:
      s[i] = chr(i)
    check(inflateAll(deflateFixed(s)) == s)

  test "round trip random-looking data":
    var s = newString(4096)
    var x = 0x12345678'u32
    for i in 0 ..< s.len:
      x = x * 1664525'u32 + 1013904223'u32
      s[i] = chr((x shr 16) and 0xFF)
    check(inflateAll(deflateFixed(s)) == s)

  test "stored block hand-decoded":
    # BFINAL=1, BTYPE=00, LEN=2, NLEN=~2, "Hi"
    check(inflateAll("\x01\x02\x00\xFD\xFFHi") == "Hi")

  test "long matches across window":
    let payload = "abcdefgh".repeat(5000)
    let enc = deflateFixed(payload)
    check(enc.len < payload.len div 2)
    check(inflateAll(enc) == payload)

  test "truncated input raises":
    expect(FlateError):
      discard inflateAll("\x03") # final fixed block header, no end code

  test "reserved block type raises":
    expect(FlateError):
      discard inflateAll("\x07\x00") # BFINAL=1, BTYPE=11

  test "fixed empty block is 03 00":
    check(deflateFixed("") == "\x03\x00")

  test "inflateInto reuses caller buffer":
    let payload = "reuse me ".repeat(100)
    let enc = deflateFixed(payload)
    let dst = newOutput(4) # tiny cap forces growth path
    inflateInto(openInputString(enc), dst)
    check(take(dst) == payload)

  test "stream chunked writes decode":
    let payload = "stream me ".repeat(3000)
    for splits in [1, 7, 1000, 65536]:
      let dst = newOutput()
      var st: DeflateStream
      openDeflateStream(st, dst)
      var pos = 0
      while pos < payload.len:
        let n = min(splits, payload.len - pos)
        writeDeflate(st, unsafeAddr payload[pos], n)
        pos += n
      finishDeflate(st)
      check(inflateAll(take(dst)) == payload)

  test "stream empty is 03 00":
    let dst = newOutput()
    var st: DeflateStream
    openDeflateStream(st, dst)
    finishDeflate(st)
    check(take(dst) == "\x03\x00")

  test "stream reset reuses tables":
    var st: DeflateStream
    for round in 0 ..< 2:
      let payload = "round " & $round & " "
      let full = payload.repeat(500)
      let dst = newOutput()
      if round == 0:
        openDeflateStream(st, dst)
      else:
        resetDeflateStream(st, dst)
      writeDeflate(st, full.toOpenArrayByte(0, full.high))
      finishDeflate(st)
      check(inflateAll(take(dst)) == full)

  test "stream matches one-shot on decode":
    let payload = "hello world. ".repeat(50)
    check(inflateAll(deflateFixed(payload)) == payload)
    let dst = newOutput()
    var st: DeflateStream
    openDeflateStream(st, dst)
    writeDeflate(st, payload.toOpenArrayByte(0, payload.high))
    finishDeflate(st)
    check(inflateAll(take(dst)) == payload)

  test "borrowed input round trip":
    let payload = "borrowed-window. ".repeat(4000)
    var plain = newString(payload.len)
    copyMem(addr plain[0], unsafeAddr payload[0], payload.len)
    var dst = newOutput()
    zlibCompressInto(openInputBorrowed(unsafeAddr plain[0], plain.len),
      dst, 6)
    let enc = take(dst)
    var dec = newOutput()
    var encCopy = enc
    zlibDecompressInto(openInputBorrowed(unsafeAddr encCopy[0], encCopy.len), dec)
    check(take(dec) == payload)

  test "newOutput capacity is honored":
    var o = newOutput(64)
    check(outputCap(o) == 64)
    for i in 0..<64: o.writeByte(byte(i))
    check(outputCap(o) == 64)
    let s = take(o)
    check(s.len == 64)
    check(s[0] == '\x00' and s[63] == '\x3F')

  test "long-range repetition round trip":
    # 100KB with a 40KB period: matches at distance 40000 exceed the
    # 32KB window and must be ignored; output must still be exact.
    var s = newString(100 * 1024)
    for i in 0..<s.len: s[i] = chr(i div 40000)
    let enc = deflateFixed(s)
    check(inflateAll(enc) == s)

  test "one-shot multi-block round trip":
    # Inputs over 32 KB encode as one fixed-Huffman block per 32 KB
    # (RFC 1951 3.2.3: BFINAL=0 except on the last block); tables reset
    # per block, so matches never cross a boundary. Small inputs still
    # encode as the historical single final block.
    let small = "hello world. ".repeat(50)
    let smallEnc = deflateFixed(small)
    check((smallEnc[0].ord and 1) == 1) # BFINAL set: single block
    check(((smallEnc[0].ord shr 1) and 3) == 1) # BTYPE fixed
    check(inflateAll(smallEnc) == small)
    # Boundary sizes around the 32 KB split.
    for n in [32767, 32768, 32769, 100 * 1024]:
      var s = newString(n)
      for i in 0 ..< n:
        s[i] = chr((i * 31 + i div 997) mod 256)
      let enc = deflateFixed(s)
      if n <= 32768:
        check((enc[0].ord and 1) == 1)
      else:
        check((enc[0].ord and 1) == 0) # first block non-final
        check(((enc[0].ord shr 1) and 3) == 1)
      check(inflateAll(enc) == s)
    # Repetitive data spanning several blocks still compresses.
    let rep = "abcdefgh".repeat(9000) # 72 KB -> 3 blocks
    let repEnc = deflateFixed(rep)
    check((repEnc[0].ord and 1) == 0)
    check(repEnc.len < rep.len div 2)
    check(inflateAll(repEnc) == rep)
