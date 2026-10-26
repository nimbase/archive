import std/[unittest, strutils]
import archive

registerDefaults()

proc handlerFor(ext: string): FormatHandler =
  for h in registeredFormats():
    if h.ext == ext:
      return h
  raise newException(ArchiveError, ext & " not registered")

suite "codecs":
  test "gzip round trip via reusable buffer":
    let gz = handlerFor(".gz")
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    let dst = newOutput()
    gz.compress(openInputString(payload), dst)
    check(outputBytes(dst).len > 0)
    let magic = peek(toInput(dst), 2)
    check(spanLen(magic) == 2)
    let mb = cast[ptr UncheckedArray[byte]](magic.p)
    check(mb[0] == 0x1f'u8 and mb[1] == 0x8b'u8)
    let enc = take(dst)
    let plain = newOutput()
    gz.decompress(openInputString(enc), plain)
    check(take(plain) == payload)

  test "gzip empty payload":
    let gz = handlerFor(".gz")
    let dst = newOutput()
    gz.compress(openInputString(""), dst)
    let back = newOutput()
    gz.decompress(toInput(dst), back)
    check(take(back) == "")

  test "decodes system gzip fixture (dynamic Huffman)":
    let gz = handlerFor(".gz")
    let inp = openInputFile("tests/testdata/interop.txt.gz")
    let want = openInputFile("tests/testdata/interop.txt")
    let dst = newOutput()
    gz.decompress(inp, dst)
    check(take(dst) == readAll(want))

  test "brotli round trip":
    let br = handlerFor(".br")
    let payload = "Hello, Brotli! ".repeat(50)
    let dst = newOutput()
    br.compress(openInputString(payload), dst)
    check(outputBytes(dst).len > 0)
    let back = newOutput()
    br.decompress(toInput(dst), back)
    check(take(back) == payload)

  test "brotli decode is store-wrapped but correct":
    let br = handlerFor(".br")
    let payload = "abc123".repeat(100)
    let dst = newOutput()
    br.compress(openInputString(payload), dst)
    let back = newOutput()
    br.decompress(toInput(dst), back)
    check(take(back) == payload)

  test "brotli corrupt input raises":
    let br = handlerFor(".br")
    expect(ArchiveError):
      let dst = newOutput()
      br.decompress(openInputString("definitely not brotli!!!"), dst)

  test "zlib round trip via reusable buffer":
    let zz = handlerFor(".zz")
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    let dst = newOutput()
    zz.compress(openInputString(payload), dst)
    check(outputBytes(dst).len > 0)
    let magic = peek(toInput(dst), 2)
    check(spanLen(magic) == 2)
    let mb = cast[ptr UncheckedArray[byte]](magic.p)
    check(mb[0] == 0x78'u8)
    check(isValidZlibHeader(mb[0], mb[1]))
    let enc = take(dst)
    let plain = newOutput()
    zz.decompress(openInputString(enc), plain)
    check(take(plain) == payload)

  test "zlib empty payload":
    let zz = handlerFor(".zz")
    let dst = newOutput()
    zz.compress(openInputString(""), dst)
    let back = newOutput()
    zz.decompress(toInput(dst), back)
    check(take(back) == "")

  test "zlib all byte values round trip":
    let zz = handlerFor(".zz")
    var s = newString(256)
    for i in 0 ..< 256:
      s[i] = chr(i)
    let dst = newOutput()
    zz.compress(openInputString(s), dst)
    let back = newOutput()
    zz.decompress(toInput(dst), back)
    check(take(back) == s)

  test "zlib levels produce valid headers":
    check(zlibHeaderForLevel(1) == (0x78'u8, 0x01'u8))
    check(zlibHeaderForLevel(6) == (0x78'u8, 0x9C'u8))
    check(zlibHeaderForLevel(9) == (0x78'u8, 0xDA'u8))
    let dst = newOutput()
    zlibCompressInto(openInputString("x".repeat(100)), dst, 1)
    let hdr = peek(toInput(dst), 2)
    let hb = cast[ptr UncheckedArray[byte]](hdr.p)
    check(hb[0] == 0x78'u8 and hb[1] == 0x01'u8)

  test "zlib decodes python reference fixture":
    let zz = handlerFor(".zz")
    let inp = openInputFile("tests/testdata/interop.txt.zz")
    let want = openInputFile("tests/testdata/interop.txt")
    let dst = newOutput()
    zz.decompress(inp, dst)
    check(take(dst) == readAll(want))

  test "zlib corrupt input raises":
    let zz = handlerFor(".zz")
    expect(ZlibError):
      let dst = newOutput()
      zz.decompress(openInputString("definitely not zlib!!!"), dst)

  test "zlib bad checksum raises":
    let good = zlibCompress("hello world".repeat(10))
    var bad = good
    bad[^1] = chr(ord(bad[^1]) xor 0xFF)
    expect(ZlibError):
      discard zlibDecompress(bad)
