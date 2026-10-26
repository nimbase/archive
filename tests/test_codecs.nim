import std/[unittest, strutils]
import archive/types
import archive/io
import archive/registry
import archive/zlibf
import archive/lz4f
import archive/bz2f
import archive/formats/gz
import archive/formats/zlib
import archive/formats/lz4
import archive/formats/bz2
import archive/formats/brotli

registerGz()
registerZlib()
registerLz4()
registerBz2()
registerBrotli()

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

  test "lz4 round trip via reusable buffer":
    let lz = handlerFor(".lz4")
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    let dst = newOutput()
    lz.compress(openInputString(payload), dst)
    check(outputBytes(dst).len > 0)
    let magic = peek(toInput(dst), 4)
    check(spanLen(magic) == 4)
    let mb = cast[ptr UncheckedArray[byte]](magic.p)
    check(mb[0] == 0x04'u8 and mb[1] == 0x22'u8)
    check(mb[2] == 0x4D'u8 and mb[3] == 0x18'u8)
    let enc = take(dst)
    let plain = newOutput()
    lz.decompress(openInputString(enc), plain)
    check(take(plain) == payload)

  test "lz4 empty payload":
    let lz = handlerFor(".lz4")
    let dst = newOutput()
    lz.compress(openInputString(""), dst)
    check(outputBytes(dst).len == 7 + 4 + 4) # header + EndMark + checksum
    let back = newOutput()
    lz.decompress(toInput(dst), back)
    check(take(back) == "")

  test "lz4 all byte values round trip":
    let lz = handlerFor(".lz4")
    var s = newString(256)
    for i in 0 ..< 256:
      s[i] = chr(i)
    let dst = newOutput()
    lz.compress(openInputString(s), dst)
    let back = newOutput()
    lz.decompress(toInput(dst), back)
    check(take(back) == s)

  test "lz4 writer header flags":
    let enc = lz4Compress("hello world")
    check(enc.len > 7)
    check(enc[4].uint8 == 0x64'u8) # independent, content checksum
    check(enc[5].uint8 == 0x40'u8) # 64KB blocks

  test "lz4 multi-block and stored blocks round trip":
    var rnd = newString(100000)
    var x = 0x12345678'u32
    for i in 0 ..< rnd.len:
      x = x * 1664525'u32 + 1013904223'u32
      rnd[i] = chr((x shr 16) and 0xFF)
    let encRnd = lz4Compress(rnd)
    check(encRnd.len > rnd.len) # incompressible: stored blocks + framing
    check(lz4Decompress(encRnd) == rnd)
    let big = "abcdefgh".repeat(30000) # 240KB: multiple compressed blocks
    let encBig = lz4Compress(big)
    check(encBig.len < big.len div 4)
    check(lz4Decompress(encBig) == big)

  test "lz4 xxh32 known vectors":
    check(xxh32(nil, 0) == 0x02CC5D05'u32)
    check(xxh32("abc") == 0x32D153FF'u32)
    check(xxh32("0123456789ABCDEF") == 0xF9F50986'u32) # lz4 CLI ground truth

  test "lz4 decodes reference cli fixture":
    let lz = handlerFor(".lz4")
    let inp = openInputFile("tests/testdata/interop.txt.lz4")
    let want = openInputFile("tests/testdata/interop.txt")
    let dst = newOutput()
    lz.decompress(inp, dst)
    check(take(dst) == readAll(want))

  test "lz4 decodes multi-block fixture with block checksums":
    let lz = handlerFor(".lz4")
    let dst = newOutput()
    lz.decompress(openInputFile("tests/testdata/big-blocks.lz4"), dst)
    let back = take(dst)
    check(back.len == 220000)
    check(back[0 ..< 64] == "abcdefghabcdefgh".repeat(4))
    check(back[^96 .. ^1] == "xyzzy-plugh-".repeat(8))

  test "lz4 content-size frame decodes":
    let payload = "sized content ".repeat(100)
    let enc = lz4Compress(payload)
    var desc = newString(10)
    desc[0] = char(0x6C) # FLG: content size + content checksum
    desc[1] = char(0x40)
    let sz = payload.len.uint64
    for i in 0 ..< 8:
      desc[2 + i] = char((sz shr (8 * i)) and 0xFF)
    let hc = xxh32(unsafeAddr desc[0], 10)
    let frame = "\x04\x22\x4D\x18" & desc &
      char((hc shr 8) and 0xFF) & enc[7 .. ^1]
    check(lz4Decompress(frame) == payload)

  test "lz4 corrupt input raises":
    let lz = handlerFor(".lz4")
    expect(Lz4Error):
      let dst = newOutput()
      lz.decompress(openInputString("definitely not lz4!!!"), dst)

  test "lz4 bad content checksum raises":
    let good = lz4Compress("hello world".repeat(10))
    var bad = good
    bad[^1] = chr(ord(bad[^1]) xor 0xFF)
    expect(Lz4Error):
      discard lz4Decompress(bad)

  test "bzip2 round trip via reusable buffer":
    let bz = handlerFor(".bz2")
    let payload = "the quick brown fox jumps over the lazy dog".repeat(20)
    let dst = newOutput()
    bz.compress(openInputString(payload), dst)
    check(outputBytes(dst).len > 0)
    let magic = peek(toInput(dst), 3)
    check(spanLen(magic) == 3)
    let mb = cast[ptr UncheckedArray[byte]](magic.p)
    check(mb[0] == byte('B') and mb[1] == byte('Z') and mb[2] == byte('h'))
    let enc = take(dst)
    let plain = newOutput()
    bz.decompress(openInputString(enc), plain)
    check(take(plain) == payload)

  test "bzip2 empty payload":
    let bz = handlerFor(".bz2")
    let dst = newOutput()
    bz.compress(openInputString(""), dst)
    let enc = take(dst)
    check(enc[0 .. 3] == "BZh6") # default level 6
    let back = newOutput()
    bz.decompress(openInputString(enc), back)
    check(take(back) == "")

  test "bzip2 all byte values round trip":
    let bz = handlerFor(".bz2")
    var s = newString(256)
    for i in 0 ..< 256:
      s[i] = chr(i)
    let dst = newOutput()
    bz.compress(openInputString(s), dst)
    let back = newOutput()
    bz.decompress(toInput(dst), back)
    check(take(back) == s)

  test "bzip2 levels produce valid headers":
    check(bz2Compress("hello world", 1)[0 .. 3] == "BZh1")
    check(bz2Compress("hello world", 9)[0 .. 3] == "BZh9")
    check(bz2Decompress(bz2Compress("level one ".repeat(50), 1)) ==
      "level one ".repeat(50))
    check(bz2Decompress(bz2Compress("level nine ".repeat(50), 9)) ==
      "level nine ".repeat(50))
    expect(Bz2Error):
      discard bz2Compress("x", 10)

  test "bzip2 crc32 known vector":
    check(bzCrcChecksum("") == 0'u32)
    check(bzCrcChecksum("123456789") == 0xFC891918'u32)

  test "bzip2 decodes python reference fixture":
    let bz = handlerFor(".bz2")
    let inp = openInputFile("tests/testdata/interop.txt.bz2")
    let want = openInputFile("tests/testdata/interop.txt")
    let dst = newOutput()
    bz.decompress(inp, dst)
    check(take(dst) == readAll(want))

  test "bzip2 multi-block round trip":
    let payload = "abcdefgh".repeat(30000) # 240KB: 3 blocks at level 1
    let enc = bz2Compress(payload, 1)
    check(enc.len < payload.len div 4)
    check(bz2Decompress(enc) == payload)

  test "bzip2 concatenated streams decode":
    let enc = bz2Compress("first-") & bz2Compress("second")
    check(bz2Decompress(enc) == "first-second")

  test "bzip2 decodes multi-block cli fixture":
    let bz = handlerFor(".bz2")
    let dst = newOutput()
    bz.decompress(openInputFile("tests/testdata/multi-blocks.bz2"), dst)
    let back = take(dst)
    check(back.len == 247200)
    check(back[0 ..< 64] ==
      "The quick brown fox jumps over the lazy dog. Pack my box with fi")

  test "bzip2 corrupt input raises":
    let bz = handlerFor(".bz2")
    expect(Bz2Error):
      let dst = newOutput()
      bz.decompress(openInputString("definitely not bzip2!!"), dst)

  test "bzip2 bad block checksum raises":
    let good = bz2Compress("hello world".repeat(10), 9)
    var bad = good
    bad[12] = chr(ord(bad[12]) xor 0xFF) # inside stored block CRC
    expect(Bz2Error):
      discard bz2Decompress(bad)

  test "bzip2 bad stream checksum raises":
    let good = bz2Compress("hello world".repeat(10), 9)
    var bad = good
    bad[^1] = chr(ord(bad[^1]) xor 0xFF) # inside combined CRC
    expect(Bz2Error):
      discard bz2Decompress(bad)

  test "bzip2 bwt edge cases round trip":
    for s in ["", "a", "aaaa", "abababab", "banana", "mississippi"]:
      var bb = newSeq[byte](s.len)
      for i in 0 ..< s.len:
        bb[i] = byte(s[i])
      let (enc, origin) = bwtEncode(bb)
      var dec = enc
      bwtDecode(dec, origin)
      check(cast[string](dec) == s)

  test "lz4 blocks obey end-of-block parsing restrictions":
    # lz4_Block_format.md: last sequence is literals-only with >= 5 bytes,
    # last match starts >= 12 bytes before block end. liblz4 rejects
    # violations, so enforce structurally (no CLI available in tests).
    proc checkBlocks(enc: string) =
      var pos = 7 # our header: magic(4) + FLG + BD + hc
      while true:
        check(pos + 4 <= enc.len)
        let sz = enc[pos].uint32 or (enc[pos + 1].uint32 shl 8) or
          (enc[pos + 2].uint32 shl 16) or (enc[pos + 3].uint32 shl 24)
        pos += 4
        if sz == 0:
          break # EndMark
        let stored = (sz and 0x80000000'u32) != 0
        let size = (sz and 0x7FFFFFFF'u32).int
        check(pos + size <= enc.len)
        if not stored:
          var p = pos
          let blkEnd = pos + size
          var lastLit = -1
          var endedByMatch = false
          while p < blkEnd:
            let tok = enc[p].uint8
            inc p
            var lit = (tok shr 4).int
            if lit == 15:
              while enc[p] == '\xFF':
                lit += 255
                inc p
              lit += enc[p].uint8.int
              inc p
            p += lit
            lastLit = lit
            if p >= blkEnd:
              endedByMatch = false # trailing literals end the block
              break
            p += 2 # offset
            var ml = (tok and 0x0F).int + 4
            if (tok and 0x0F) == 15:
              while enc[p] == '\xFF':
                ml += 255
                inc p
              ml += enc[p].uint8.int
              inc p
            endedByMatch = true
          check(p == blkEnd)
          check(not endedByMatch) # ends right after literals
          check(lastLit >= 5)
        pos += size
    checkBlocks(lz4Compress("hello world. hello world. hello world. "))
    checkBlocks(lz4Compress("a"))
    checkBlocks(lz4Compress("ab"))
    var rnd = newString(70000)
    var x = 0x9E3779B9'u32
    for i in 0 ..< rnd.len:
      x = x * 1664525'u32 + 1013904223'u32
      rnd[i] = chr((x shr 16) and 0xFF)
    checkBlocks(lz4Compress(rnd))
    checkBlocks(lz4Compress("abcdefgh".repeat(30000)))
    var tiny = ""
    for i in 1 .. 20:
      tiny.add(chr(ord('a') + i mod 26))
      check(lz4Decompress(lz4Compress(tiny)) == tiny)
      checkBlocks(lz4Compress(tiny))
