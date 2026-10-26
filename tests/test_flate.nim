import std/[unittest, strutils]
import archive/io
import archive/flate

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
