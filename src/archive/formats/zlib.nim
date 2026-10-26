## Zlib compression format, ported from zlib.go (extension ".zz").
##
## Backend is our own zlibf/flate (RFC 1950/1951, zero-copy in, reusable
## output buffers): no external compression dependency. Header 78 01 /
## 78 9C / 78 DA by level; Adler-32 trailer verified on decompress.

import std/[strutils]
from std/os import splitFile
import ../zlibf
import ../io
import ../types
import ../registry

export zlibf

type Zlib* = object
  compressionLevel*: int ## 0 means DefaultCompression (like Go)

proc extension*(z: Zlib): string = ".zz"
proc mediaType*(z: Zlib): string = "application/zlib"

proc matchZlib*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == ".zz":
    result.byName = true
  if inp != nil:
    let s = peek(inp, 2)
    if spanLen(s) == 2:
      let b = cast[ptr UncheckedArray[byte]](s.p)
      if isValidZlibHeader(b[0], b[1]):
        result.byStream = true

proc openZlibReader*(inp: Input): Input =
  ## One-shot decompress into a fresh buffer (zero-copy input).
  let dst = newOutput()
  try:
    zlibDecompressInto(inp, dst)
  except CatchableError as e:
    raise newException(ArchiveError, "zlib decompress: " & e.msg)
  toInput(dst)

proc registerZlib*(z: Zlib = Zlib()) =
  let h = FormatHandler(ext: ".zz", mediaType: "application/zlib",
      kinds: {fkCompression})
  let zz = z
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchZlib(filename, inp)
  h.compress = proc(inp: Input; dst: Output) {.closure.} =
    zlibf.zlibCompressInto(inp, dst, zz.compressionLevel)
  h.decompress = proc(inp: Input; dst: Output) {.closure.} =
    zlibDecompressInto(inp, dst)
  registerFormat(h)
