## Bzip2 compression format, ported from bz2.go (extension ".bz2").
##
## Backend is our own bz2f (BWT + MTF + Huffman, zero-copy in, reusable
## output buffers): no external compression dependency. Header "BZh"
## plus block-size digit; per-block and combined CRCs verified.

import std/[strutils]
from std/os import splitFile
import ../bz2f
import ../io
import ../types

export bz2f

type Bz2* = object
  compressionLevel*: int ## 0 means DefaultCompression (6); 1..9 select up to 100k..900k RLE1 bytes per block

proc extension*(b: Bz2): string = ".bz2"
proc mediaType*(b: Bz2): string = "application/x-bzip2"

proc matchBz2*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == $fmtBz2:
    result.byName = true
  if inp != nil:
    let s = peek(inp, 3)
    if spanLen(s) == 3:
      let b = cast[ptr UncheckedArray[byte]](s.p)
      if b[0] == byte('B') and b[1] == byte('Z') and b[2] == byte('h'):
        result.byStream = true

proc openBz2Reader*(inp: Input): Input =
  ## One-shot decompress into a fresh buffer (zero-copy input).
  let dst = newOutput()
  try:
    bz2DecompressInto(inp, dst)
  except CatchableError as e:
    raise newException(ArchiveError, "bzip2 decompress: " & e.msg)
  toInput(dst)

