## LZ4 compression format, ported from lz4.go (extension ".lz4").
##
## Backend is our own lz4f (LZ4 frame format, zero-copy in, reusable
## output buffers): no external compression dependency. Magic
## 04 22 4D 18, independent 64KB blocks, content checksum.

import std/[strutils]
from std/os import splitFile
import ../lz4f
import ../io
import ../types
import ../registry

export lz4f

type Lz4* = object
  compressionLevel*: int ## accepted for API parity (fast path always)

proc extension*(l: Lz4): string = ".lz4"
proc mediaType*(l: Lz4): string = "application/x-lz4"

proc matchLz4*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == ".lz4":
    result.byName = true
  if inp != nil:
    let s = peek(inp, 4)
    if spanLen(s) == 4:
      let b = cast[ptr UncheckedArray[byte]](s.p)
      # on-disk magic bytes 04 22 4D 18 (matches Go's lz4Header)
      if b[0] == 0x04 and b[1] == 0x22 and b[2] == 0x4D and b[3] == 0x18:
        result.byStream = true

proc openLz4Reader*(inp: Input): Input =
  ## One-shot decompress into a fresh buffer (zero-copy input).
  let dst = newOutput()
  try:
    lz4DecompressInto(inp, dst)
  except CatchableError as e:
    raise newException(ArchiveError, "lz4 decompress: " & e.msg)
  toInput(dst)

proc registerLz4*(l: Lz4 = Lz4()) =
  let h = FormatHandler(ext: ".lz4", mediaType: "application/x-lz4",
      kinds: {fkCompression})
  let ll = l
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchLz4(filename, inp)
  h.compress = proc(inp: Input; dst: Output) {.closure.} =
    lz4f.lz4CompressInto(inp, dst, ll.compressionLevel)
  h.decompress = proc(inp: Input; dst: Output) {.closure.} =
    lz4DecompressInto(inp, dst)
  registerFormat(h)
