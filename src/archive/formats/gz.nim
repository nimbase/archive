## Gzip compression format, ported from gz.go.
##
## Backend is our own gzipf/flate (RFC 1951/1952, zero-copy in, reusable
## output buffers): no external compression dependency. Magic 1f 8b,
## default level when 0, multistream unless disabled.

import std/[strutils]
from std/os import splitFile
import ../gzipf
import ../io
import ../types
import ../registry

export gzipf

type Gz* = object
  compressionLevel*: int  ## 0 means DefaultCompression (like Go)
  disableMultistream*: bool
  multithreaded*: bool    ## accepted for API parity; encoder is single-threaded

const gzMagic* = [0x1f'u8, 0x8b'u8]

proc extension*(g: Gz): string = ".gz"
proc mediaType*(g: Gz): string = "application/gzip"

proc matchGz*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == formatExt[fmtGz]:
    result.byName = true
  if inp != nil:
    let s = peek(inp, gzMagic.len)
    if spanLen(s) == gzMagic.len and
        cast[ptr UncheckedArray[byte]](s.p)[0] == gzMagic[0] and
        cast[ptr UncheckedArray[byte]](s.p)[1] == gzMagic[1]:
      result.byStream = true

proc openGzReader*(inp: Input; multistream = true): Input =
  ## One-shot decompress into a fresh buffer (zero-copy input).
  let dst = newOutput()
  try:
    gzipDecompressInto(inp, dst, multistream)
  except CatchableError as e:
    raise newException(ArchiveError, "gzip decompress: " & e.msg)
  toInput(dst)

proc registerGz*(g: Gz = Gz()) =
  let h = newHandler(fmtGz)
  let gg = g
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchGz(filename, inp)
  h.compress = proc(inp: Input; dst: Output) {.closure.} =
    gzipf.gzipCompressInto(inp, dst, gg.compressionLevel)
  h.decompress = proc(inp: Input; dst: Output) {.closure.} =
    gzipDecompressInto(inp, dst, not gg.disableMultistream)
  registerFormat(h)
