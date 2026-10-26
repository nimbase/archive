## Brotli compression format, ported from brotli.go.
##
## Backend is nbrotli (hard require, pure Nim, no C bindings).
## Decode coverage is full (q=0..11, large window 10..30).
## Encode is store-only in nbrotli v1, so compress buffers and uses
## compressStore; output is always decodable by the reference `brotli`
## CLI but larger than quality-compressed output.

import std/[strutils]
from std/os import splitFile
import nbrotli
import ../io
import ../types
import ../registry

type Brotli* = object
  quality*: int      ## 0..11, stored for future real encoder
  windowBits*: int   ## 10..24 for store encoder

proc defaultBrotli*(): Brotli = Brotli(quality: 11, windowBits: 16)

proc extension*(b: Brotli): string = ".br"
proc mediaType*(b: Brotli): string = "application/x-br"

proc isAsciiPrintable(data: openArray[byte]): bool =
  if data.len == 0:
    return false
  for c in data:
    if c >= 9 and c <= 13:
      continue
    if c >= 32 and c <= 126:
      continue
    return false
  true

proc isValidBrotliStream*(prefix: Span): bool =
  ## Port of Go isValidBrotliStream: trial-decode up to 1KB.
  if spanLen(prefix) == 0:
    return false
  let n = min(spanLen(prefix), 1024)
  var raw = newSeq[byte](n)
  copyMem(addr raw[0], prefix.p, n)
  var dec = initDecoder()
  dec.feed(raw)
  var output: seq[byte] = @[]
  let res = dec.decodeSome(output, 1024)
  if res == Error:
    return false
  if res == NeedsMoreInput and output.len == 0:
    let b = cast[ptr UncheckedArray[byte]](prefix.p)
    if n >= 4:
      let first = b[0]
      return first == 0x1b or first == 0x0b or first == 0x8b
    return false
  # Avoid stepping on other formats: if the raw prefix matches a
  # registered non-brotli format by stream, do not claim it.
  var probe = newString(n)
  copyMem(addr probe[0], prefix.p, n)
  let probeInp = openInputString(probe)
  for h in registeredFormats():
    if h.ext == ".br":
      continue
    if h.doMatch != nil:
      let mr = h.doMatch("", probeInp)
      if mr.byStream:
        return false
  let totalRead = output.len
  if n > 0 and float(totalRead) / float(n) > 1.0:
    return true
  if isAsciiPrintable(output):
    return true
  if n >= 1:
    let first = cast[ptr UncheckedArray[byte]](prefix.p)[0]
    if first == 0x1b or first == 0x0b or first == 0x8b:
      return true
  false

proc matchBrotli*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == ".br":
    result.byName = true
  if inp != nil:
    if isValidBrotliStream(peek(inp, 1024)):
      result.byStream = true

proc brotliDecompressInto*(inp: Input; dst: Output) =
  ## One-shot decode into the reusable buffer (input copied once into
  ## nbrotli's buffer; output written directly into `dst`).
  let n = remaining(inp)
  if n == 0:
    return
  let s = readSpan(inp, n)
  var raw = newSeq[byte](s.len)
  copyMem(addr raw[0], s.p, s.len)
  let plain =
    try: nbrotli.decompress(raw)
    except BrotliError as e:
      raise newException(ArchiveError,
        "brotli decompress error " & $e.code & ": " & e.msg)
    except CatchableError as e:
      raise newException(ArchiveError, "brotli decompress: " & e.msg)
  if plain.len > 0:
    let w = reserve(dst, plain.len)
    copyMem(w, unsafeAddr plain[0], plain.len)
    advance(dst, plain.len)

proc brotliCompressInto*(inp: Input; dst: Output; wbits = 16) =
  ## Store-encode into the reusable buffer.
  let n = remaining(inp)
  var raw = newSeq[byte](n)
  if n > 0:
    let s = readSpan(inp, n)
    copyMem(addr raw[0], s.p, s.len)
  let enc =
    try: compressStore(raw, wbits)
    except CatchableError as e:
      raise newException(ArchiveError, "brotli compress: " & e.msg)
  if enc.len > 0:
    var tmp = newString(enc.len)
    for i, b in enc:
      tmp[i] = char(b)
    dst.writeStr(tmp)

proc openBrotliReader*(inp: Input): Input =
  ## One-shot decode into a fresh buffer.
  let dst = newOutput()
  brotliDecompressInto(inp, dst)
  toInput(dst)

proc registerBrotli*(b: Brotli = defaultBrotli()) =
  let h = FormatHandler(ext: ".br", mediaType: "application/x-br",
      kinds: {fkCompression})
  let bb = b
  h.doMatch = proc(filename: string; inp: Input): MatchResult {.closure.} =
    matchBrotli(filename, inp)
  h.compress = proc(inp: Input; dst: Output) {.closure.} =
    brotliCompressInto(inp, dst, bb.windowBits)
  h.decompress = proc(inp: Input; dst: Output) {.closure.} =
    brotliDecompressInto(inp, dst)
  registerFormat(h)
