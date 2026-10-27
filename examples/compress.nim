## One-shot compression: pick a Format, get bytes back.
## Run: `clue build examples/compress.nim --out:/tmp/compress && /tmp/compress`
##   or `nim c -r --path:../src examples/compress.nim` from the package root
##   (nbrotli must be resolvable: `clue install` fetches it).

import std/strutils
from std/os import getTempDir, joinPath
import archive

block fromStr:
  let payload = "the quick brown fox jumps over the lazy dog ".repeat(50)

  for fmt in [cfGz, cfZlib, cfLz4, cfBz2, cfBrotli]:
    # level 0 = codec default; per-call levels need no re-registration
    let enc = compress(fmt, payload)
    assert decompress(fmt, enc) == payload
    echo $fmt, ": ", payload.len, " -> ", enc.len, " bytes"

  # corrupt input raises the codec's own error type
  try:
    discard decompress(cfGz, "definitely not gzip")
  except CatchableError as e:
    echo "expected failure: ", e.msg

block fromFile:
  # same one-shots, straight to disk: input is memory-mapped, output
  # is written once; paths below are temp-dir dummies, swap in your own
  let src = joinPath(getTempDir(), "compress_demo.txt")
  let enc = src & ".gz"
  let back = src & ".out"
  writeFile(src, "the quick brown fox jumps over the lazy dog ".repeat(50))
  compressFile(cfGz, src, enc)
  decompressFile(cfGz, enc, back)
  assert readFile(back) == readFile(src)
  echo "file round trip ok: ", enc
  