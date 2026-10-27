## One-shot compression: pick a Format, get bytes back.
## Run: `clue build examples/compress.nim --out:/tmp/compress && /tmp/compress`
##   or `nim c -r --path:../src examples/compress.nim` from the package root
##   (nbrotli must be resolvable: `clue install` fetches it).

import std/strutils
import archive
import archive/registry   # Format enum
import archive/types      # ArchiveError

let payload = "the quick brown fox jumps over the lazy dog ".repeat(50)

for fmt in [fmtGz, fmtZlib, fmtLz4, fmtBz2, fmtBrotli]:
  # level 0 = codec default; per-call levels need no re-registration
  let enc = compress(fmt, payload)
  assert decompress(fmt, enc) == payload
  echo $fmt, ": ", payload.len, " -> ", enc.len, " bytes"

# corrupt input raises the codec's own error type
try:
  discard decompress(fmtGz, "definitely not gzip")
except CatchableError as e:
  echo "expected failure: ", e.msg
