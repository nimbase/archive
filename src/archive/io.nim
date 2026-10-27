## Zero-copy I/O core: memfile-backed inputs, reusable outputs.
##
## Replaces streams throughout the library. `Input` is a read cursor over
## either a memory-mapped file (zero-copy, no read syscalls, no buffer
## copies) or an owned/shared string. `Output` is a reusable growable
## buffer: pass the same Output across calls and `reset` it to avoid
## repeated allocation. `Span` is a borrowed pointer+length view, valid
## only while its parent Input/Output lives.

import std/memfiles
import ./crc32

const StreamChunkSize* = 65536
  ## Fixed-size working chunk for streaming extraction. All to-disk
  ## paths reuse buffers of this size; never scales with entry size.
const StreamWindowSize* = 32768
  ## DEFLATE sliding window (RFC 1951). Retained across flushes so
  ## matches referencing up to 32KB back stay valid.
const StreamBufCap* = StreamChunkSize + StreamWindowSize
  ## Max buffered bytes during streaming inflate (96KB).
const MaxScratchCap* = 1 shl 20
  ## Sensible maximum pool size (1MB). Reusable scratch buffers that
  ## grow beyond this are trimmed on reset to release excess.

type
  MapHandle* = ref object
    ## Owns a read-only file mapping. Closed idempotently.
    mf: MemFile
    size*: int
    closed: bool

  Input* = ref object of RootObj
    ## Read cursor. One of `str` (string-backed) or `map` (mmap-backed)
    ## keeps the memory alive; `keep` extends that to derived views
    ## (e.g. Output converted via toInput).
    str: string
    map: MapHandle
    keep: RootRef
    base: pointer
    len: int
    pos: int

  Output* = ref object of RootObj
    ## Reusable write buffer. `buf` may over-allocate; `len` is used.
    buf: string
    len*: int

  Span* = object
    ## Borrowed view into Input/Output memory. Copy is a memcpy;
    ## the parent must outlive any use.
    p*: pointer
    len*: int

  IoError* = object of CatchableError

# ---------- file mapping ----------

proc closeMap*(h: MapHandle) =
  if h != nil and not h.closed:
    h.closed = true
    try:
      close(h.mf)
    except CatchableError:
      discard

proc openMap*(path: string): MapHandle =
  ## Memory-map a file read-only. Empty files map to size 0 (no mmap).
  result = MapHandle()
  var mf = memfiles.open(path, fmRead)
  result.mf = mf
  result.size = mf.size

proc close*(inp: Input) =
  ## Release the mapping/string reference. Idempotent.
  if inp == nil:
    return
  if inp.map != nil:
    closeMap(inp.map)
    inp.map = nil
  inp.str = ""
  inp.keep = nil
  inp.base = nil
  inp.len = 0
  inp.pos = 0

# ---------- constructors ----------

proc baseOf(s: string): pointer =
  if s.len == 0: nil
  else: unsafeAddr s[0]

proc openInputFile*(path: string): Input =
  ## Zero-copy input over a memory-mapped file.
  let h = openMap(path)
  result = Input(map: h, base: h.mf.mem, len: h.size, pos: 0)
  if h.size == 0:
    # mmap of an empty file is invalid; keep string-backed empty.
    closeMap(h)
    result.map = nil
    result.base = nil

proc openInputString*(s: string): Input =
  ## Input sharing `s` (no copy; string is refcounted).
  Input(str: s, base: baseOf(s), len: s.len, pos: 0)

proc openInputCopy*(p: pointer; length: int): Input =
  ## Input owning a copy of [p, p+length).
  var s = newString(length)
  if length > 0:
    copyMem(addr s[0], p, length)
  openInputString(s)

proc openInputBytes*(data: openArray[byte]): Input =
  var s = newString(data.len)
  if data.len > 0:
    copyMem(addr s[0], unsafeAddr data[0], data.len)
  openInputString(s)

proc openInputView*(s: Span; keep: RootRef): Input =
  ## Input borrowing a span; `keep` (usually the parent Input/Output)
  ## is retained so the memory outlives this cursor.
  Input(keep: keep, base: s.p, len: s.len, pos: 0)

proc newOutput*(cap = 0): Output =
  result = Output()
  if cap > 0:
    result.buf = newString(cap)
    result.buf.setLen(0)

proc reset*(dst: Output) =
  ## Reuse the buffer without freeing capacity.
  dst.len = 0

proc resetBounded*(dst: Output, maxCap = MaxScratchCap) =
  ## Reuse the buffer, releasing excess when it grew oversized.
  ## Call between entries so a single huge entry cannot pin a huge
  ## buffer for the rest of the extraction (pool stays bounded).
  dst.len = 0
  if dst.buf.len > maxCap:
    dst.buf = ""
    # Next ensureCap reallocates on demand, bounded by actual use.

proc outputCap*(dst: Output): int =
  ## Current buffer capacity (bytes retained for reuse).
  dst.buf.len

proc ensureFixedCap*(dst: Output, cap: int) =
  ## Ensure at least `cap` bytes of capacity for streaming reuse.
  ## Called once per extraction; streaming paths flush before exceeding
  ## it, so capacity never grows beyond `cap` afterwards.
  if dst.buf.len < cap:
    dst.buf.setLen(cap)
    # Output tracks used in dst.len, capacity in buf.len. setLen
    # preserves existing bytes; used count stays in dst.len.

when defined(linux) or defined(macosx):
  proc c_madvise(a1: pointer, a2: int, a3: cint): cint {.
    importc: "madvise", header: "<sys/mman.h>", gcsafe.}

proc releaseSpanPages*(s: Span) =
  ## Best-effort release of file-backed pages after streaming an entry.
  ## Keeps RSS bounded to working buffers + metadata, not total archive.
  ## `madvise(DONTNEED)` drops clean mapped pages; subsequent access
  ## would re-fault from disk, but streamed ranges are never re-read.
  ## No-op on failure or unsupported platforms; never raises, gcsafe.
  when defined(linux) or defined(macosx):
    if s.len <= 0 or s.p == nil:
      return
    const PageSize = 4096
    const MadvDontNeed = 4.cint
    let startAddr = cast[int](s.p)
    let alignedStart = startAddr and not (PageSize - 1)
    let endAddr = startAddr + s.len
    let alignedEnd = (endAddr + PageSize - 1) and not (PageSize - 1)
    let total = alignedEnd - alignedStart
    if total <= 0:
      return
    try:
      discard c_madvise(cast[pointer](alignedStart), total, MadvDontNeed)
    except CatchableError:
      discard

const ReleaseGranularity* = 1 shl 20
  ## Input pages are released in 1MB chunks during streaming so even a
  ## single huge entry stays bounded (working set ~1MB + 96KB scratch).

proc flushKeepWindow*(dst: Output, f: File, keep: int,
    crc: var uint32, total: var int) =
  ## Write all but the last `keep` buffered bytes to `f`, updating the
  ## running (inverted) `crc` and `total`, then compact the retained
  ## window to the front. Keeps peak buffered at StreamBufCap.
  ## `crc` starts as 0xFFFFFFFF; caller xors at the end.
  let toWrite = dst.len - keep
  if toWrite <= 0:
    return
  crc = crc32Update(crc, addr dst.buf[0], toWrite)
  var off = 0
  while off < toWrite:
    let n = writeBuffer(f,
      cast[pointer](cast[int](unsafeAddr dst.buf[0]) + off), toWrite - off)
    if n <= 0:
      raise newException(IoError, "short write")
    off += n
  total += toWrite
  if keep > 0:
    copyMem(addr dst.buf[0], addr dst.buf[toWrite], keep)
  dst.len = keep

proc flushAllToFile*(dst: Output, f: File, crc: var uint32, total: var int) =
  ## Final flush: write everything buffered, no window retained.
  flushKeepWindow(dst, f, 0, crc, total)

proc outputBaseAddr*(dst: Output): pointer =
  ## Base pointer of the reusable buffer for explicit checksum updates.
  ## Lets checksum-agnostic flushes (Adler, xxHash) scan flushed bytes
  ## before compaction while keeping `buf` itself private.
  if dst.buf.len == 0:
    nil
  else:
    unsafeAddr dst.buf[0]

proc flushKeepWindowNoCrc*(dst: Output, f: File, keep: int): int =
  ## Checksum-agnostic flush: write all but the last `keep` bytes,
  ## compact the window, return bytes written. Caller updates its own
  ## running checksum over `[base, base+result)` before/after.
  let toWrite = dst.len - keep
  if toWrite <= 0:
    return 0
  var off = 0
  while off < toWrite:
    let n = writeBuffer(f,
      cast[pointer](cast[int](unsafeAddr dst.buf[0]) + off), toWrite - off)
    if n <= 0:
      raise newException(IoError, "short write")
    off += n
  if keep > 0:
    copyMem(addr dst.buf[0], addr dst.buf[toWrite], keep)
  dst.len = keep
  toWrite

proc flushAllNoCrc*(dst: Output, f: File): int =
  ## Final checksum-agnostic flush; returns bytes written.
  flushKeepWindowNoCrc(dst, f, 0)

proc writeSpanToFile*(s: Span, f: File, crc: var uint32, total: var int) =
  ## Zero-copy stored path: CRC + write directly from the mapped span,
  ## no intermediate heap copy. Chunked in 1MB pieces with page release
  ## so even a huge stored entry never pins more than the working set;
  ## peak stays bounded, not proportional to entry size.
  if s.len == 0:
    return
  var off = 0
  while off < s.len:
    let chunk = min(s.len - off, ReleaseGranularity)
    let p = cast[pointer](cast[int](s.p) + off)
    crc = crc32Update(crc, p, chunk)
    var woff = 0
    while woff < chunk:
      let n = writeBuffer(f,
        cast[pointer](cast[int](p) + woff), chunk - woff)
      if n <= 0:
        raise newException(IoError, "short write")
      woff += n
    total += chunk
    releaseSpanPages(Span(p: p, len: chunk))
    off += chunk

proc toInput*(dst: Output): Input =
  ## Zero-copy read view over an Output's used bytes.
  Input(keep: dst, base: baseOf(dst.buf), len: dst.len, pos: 0)

proc take*(dst: Output): string =
  ## Move the used bytes out of `dst` as an exact-size string, reusing
  ## capacity for the next fill. Resets length to zero.
  result = newString(dst.len)
  if dst.len > 0:
    copyMem(addr result[0], addr dst.buf[0], dst.len)
  dst.len = 0

# ---------- cursor ----------

proc inputLen*(inp: Input): int = inp.len
proc inputPos*(inp: Input): int = inp.pos
proc remaining*(inp: Input): int = inp.len - inp.pos

proc seek*(inp: Input; pos: int) =
  if pos < 0 or pos > inp.len:
    raise newException(IoError, "seek out of range")
  inp.pos = pos

proc skip*(inp: Input; n: int) =
  seek(inp, inp.pos + n)

proc peek*(inp: Input; n: int): Span =
  ## Borrowed view of up to n bytes at the cursor (no advance).
  let avail = max(0, inp.len - inp.pos)
  let takeN = min(n, avail)
  if takeN == 0:
    Span(p: nil, len: 0)
  else:
    Span(p: cast[pointer](cast[int](inp.base) + inp.pos), len: takeN)

proc readSpan*(inp: Input; n: int): Span =
  ## Borrowed view of up to n bytes, advancing the cursor.
  result = peek(inp, n)
  inp.pos += result.len

proc readByte*(inp: Input): byte =
  if inp.pos >= inp.len:
    raise newException(IoError, "read past end of input")
  result = cast[ptr UncheckedArray[byte]](inp.base)[inp.pos]
  inc inp.pos

proc readBytes*(inp: Input; n: int): string =
  ## Copying read.
  let s = readSpan(inp, n)
  result = newString(s.len)
  if s.len > 0:
    copyMem(addr result[0], s.p, s.len)

proc readAll*(inp: Input): string =
  readBytes(inp, remaining(inp))

proc byteAt*(inp: Input; off: int): byte =
  if off < 0 or off >= inp.len:
    raise newException(IoError, "offset out of range")
  cast[ptr UncheckedArray[byte]](inp.base)[off]

proc spanAt*(inp: Input; off, n: int): Span =
  ## Borrowed absolute view (bounds-checked).
  if off < 0 or n < 0 or off + n > inp.len:
    raise newException(IoError, "span out of range")
  if n == 0:
    Span(p: nil, len: 0)
  else:
    Span(p: cast[pointer](cast[int](inp.base) + off), len: n)

proc basePointer*(inp: Input): pointer = inp.base

proc copyStreamToFile*(inp: Input; dest: string) =
  ## Streams an Input to a file in 64KB chunks (zero-copy views, no
  ## intermediate whole-content string). Used by archive extraction to
  ## keep peak memory proportional to one chunk, not the entry.
  var f: File
  if not open(f, dest, fmWrite):
    raise newException(IOError, "cannot open for writing: " & dest)
  try:
    while remaining(inp) > 0:
      let chunk = readSpan(inp, min(remaining(inp), 65536))
      if chunk.len == 0:
        break
      var off = 0
      while off < chunk.len:
        let n = writeBuffer(f,
          cast[pointer](cast[int](chunk.p) + off), chunk.len - off)
        if n <= 0:
          raise newException(IOError, "short write: " & dest)
        off += n
  finally:
    close(f)

# ---------- output writes ----------

proc ensureCap(dst: Output; additional: int) =
  let need = dst.len + additional
  if need <= dst.buf.len:
    return
  var cap = max(dst.buf.len * 2, 64)
  if cap < need:
    cap = need
  dst.buf.setLen(cap)

proc writeBytes*(dst: Output; p: pointer; n: int) =
  if n <= 0:
    return
  ensureCap(dst, n)
  copyMem(addr dst.buf[dst.len], p, n)
  dst.len += n

proc writeStr*(dst: Output; s: string) =
  if s.len > 0:
    writeBytes(dst, unsafeAddr s[0], s.len)

proc writeByte*(dst: Output; c: char | byte) =
  ensureCap(dst, 1)
  dst.buf[dst.len] = char(c)
  inc dst.len

proc outputBytes*(dst: Output): Span =
  ## Borrowed view of used bytes.
  if dst.len == 0:
    Span(p: nil, len: 0)
  else:
    Span(p: unsafeAddr dst.buf[0], len: dst.len)

proc reserve*(dst: Output; additional: int): pointer =
  ## Ensure room for `additional` bytes, return the write pointer at
  ## `dst.len`. Caller must call `advance` after filling. The pointer
  ## is valid only until the next growing operation.
  ensureCap(dst, additional)
  if dst.buf.len == 0:
    nil
  else:
    addr dst.buf[dst.len]

proc advance*(dst: Output; n: int) =
  ## Commit n bytes written via `reserve`.
  if n < 0 or dst.len + n > dst.buf.len:
    raise newException(IoError, "advance out of range")
  dst.len += n

# ---------- span helpers (LE integers, memcmp) ----------

proc spanLen*(s: Span): int = s.len

proc u16le*(s: Span; off: int): int =
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[off].int or (b[off + 1].int shl 8)

proc u32le*(s: Span; off: int): uint32 =
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[off].uint32 or (b[off + 1].uint32 shl 8) or
    (b[off + 2].uint32 shl 16) or (b[off + 3].uint32 shl 24)

proc spanToString*(s: Span): string =
  result = newString(s.len)
  if s.len > 0:
    copyMem(addr result[0], s.p, s.len)

proc spanEqual*(a: Span; s: string): bool =
  if a.len != s.len:
    return false
  if a.len == 0:
    return true
  equalMem(a.p, unsafeAddr s[0], a.len)
