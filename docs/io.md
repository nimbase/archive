# I/O core (src/archive/io.nim)

Zero-copy I/O core. Replaces streams throughout the library.

- `Input` is a read cursor over a memory-mapped file or an owned/shared string.
- `Output` is a reusable growable buffer. Pass the same `Output` across calls and `reset` it to avoid allocation.
- `Span` is a borrowed pointer + length view, valid only while its parent lives.

## Constants (src/archive/io.nim:13-22,193)

| name | value | use |
| ---- | ----- | --- |
| `StreamChunkSize` | 65536 | streaming chunk for to-disk paths |
| `StreamWindowSize` | 32768 | DEFLATE sliding window |
| `StreamBufCap` | 96 KB | max buffered bytes during streaming inflate |
| `MaxScratchCap` | 1 MB | reusable pool trim threshold |
| `ReleaseGranularity` | 1 MB | page-release chunk |

## Types

```nim
MapHandle* = ref object  # owns read-only mmap, close is idempotent
Input* = ref object of RootObj   # str/map/keep/base/len/pos (private)
Output* = ref object of RootObj  # buf: string capacity, len: int used
Span* = object  # p*: pointer, len*: int, borrowed
IoError* = object of CatchableError
```

## Ownership and lifetimes

- `openInputFile` mmaps; `close(inp)` is nil-safe and idempotent. Empty files become string-backed (no mmap).
- `openInputString` shares the string (refcounted, no copy). Caller may drop `s` after; `Input.str` keeps it.
- `openInputCopy` / `openInputBytes` own a fresh copy.
- `openInputBorrowed(p, len)` retains nothing; caller must keep memory alive; only for one-shot calls returning before the caller frame exits.
- `openInputView(s, keep)` borrows `s` but retains `keep` (usually parent `Input` / `Output`).
- `toInput(dst)` retains `dst` via `keep`; mutating `dst` after invalidates cursor semantics.
- `peek` / `readSpan` / `spanAt` / `outputBytes` return borrowed `Span`; valid only while parent lives and (for `Output`) until next growing write or `reset`.
- `reserve` pointer is valid only until the next growing op; pair with `advance`.
- Reuse: `reset` keeps capacity, `resetBounded` drops excess over `MaxScratchCap`. `newOutput(cap)` pre-reserves without setting `len`.
- `releaseSpanPages` is best-effort `madvise(DONTNEED)`, never raises.

## Procs

### Mapping and inputs (src/archive/io.nim:58-126)

| proc | behavior | errors |
| ---- | -------- | ------ |
| `openMap(path)` | read-only mmap | OS / MemFile errors |
| `closeMap(h)` | idempotent close | swallows errors |
| `close(inp)` | nil-safe, clears refs/cursor | none |
| `openInputFile(path)` | mmap input | open failure |
| `openInputString(s)` | shared-string input | none |
| `openInputCopy(p, len)` | copying input | none (assumes valid `p`) |
| `openInputBytes(data)` | copying input | none |
| `openInputBorrowed(p, len)` | non-owning | none (caller keeps alive) |
| `openInputView(s, keep)` | retaining view | none |

### Outputs (src/archive/io.nim:131-157,278-282,383-416)

| proc | behavior |
| ---- | -------- |
| `newOutput(cap=0)` | `cap` reserves capacity, `len=0` |
| `reset(dst)` | `len=0`, keep capacity |
| `resetBounded(dst, maxCap)` | `len=0`, drop `buf` if oversized |
| `outputCap(dst)` | `buf.len` |
| `ensureFixedCap(dst, cap)` | grow-only |
| `toInput(dst)` | retaining view of used bytes |
| `take(dst)` | copy used bytes to exact-size string, reset `len` |
| `writeBytes/writeStr/writeByte` | append |
| `outputBytes(dst)` | borrowed used-bytes view |
| `reserve(dst, n) / advance(dst, n)` | external write; `advance` raises `IoError` if out of range |

### Cursors (src/archive/io.nim:292-348,424-440)

| proc | behavior |
| ---- | -------- |
| `inputLen/inputPos/remaining` | accessors |
| `seek(inp, pos)` | raises `IoError` if outside `[0, len]` |
| `skip(inp, n)` | via `seek` |
| `peek(inp, n)` | borrowed up-to-`n` at cursor, no advance; empty if exhausted |
| `readSpan(inp, n)` | `peek` + advance |
| `readByte` | raises `IoError` past end |
| `readBytes(n)` / `readAll` | copying reads |
| `byteAt(off)` / `spanAt(off, n)` | absolute; `spanAt` raises `IoError` on bad range |
| `basePointer(inp)` | for offset arithmetic only, no dereference |
| `spanLen, u16le, u32le` | unchecked LE loads, caller bounds-checks |
| `spanToString, spanEqual` | copy / compare |

### File flushing (src/archive/io.nim:197-255,350)

Chunked writes with optional CRC accounting. `flushKeepWindow` writes all but `keep` bytes and compacts; `flushAllToFile` flushes everything. `writeSpanToFile` writes a span in 1 MB chunks. `copyStreamToFile` copies an `Input` to `dest` in 64 KB chunks. Short writes raise `IoError` / `IOError`.

```nim
import archive/io
let dst = newOutput()
compressInto(cfGz, openInputString("hello ".repeat(100)), dst)
let back = newOutput()
decompressInto(cfGz, toInput(dst), back)
assert take(back) == "hello ".repeat(100)
```
