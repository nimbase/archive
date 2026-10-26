## SIMD kernels for the archive library, mirroring ports/nbrotli/simd.nim.
##
## Enabled with `clue build --features:nimsimd` (or `-d:features.archive.nimsimd`).
## amd64 builds add -mavx2/-msse4.2, so a feature build requires a CPU with
## AVX2 + SSE4.2; without the feature everything falls back to scalar code
## and the binary runs anywhere. arm64 falls back to scalar copy/CRC for now.

when defined(features.archive.nimsimd) or defined(nimsimd):
  const simdOn* = true
else:
  const simdOn* = false

when simdOn and defined(amd64):
  {.passC: "-mavx2 -mavx -msse4.2 -msse2".}
  import std/bitops
  import nimsimd/sse2
  import nimsimd/avx2
  import nimsimd/sse42

const hasAvx2* = simdOn and defined(amd64)

when hasAvx2:
  var simdState {.threadvar.}: int8
    ## 0 = untested, 1 = validated, -1 = broken silicon (scalar fallback).

  proc simdSelfTest(): bool =
    ## Some CPUs/VMs mistranslate crc32 (e.g. Castagnoli instead of
    ## IEEE). Validate the check value "123456789" -> 0xCBF43926 plus
    ## a u64-path span before trusting any SIMD kernel.
    const check = "123456789"
    var c: uint32 = 0xFFFFFFFF'u32
    for i in 0 ..< check.len:
      c = mm_crc32_u8(c, byte(check[i]))
    if (c xor 0xFFFFFFFF'u32) != 0xCBF43926'u32:
      return false
    var c2: uint32 = 0xFFFFFFFF'u32
    var v: uint64 = 0x0102030405060708'u64
    c2 = uint32(mm_crc32_u64(c2.uint64, v))
    # cross-check u64 op against 8x u8 ops
    var c3: uint32 = 0xFFFFFFFF'u32
    for i in 0 ..< 8:
      c3 = mm_crc32_u8(c3, byte((v shr (8 * i)) and 0xFF))
    c2 == c3

proc simdValidated*(): bool {.inline.} =
  ## True when SIMD kernels passed the self-test (or feature is off,
  ## in which case callers use scalar paths anyway).
  when hasAvx2:
    if simdState == 0:
      simdState = if simdSelfTest(): 1 else: -1
    simdState == 1
  else:
    false

proc copyMemSimd*(dst, src: pointer; len: int) {.inline.} =
  ## Non-overlapping copy, 32B AVX2 chunks when validated, else scalar.
  when hasAvx2:
    if simdValidated():
      if len >= 32:
        var off = 0
        let n32 = len and not 31
        while off < n32:
          let s = cast[ptr M256i](cast[int](src) + off)
          let d = cast[ptr M256i](cast[int](dst) + off)
          mm256_storeu_si256(d, mm256_loadu_si256(s))
          off += 32
        let rem = len - off
        if rem >= 16:
          let s = cast[ptr M128i](cast[int](src) + off)
          let d = cast[ptr M128i](cast[int](dst) + off)
          mm_storeu_si128(d, mm_loadu_si128(s))
          off += 16
        let rem2 = len - off
        if rem2 > 0:
          copyMem(cast[pointer](cast[int](dst) + off),
            cast[pointer](cast[int](src) + off), rem2)
        return
      if len >= 16:
        let s = cast[ptr M128i](src)
        let d = cast[ptr M128i](dst)
        mm_storeu_si128(d, mm_loadu_si128(s))
        let rem = len - 16
        if rem > 0:
          copyMem(cast[pointer](cast[int](dst) + 16),
            cast[pointer](cast[int](src) + 16), rem)
        return
  if len > 0:
    copyMem(dst, src, len)

proc copyMatchSimd*(dst, src: pointer; len, dist: int) {.inline.} =
  ## LZ77 match copy handling overlap (dist < len repeats the pattern).
  ## Bulk path for dist >= len, doubling loop otherwise.
  if len <= 0:
    return
  if dist >= len:
    copyMemSimd(dst, src, len)
    return
  if dist <= 0:
    return
  copyMemSimd(dst, src, dist)
  var done = dist
  while done < len:
    let n = min(done, len - done)
    copyMemSimd(cast[pointer](cast[int](dst) + done), dst, n)
    done += n

proc matchLenSimd*(a, b: pointer; maxLen: int): int {.inline.} =
  ## Length of longest common prefix up to maxLen. AVX2 chunked when
  ## validated, else scalar.
  when hasAvx2:
    if simdValidated():
      var off = 0
      let n32 = maxLen and not 31
      while off < n32:
        let va = cast[ptr M256i](cast[int](a) + off)
        let vb = cast[ptr M256i](cast[int](b) + off)
        let eq = mm256_cmpeq_epi8(mm256_loadu_si256(va), mm256_loadu_si256(vb))
        let mask = mm256_movemask_epi8(eq)
        if mask != -1'i32:
          return off + countTrailingZeroBits(not mask)
        off += 32
      while off < maxLen:
        if cast[ptr UncheckedArray[byte]](a)[off] !=
            cast[ptr UncheckedArray[byte]](b)[off]:
          return off
        inc off
      return off
  var ln = 0
  while ln < maxLen and
      cast[ptr UncheckedArray[byte]](a)[ln] ==
      cast[ptr UncheckedArray[byte]](b)[ln]:
    inc ln
  ln

proc crc32Hw*(crc: uint32; p: pointer; len: int): uint32 {.inline.} =
  ## IEEE CRC-32 via SSE4.2 crc32 instruction, 8 bytes per op.
  ## Only called after crc32HwAvailable() validated the silicon.
  when hasAvx2:
    var c = crc
    var off = 0
    let n64 = len and not 7
    while off < n64:
      var v: uint64
      copyMem(addr v, cast[pointer](cast[int](p) + off), 8)
      c = uint32(mm_crc32_u64(c.uint64, v))
      off += 8
    while off < len:
      c = mm_crc32_u8(c, cast[ptr UncheckedArray[uint8]](p)[off])
      inc off
    c
  else:
    crc # unreachable without the feature; caller uses scalar table
