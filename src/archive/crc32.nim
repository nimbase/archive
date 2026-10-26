## CRC-32 (IEEE) ported from Go hash/crc32.
##
## Table-driven scalar core; when the `nimsimd` feature is on, bulk
## updates use the SSE4.2 hardware instruction, but only after a
## runtime self-test (some VMs mistranslate crc32 to Castagnoli).

import ./simd

const poly = 0xEDB88320'u32

proc buildTable(): array[256, uint32] =
  for i in 0 .. 255:
    var c = i.uint32
    for _ in 0 ..< 8:
      if (c and 1) != 0:
        c = (c shr 1) xor poly
      else:
        c = c shr 1
    result[i] = c

const ieeeTable = buildTable()

proc crc32UpdateScalar(crc: uint32; p: pointer; length: int): uint32 =
  result = crc
  let b = cast[ptr UncheckedArray[byte]](p)
  for i in 0 ..< length:
    result = ieeeTable[(result xor b[i].uint32) and 0xFF] xor (result shr 8)

proc crc32Update*(crc: uint32; p: pointer; length: int): uint32 =
  ## Running update over an inverted crc (start with 0xFFFFFFFF).
  ## Hardware path only after silicon validation (see simdValidated).
  when simdOn:
    if simdValidated():
      crc32Hw(crc, p, length)
    else:
      crc32UpdateScalar(crc, p, length)
  else:
    crc32UpdateScalar(crc, p, length)

proc crc32Update*(crc: uint32; data: openArray[byte]): uint32 =
  if data.len == 0:
    crc
  else:
    crc32Update(crc, unsafeAddr data[0], data.len)

proc crc32Update*(crc: uint32; data: string): uint32 =
  if data.len == 0:
    crc
  else:
    crc32Update(crc, unsafeAddr data[0], data.len)

proc crc32Checksum*(data: openArray[byte]): uint32 =
  crc32Update(0xFFFFFFFF'u32, data) xor 0xFFFFFFFF'u32

proc crc32Checksum*(data: string): uint32 =
  crc32Update(0xFFFFFFFF'u32, data) xor 0xFFFFFFFF'u32
