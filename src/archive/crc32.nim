## CRC-32 (IEEE) ported from Go hash/crc32.
##
## Slicing-by-8 scalar core: eight independent table lookups per 8 input
## bytes break the serial dependency chain of the byte-at-a-time loop;
## short inputs and tail bytes use the single-byte table. Same IEEE
## result as the classic table (verified by differential fuzz against it).
## Archive codecs stay scalar pure Nim; brotli via nbrotli carries its
## own internal SIMD. (x86 `crc32` is Castagnoli, not IEEE, so the
## hardware instruction cannot be used here.)

const poly = 0xEDB88320'u32

proc buildSliceTable(): array[8, array[256, uint32]] =
  for i in 0 .. 255:
    var c = i.uint32
    for _ in 0 ..< 8:
      if (c and 1) != 0:
        c = (c shr 1) xor poly
      else:
        c = c shr 1
    result[0][i] = c
  for i in 0 .. 255:
    var c = result[0][i]
    for k in 1 .. 7:
      c = result[0][c and 0xFF] xor (c shr 8)
      result[k][i] = c

const sliceTable = buildSliceTable()

proc crc32Update*(crc: uint32; p: pointer; length: int): uint32 =
  ## Running update over an inverted crc (start with 0xFFFFFFFF).
  result = crc
  let b = cast[ptr UncheckedArray[byte]](p)
  var i = 0
  let n8 = length and not 7
  while i < n8:
    let a = (b[i].uint32 or (b[i + 1].uint32 shl 8) or
      (b[i + 2].uint32 shl 16) or (b[i + 3].uint32 shl 24)) xor result
    let d = b[i + 4].uint32 or (b[i + 5].uint32 shl 8) or
      (b[i + 6].uint32 shl 16) or (b[i + 7].uint32 shl 24)
    result = sliceTable[0][(d shr 24) and 0xFF] xor
      sliceTable[1][(d shr 16) and 0xFF] xor
      sliceTable[2][(d shr 8) and 0xFF] xor
      sliceTable[3][d and 0xFF] xor
      sliceTable[4][(a shr 24) and 0xFF] xor
      sliceTable[5][(a shr 16) and 0xFF] xor
      sliceTable[6][(a shr 8) and 0xFF] xor
      sliceTable[7][a and 0xFF]
    i += 8
  while i < length:
    result = sliceTable[0][(result xor b[i].uint32) and 0xFF] xor
      (result shr 8)
    inc i

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
