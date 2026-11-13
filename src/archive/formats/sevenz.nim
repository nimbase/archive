## 7-Zip archival format, clean-room implementation.
##
## Covers the 7z container from the public 7zFormat.txt / Methods.txt spec
## plus the zesven specification pages as oracle (no 7-Zip sources used):
## signature, plain + encoded headers, property-ID walk, Pack/Unpack/
## SubStreams/Files info, folder/coder/bind-pair validation, substream
## slicing, and folder decode for Copy, LZMA, LZMA2, Delta, BCJ-x86 and
## 7zAES. PPMd and BCJ2 refuse cleanly with explicit errors.
## The writer emits STORE archives (meth 0, default: one Copy folder per
## data file) or LZMA2-solid archives (meth 1: shared LZMA2 folders up to
## 8MiB solid data each, fast greedy match finder, 1MiB dictionary).
## Plain headers; bsdtar and 7zz both extract either output.
##
## Memory: header parsing is bounded (64MB header cap); STORE bodies are
## borrowed spans, never copied. Decoded folders are owned per-call
## strings bounded by max7zUnpackedBytes. No globals, all state on the
## stack or per-call. Passwords flow per call (the `Sz` value is per-call).

import std/[times, strutils]
from std/os import splitFile
import ../types
import ../crc32
import ./szlzma
import ./szlzmenc
import ./szfilter
import ./szaes

type SzError* = object of ArchiveError

const
  szMagic* = "\x37\x7A\xBC\xAF\x27\x1C"
    ## 6-byte signature: '7','z' + BC AF 27 1C.
  szMaxHeaderBytes* = 64 * 1024 * 1024
    ## Header cap (spec SHOULD: 64 MiB). Larger headers raise instead of
    ## allocating (likely corrupt/malicious).
  szMaxEntries* = 1_000_000
    ## Cap on file/folder/pack-stream counts each (spec SHOULD: 1M files).
  szMaxFolderDepth* = 4
    ## Max nested encoded headers (spec MUST reject beyond 4).

type Sz* = object
  ## 7z archive options. `password` enables 7zAES decryption on read
  ## (content and headers); on write it encrypts LZMA2-solid folders
  ## (requires meth 1; STORE with a password raises instead of writing
  ## plaintext). `kdfLg2` selects the KDF iteration log2 on write
  ## (0 = default 19, i.e. 2^19 rounds); readers take the count from
  ## each header and ignore this field. `meth` selects the file codec
  ## on write: 0 = STORE (default, one Copy folder per data file),
  ## 1 = LZMA2-solid (fast level, files share LZMA2 folders up to 8MiB
  ## solid data each). The value itself is per-call, never global.
  meth*: int
  password*: string
  kdfLg2*: int
  encHeaders*: bool
    ## Header-encrypted write (`-mhe=on` equivalent): the writer
    ## compresses (LZMA2) and AES-encrypts the header; readers need the
    ## password to list, like RAR HEAD_CRYPT. Requires `password`.
  useFilters*: bool
    ## Auto filters on write: when true, the LZMA2-solid writer tries
    ## Delta forward transforms (distances 1 and 4) per solid group and
    ## keeps the smallest packing (fallback to filter-free when nothing
    ## wins). Default false preserves existing behavior and speed.
    ## (BCJ forward is a follow-up; BCJ decode already works.)
  continueOnError*: bool
    ## Skip-and-continue on per-file handler/decode failures during
    ## extract (mirrors zip/tar/rar); abort with SzError otherwise.

proc extension*(z: Sz): ArchiveFormat = af7z
proc mediaType*(z: Sz): MediaType = mt7z

# ---------- little-endian + NUMBER codecs ----------

proc rdU32le(inp: Input): uint32 =
  if remaining(inp) < 4:
    raise newException(SzError, "7z: truncated u32")
  let s = readSpan(inp, 4)
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint32 or (b[1].uint32 shl 8) or (b[2].uint32 shl 16) or
    (b[3].uint32 shl 24)

proc rdU64le(inp: Input): uint64 =
  if remaining(inp) < 8:
    raise newException(SzError, "7z: truncated u64")
  let s = readSpan(inp, 8)
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint64 or (b[1].uint64 shl 8) or (b[2].uint64 shl 16) or
    (b[3].uint64 shl 24) or (b[4].uint64 shl 32) or
    (b[5].uint64 shl 40) or (b[6].uint64 shl 48) or
    (b[7].uint64 shl 56)

proc rdU32leAt(inp: Input; off: uint64): uint32 =
  ## Absolute-offset u32 read with bounds check.
  if off + 4 > uint64(inputLen(inp)):
    raise newException(SzError, "7z: truncated u32")
  let s = spanAt(inp, int(off), 4)
  let b = cast[ptr UncheckedArray[byte]](s.p)
  b[0].uint32 or (b[1].uint32 shl 8) or (b[2].uint32 shl 16) or
    (b[3].uint32 shl 24)

proc wrU16le(dst: Output; v: uint16) =
  writeByte(dst, char(v and 0xFF))
  writeByte(dst, char((v shr 8) and 0xFF))

proc wrU32le(dst: Output; v: uint32) =
  writeByte(dst, char(v and 0xFF))
  writeByte(dst, char((v shr 8) and 0xFF))
  writeByte(dst, char((v shr 16) and 0xFF))
  writeByte(dst, char((v shr 24) and 0xFF))

proc wrU64le(dst: Output; v: uint64) =
  for i in 0 ..< 8:
    writeByte(dst, char((v shr (8 * i)) and 0xFF))

proc readNum*(inp: Input): uint64 =
  ## 7z variable-length UINT64: leading-1 count of the first byte selects
  ## 0..8 extra LE bytes. Accepts non-minimal encodings (spec).
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated number")
  let first = readByte(inp)
  var mask: byte = 0x80
  var extra = 0
  while (first and mask) != 0:
    inc extra
    mask = mask shr 1
    if extra > 8:
      raise newException(SzError, "7z: bad number encoding")
  if extra == 8:
    # 0xFF marker: full 64-bit value follows, first byte contributes nothing.
    var w = 0'u64
    for i in 0 ..< 8:
      if remaining(inp) <= 0:
        raise newException(SzError, "7z: truncated number")
      w += readByte(inp).uint64 shl (8 * i)
    return w
  if remaining(inp) < extra:
    raise newException(SzError, "7z: truncated number")
  # value_bits occupy the high bits: shift left past the extra bytes,
  # which follow in little-endian order.
  var v = (first and (mask - 1)).uint64 shl (8 * extra)
  for i in 0 ..< extra:
    v += readByte(inp).uint64 shl (8 * i)
  v

proc writeNum*(dst: Output; v: uint64) =
  ## Minimal-length NUMBER encoding (readers must accept any form).
  if v < 0x80:
    writeByte(dst, char(v))
    return
  var tmp = v
  var nbytes = 0
  while tmp > 0:
    inc nbytes
    tmp = tmp shr 8
  # nbytes extra bytes need nbytes leading 1s + value bits to fit.
  var extra = nbytes
  while extra < 8 and (v shr (8 * extra)) >= (1'u64 shl (7 - extra)):
    inc extra
  if extra > 8:
    extra = 8
  let firstBits = 7 - extra
  var first = 0'u64
  for i in 0 ..< extra:
    first = first or 0x80'u64 shr i
  if extra < 8:
    first = first or (v shr (8 * extra))
  else:
    first = 0xFF'u64
  writeByte(dst, char(first and 0xFF))
  for i in 0 ..< extra:
    writeByte(dst, char((v shr (8 * i)) and 0xFF))
  discard firstBits

proc matchSz*(filename: string; inp: Input): MatchResult =
  if splitFile(filename.toLowerAscii()).ext == $af7z:
    result.byName = true
  if inp != nil:
    let s = peek(inp, 6)
    if s.len == 6 and spanEqual(s, szMagic):
      result.byStream = true

# ---------- header model ----------

type SzCoder = object
  id: string     ## method ID bytes in stored order
  complex: bool
  numIn: int
  numOut: int
  props: string  ## coder properties (may be empty)

type SzFolder = object
  coders: seq[SzCoder]
  binds: seq[tuple[inIdx, outIdx: int]]
  packIdx: seq[int]   ## explicit packed-stream indices (empty = implicit 0)
  unpackSizes: seq[uint64]
  folderCrc: uint32
  hasCrc: bool

type SzFileEntry = object
  name: string
  size: int64
  mtime: Time
  hasTime: bool
  mode: int
  isDir: bool
  isSymlink: bool
  isRegular: bool
  linkTarget: string
  folderIdx: int   ## -1 when the entry holds no data
  subOff: uint64   ## byte offset of this file inside the folder stream
  subLen: uint64
  dataCrc: uint32
  hasCrc: bool

type SzSubAssign = object
  folderIdx*: int
  subOff*: uint64
  subLen*: uint64
  hasCrc*: bool
  crc*: uint32

type SzArchive = object
  packOff: seq[uint64]  ## absolute file offsets of pack streams
  packSizes: seq[uint64]
  packCrcs: seq[uint32]
  packHasCrc: seq[bool]
  folders: seq[SzFolder]
  subs: seq[seq[SzSubAssign]]
  files: seq[SzFileEntry]

proc need(inp: Input; n: uint64) =
  if n > uint64(remaining(inp)):
    raise newException(SzError, "7z: truncated header")

proc readBytes(inp: Input; n: uint64): string =
  ## Exact-size copy (header metadata only, always small).
  need(inp, n)
  if n == 0:
    return ""
  let s = readSpan(inp, int(n))
  result = newString(int(n))
  copyMem(addr result[0], s.p, int(n))

proc readRawBits(inp: Input; count: int): seq[bool] =
  ## MSB-first bit field WITHOUT an AllAreDefined prefix (7z writes
  ## EmptyStream/EmptyFile/Anti as bare bitmaps sized by the property).
  let nbytes = (count + 7) div 8
  need(inp, nbytes.uint64)
  for i in 0 ..< count:
    result.add(((byteAt(inp, inputPos(inp) + i div 8) shr
      (7 - (i mod 8))) and 1) != 0)
  skip(inp, nbytes)

proc readBoolBitField(inp: Input; count: int): seq[bool] =
  ## AllAreDefined + optional MSB-first bit field.
  if remaining(inp) < 1:
    raise newException(SzError, "7z: truncated bit field")
  let all = readByte(inp)
  result = newSeq[bool](count)
  if all != 0:
    for i in 0 ..< count:
      result[i] = true
  else:
    let nbytes = (count + 7) div 8
    need(inp, nbytes.uint64)
    for i in 0 ..< count:
      let b = byteAt(inp, inputPos(inp) + i div 8)
      result[i] = ((b shr (7 - (i mod 8))) and 1) != 0
    skip(inp, nbytes)

proc utf16leToUtf8(data: string): string =
  ## UTF-16LE (NUL-terminated by caller convention) to UTF-8. Rejects
  ## unpaired surrogates (spec allows replace-or-reject; reject is safer).
  if data.len mod 2 != 0:
    raise newException(SzError, "7z: odd-byte UTF-16 name")
  var i = 0
  while i < data.len:
    let u = ord(data[i]).uint32 or (ord(data[i + 1]).uint32 shl 8)
    i += 2
    var cp = u
    if cp >= 0xD800 and cp <= 0xDBFF:
      if i + 1 >= data.len:
        raise newException(SzError, "7z: unpaired UTF-16 surrogate")
      let lo = ord(data[i]).uint32 or (ord(data[i + 1]).uint32 shl 8)
      if lo < 0xDC00 or lo > 0xDFFF:
        raise newException(SzError, "7z: unpaired UTF-16 surrogate")
      i += 2
      cp = 0x10000 + ((cp - 0xD800) shl 10) + (lo - 0xDC00)
    elif cp >= 0xDC00 and cp <= 0xDFFF:
      raise newException(SzError, "7z: unpaired UTF-16 surrogate")
    if cp < 0x80:
      result.add(chr(int(cp)))
    elif cp < 0x800:
      result.add(chr(int(0xC0 or (cp shr 6))))
      result.add(chr(int(0x80 or (cp and 0x3F))))
    elif cp < 0x10000:
      result.add(chr(int(0xE0 or (cp shr 12))))
      result.add(chr(int(0x80 or ((cp shr 6) and 0x3F))))
      result.add(chr(int(0x80 or (cp and 0x3F))))
    else:
      result.add(chr(int(0xF0 or (cp shr 18))))
      result.add(chr(int(0x80 or ((cp shr 12) and 0x3F))))
      result.add(chr(int(0x80 or ((cp shr 6) and 0x3F))))
      result.add(chr(int(0x80 or (cp and 0x3F))))

proc utf8ToUtf16le(s: string): string =
  ## UTF-8 to UTF-16LE (no NUL terminator; caller appends).
  var i = 0
  while i < s.len:
    let b0 = ord(s[i]).uint32
    var cp: uint32
    var nbytes = 1
    if b0 < 0x80:
      cp = b0
    elif (b0 and 0xE0) == 0xC0:
      nbytes = 2
      cp = b0 and 0x1F
    elif (b0 and 0xF0) == 0xE0:
      nbytes = 3
      cp = b0 and 0x0F
    elif (b0 and 0xF8) == 0xF0:
      nbytes = 4
      cp = b0 and 0x07
    else:
      raise newException(SzError, "7z: bad UTF-8 name")
    if i + nbytes > s.len:
      raise newException(SzError, "7z: truncated UTF-8 name")
    for k in 1 ..< nbytes:
      let bx = ord(s[i + k]).uint32
      if (bx and 0xC0) != 0x80:
        raise newException(SzError, "7z: bad UTF-8 name")
      cp = (cp shl 6) or (bx and 0x3F)
    i += nbytes
    if cp < 0x10000:
      if cp >= 0xD800 and cp <= 0xDFFF:
        raise newException(SzError, "7z: bad UTF-8 name")
      result.add(chr(int(cp and 0xFF)))
      result.add(chr(int((cp shr 8) and 0xFF)))
    else:
      let v = cp - 0x10000
      let hi = 0xD800 + (v shr 10)
      let lo = 0xDC00 + (v and 0x3FF)
      result.add(chr(int(hi and 0xFF)))
      result.add(chr(int((hi shr 8) and 0xFF)))
      result.add(chr(int(lo and 0xFF)))
      result.add(chr(int((lo shr 8) and 0xFF)))

proc filetimeToTime(ft: uint64): Time =
  ## Windows FILETIME (100ns since 1601-01-01) to Unix time.
  const epochDiff = 11644473600'u64
  let secs = ft div 10_000_000
  if secs < epochDiff:
    fromUnix(0)
  else:
    fromUnix(int64(secs - epochDiff))

proc timeToFiletime(t: Time): uint64 =
  uint64(toUnix(t) + 11644473600) * 10_000_000'u64

# ---------- signature ----------

proc parseSignature(inp: Input; ctx: ArchiveContext): tuple[nextOff,
    nextSize, nextCrc: uint64] =
  if remaining(inp) < 32:
    raise newException(SzError, "7z: truncated signature")
  let magic = readSpan(inp, 6)
  if not spanEqual(magic, szMagic):
    raise newException(SzError, "7z: bad signature")
  let major = readByte(inp)
  discard readByte(inp) # minor: feature set comes from coder IDs
  if major != 0:
    raise newException(SzError, "7z: unsupported version")
  let startCrc = rdU32le(inp)
  let headOff = rdU64le(inp)
  let headSize = rdU64le(inp)
  let headCrc = rdU32le(inp)
  if headSize == 0 or headSize > uint64(szMaxHeaderBytes):
    raise newException(SzError, "7z: bad header size")
  if ctx.max7zHeaderBytes != 0 and headSize > uint64(ctx.max7zHeaderBytes):
    raise newException(SzError, "7z: header exceeds cap")
  if headOff > uint64(high(int64)) - headSize - 32:
    raise newException(SzError, "7z: bad header offset")
  let absEnd = 32'u64 + headOff + headSize
  # CRC over the 20 StartHeader bytes (offset 12..31).
  let crcSpan = spanAt(inp, 12, 20)
  var calc = crc32Update(0xFFFFFFFF'u32, crcSpan.p, crcSpan.len) xor
    0xFFFFFFFF'u32
  if calc != startCrc:
    raise newException(SzError, "7z: signature CRC mismatch")
  discard absEnd
  (headOff, headSize, headCrc.uint64)

proc headerInput(inp: Input; headOff, headSize: uint64): Input =
  ## Borrowed view over the header bytes (zero-copy); CRC-checked by
  ## the caller after the walk (needs the stored CRC first). Offsets are
  ## absolute (signature-relative), so bound against total length.
  let total = uint64(inputLen(inp))
  if headOff > total or 32 > total - headOff or
      headSize > total - headOff - 32:
    raise newException(SzError, "7z: header past end of file")
  let s = spanAt(inp, int(32 + headOff), int(headSize))
  openInputView(s, inp)

# ---------- PackInfo ----------

proc parsePackInfo(inp: Input; base: uint64; arch: var SzArchive) =
  # Caller consumed 0x06. Layout: PackPos NumPack [Sizes] [Digests]
  # with no PackInfo-level terminator; the next section ID follows
  # immediately (verified against 7z-written archives).
  let packPos = readNum(inp)
  let numPack = readNum(inp)
  if numPack > szMaxEntries.uint64:
    raise newException(SzError, "7z: too many pack streams")
  if packPos > uint64(high(int64)):
    raise newException(SzError, "7z: bad pack position")
  if numPack == 0:
    # No sizes or digests possible; leave the next section ID unread.
    return
  if remaining(inp) <= 0 or readByte(inp) != 0x09:
    raise newException(SzError, "7z: missing pack sizes")
  var sizes: seq[uint64] = @[]
  # Exactly NumPackStreams numbers: a zero-length stream encodes as a
  # single 0x00 byte, indistinguishable from a terminator, so the
  # section is count-delimited with an explicit end marker after.
  for _ in 0 ..< int(numPack):
    sizes.add(readNum(inp))
  if remaining(inp) <= 0 or readByte(inp) != 0x00:
    raise newException(SzError, "7z: bad pack sizes terminator")
  var crcs: seq[uint32] = @[]
  var hasCrc: seq[bool] = @[]
  for _ in 0 ..< int(numPack):
    crcs.add(0)
    hasCrc.add(false)
  # Optional digests section (peek: PackInfo itself has no terminator,
  # the next section ID follows immediately).
  if remaining(inp) > 0:
    let save = inputPos(inp)
    if readByte(inp) == 0x0A:
      let defined = readBoolBitField(inp, int(numPack))
      crcs = @[]
      hasCrc = @[]
      for i in 0 ..< int(numPack):
        hasCrc.add(defined[i])
        if defined[i]:
          crcs.add(rdU32le(inp))
        else:
          crcs.add(0)
    else:
      seek(inp, save)
  if base + packPos > uint64(high(int64)):
    raise newException(SzError, "7z: bad pack position")
  arch.packOff = @[]
  arch.packSizes = @[]
  arch.packCrcs = @[]
  arch.packHasCrc = @[]
  var off = base + packPos
  for i in 0 ..< int(numPack):
    if sizes[i] > uint64(high(int64)) - off:
      raise newException(SzError, "7z: pack stream out of range")
    arch.packOff.add(off)
    arch.packSizes.add(sizes[i])
    arch.packCrcs.add(crcs[i])
    arch.packHasCrc.add(hasCrc[i])
    off += sizes[i]

# ---------- UnpackInfo ----------

proc coderIdName(id: string): string =
  ## Short hex tag for errors, e.g. "03 01 01".
  result = ""
  for i, b in id:
    if i > 0:
      result.add(' ')
    result.add("0123456789ABCDEF"[(ord(b) shr 4) and 0xF])
    result.add("0123456789ABCDEF"[ord(b) and 0xF])

proc isAesCoder(id: string): bool =
  id.len == 4 and ord(id[0]) == 0x06 and ord(id[1]) == 0xF1 and
    ord(id[2]) == 0x07 and ord(id[3]) == 0x01

proc parseFolder(inp: Input): SzFolder =
  let numCoders = readNum(inp)
  if numCoders == 0 or numCoders > 32:
    raise newException(SzError, "7z: bad coder count")
  result.coders = @[]
  var totalIn = 0
  var totalOut = 0
  for _ in 0 ..< int(numCoders):
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated coder")
    let flags = readByte(inp)
    let idSize = int(flags and 0x0F)
    if idSize == 0 or idSize > 8:
      raise newException(SzError, "7z: bad coder id size")
    if (flags and 0xC0) != 0:
      raise newException(SzError, "7z: bad coder flags")
    let isComplex = (flags and 0x10) != 0
    var id = ""
    if idSize > 0:
      need(inp, idSize.uint64)
      let s = readSpan(inp, idSize)
      id = newString(idSize)
      copyMem(addr id[0], s.p, idSize)
    var ni = 1
    var no = 1
    if isComplex:
      ni = int(readNum(inp))
      no = int(readNum(inp))
      if ni <= 0 or no <= 0 or ni > 8 or no > 8:
        raise newException(SzError, "7z: bad coder stream counts")
    var props = ""
    if (flags and 0x20) != 0:
      let ps = readNum(inp)
      if ps > 1 shl 20:
        raise newException(SzError, "7z: coder props too large")
      props = readBytes(inp, ps)
    result.coders.add(SzCoder(id: id, complex: isComplex, numIn: ni,
      numOut: no, props: props))
    totalIn += ni
    totalOut += no
  # Bind pairs: every output except one is bound.
  let numBinds = totalOut - 1
  if numBinds < 0:
    raise newException(SzError, "7z: bad folder outputs")
  result.binds = @[]
  var boundOut = newSeq[bool](totalOut)
  for _ in 0 ..< numBinds:
    let ii = int(readNum(inp))
    let oo = int(readNum(inp))
    result.binds.add((inIdx: ii, outIdx: oo))
    if oo < 0 or oo >= totalOut or boundOut[oo]:
      raise newException(SzError, "7z: bad bind pair")
    boundOut[oo] = true
  # Packed indices for unbound inputs.
  let numPacked = totalIn - numBinds
  if numPacked <= 0:
    raise newException(SzError, "7z: folder has no packed input")
  result.packIdx = @[]
  if numPacked == 1:
    # Implicit: the single unbound input is packed stream 0 of the folder
    # mapping (resolved against global pack list by folder order later).
    discard
  else:
    for _ in 0 ..< numPacked:
      result.packIdx.add(int(readNum(inp)))
  # Unpack sizes + folder CRC are read by the caller (section level).

proc parseUnpackInfo(inp: Input; arch: var SzArchive) =
  # Caller consumed 0x07. Folders, unpack sizes, folder CRCs, 0x00.
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated unpack info")
  let b = readByte(inp)
  if b != 0x0B:
    raise newException(SzError, "7z: missing folder section")
  let numFolders = readNum(inp)
  if numFolders > szMaxEntries.uint64:
    raise newException(SzError, "7z: too many folders")
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated folder section")
  let ext = readByte(inp)
  if ext == 0x01:
    raise newException(SzError, "7z: external folders unsupported")
  elif ext != 0x00:
    raise newException(SzError, "7z: bad folder external byte")
  arch.folders = @[]
  for _ in 0 ..< int(numFolders):
    arch.folders.add(parseFolder(inp))
  # Unpack sizes: one per coder output, in folder order.
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated unpack sizes")
  if readByte(inp) != 0x0C:
    raise newException(SzError, "7z: missing unpack sizes")
  for fi in 0 ..< arch.folders.len:
    var totalOut = 0
    for c in arch.folders[fi].coders:
      totalOut += c.numOut
    arch.folders[fi].unpackSizes = @[]
    for _ in 0 ..< totalOut:
      arch.folders[fi].unpackSizes.add(readNum(inp))
  # Folder CRCs (optional section).
  for fi in 0 ..< arch.folders.len:
    arch.folders[fi].hasCrc = false
    arch.folders[fi].folderCrc = 0
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated unpack info")
  var id = readByte(inp)
  if id == 0x0A:
    let defined = readBoolBitField(inp, arch.folders.len)
    for fi in 0 ..< arch.folders.len:
      arch.folders[fi].hasCrc = defined[fi]
      if defined[fi]:
        arch.folders[fi].folderCrc = rdU32le(inp)
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated unpack info")
    id = readByte(inp)
  if id != 0x00:
    raise newException(SzError, "7z: bad unpack info terminator")

# ---------- SubStreamsInfo ----------

proc parseSubStreams(inp: Input; arch: SzArchive): seq[seq[SzSubAssign]] =
  ## Per-folder substream assignment. Absent section = one substream per
  ## folder covering the whole folder output.
  result = newSeq[seq[SzSubAssign]](arch.folders.len)
  for fi in 0 ..< arch.folders.len:
    let total = if arch.folders[fi].unpackSizes.len > 0:
      arch.folders[fi].unpackSizes[^1] else: 0'u64
    result[fi] = @[SzSubAssign(folderIdx: fi, subOff: 0, subLen: total,
      hasCrc: arch.folders[fi].hasCrc, crc: arch.folders[fi].folderCrc)]
  if remaining(inp) <= 0:
    return result
  let save = inputPos(inp)
  let id = readByte(inp)
  if id != 0x08:
    seek(inp, save)
    return result
  if arch.folders.len == 0:
    raise newException(SzError, "7z: substreams without folders")
  var numStreams = newSeq[uint64](arch.folders.len)
  for i in 0 ..< numStreams.len:
    numStreams[i] = 1
  var sizesPerFolder: seq[seq[uint64]] = newSeq[seq[uint64]](
    arch.folders.len)
  var crcsPerFolder: seq[seq[tuple[has: bool; crc: uint32]]] =
    newSeq[seq[tuple[has: bool; crc: uint32]]](arch.folders.len)
  var nid = readByte(inp)
  if nid == 0x0D:
    for fi in 0 ..< arch.folders.len:
      numStreams[fi] = readNum(inp)
      if numStreams[fi] == 0 or numStreams[fi] > szMaxEntries.uint64:
        raise newException(SzError, "7z: bad substream count")
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated substreams")
    nid = readByte(inp)
  if nid == 0x09:
    for fi in 0 ..< arch.folders.len:
      let total = if arch.folders[fi].unpackSizes.len > 0:
        arch.folders[fi].unpackSizes[^1] else: 0'u64
      var sizes: seq[uint64] = @[]
      var acc = 0'u64
      for _ in 1 ..< int(numStreams[fi]):
        let s = readNum(inp)
        sizes.add(s)
        acc += s
        if acc > total:
          raise newException(SzError, "7z: substream sizes overflow")
      if acc > total:
        raise newException(SzError, "7z: substream sizes overflow")
      sizes.add(total - acc)
      sizesPerFolder[fi] = sizes
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated substreams")
    nid = readByte(inp)
  else:
    for fi in 0 ..< arch.folders.len:
      let total = if arch.folders[fi].unpackSizes.len > 0:
        arch.folders[fi].unpackSizes[^1] else: 0'u64
      sizesPerFolder[fi] = @[total]
  if nid == 0x0A:
    # One AllAreDefined + optional BitField covers ALL substreams that
    # need entries (single-stream folders with a folder CRC inherit it
    # and consume neither bitmap bits nor CRC slots).
    var inherit = newSeq[bool](arch.folders.len)
    var total = 0
    for fi in 0 ..< arch.folders.len:
      inherit[fi] = sizesPerFolder[fi].len == 1 and arch.folders[fi].hasCrc
      if not inherit[fi]:
        total += sizesPerFolder[fi].len
    let defined = readBoolBitField(inp, total)
    var di = 0
    for fi in 0 ..< arch.folders.len:
      crcsPerFolder[fi] = @[]
      for si in 0 ..< sizesPerFolder[fi].len:
        if inherit[fi]:
          crcsPerFolder[fi].add((has: true,
            crc: arch.folders[fi].folderCrc))
        else:
          if defined[di]:
            crcsPerFolder[fi].add((has: true, crc: rdU32le(inp)))
          else:
            crcsPerFolder[fi].add((has: false, crc: 0'u32))
          inc di
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated substreams")
    nid = readByte(inp)
  else:
    for fi in 0 ..< arch.folders.len:
      crcsPerFolder[fi] = @[]
      for si in 0 ..< sizesPerFolder[fi].len:
        if sizesPerFolder[fi].len == 1 and arch.folders[fi].hasCrc:
          crcsPerFolder[fi].add((has: true,
            crc: arch.folders[fi].folderCrc))
        else:
          crcsPerFolder[fi].add((has: false, crc: 0'u32))
  if nid != 0x00:
    raise newException(SzError, "7z: bad substreams terminator")
  # Rebuild assignments with explicit offsets.
  for fi in 0 ..< arch.folders.len:
    result[fi] = @[]
    var off = 0'u64
    for si in 0 ..< sizesPerFolder[fi].len:
      result[fi].add(SzSubAssign(folderIdx: fi, subOff: off,
        subLen: sizesPerFolder[fi][si],
        hasCrc: crcsPerFolder[fi][si].has,
        crc: crcsPerFolder[fi][si].crc))
      off += sizesPerFolder[fi][si]

# ---------- folder decode ----------

proc folderPackedCount(f: SzFolder): int =
  var totalIn = 0
  var totalOut = 0
  for c in f.coders:
    totalIn += c.numIn
    totalOut += c.numOut
  totalIn - (totalOut - 1)

proc folderPackBase(arch: SzArchive; fi: int): int =
  ## Global pack-stream index of folder fi's first packed input.
  result = 0
  for gi in 0 ..< fi:
    result += folderPackedCount(arch.folders[gi])

proc resolvePackSpan(inp: Input; arch: SzArchive; fi: int): Span =
  ## Structural pack-stream resolution (no coder check): the single
  ## packed stream feeding a single-input folder. Bounds-checked.
  let f = arch.folders[fi]
  if folderPackedCount(f) != 1:
    raise newException(SzError, "7z: folder needs decoder")
  var packIdx: int
  if f.packIdx.len > 0:
    if f.packIdx.len != 1:
      raise newException(SzError, "7z: bad packed indices")
    packIdx = f.packIdx[0]
  else:
    packIdx = folderPackBase(arch, fi)
  if packIdx < 0 or packIdx >= arch.packOff.len:
    raise newException(SzError, "7z: pack index out of range")
  let off = arch.packOff[packIdx]
  let size = arch.packSizes[packIdx]
  if off + size > uint64(inputLen(inp)) or off < 32:
    raise newException(SzError, "7z: pack stream out of range")
  spanAt(inp, int(off), int(size))

proc packBytesOf(inp: Input; arch: SzArchive; fi: int): string =
  ## Owned copy of a folder's single pack stream (for decoders).
  let f = arch.folders[fi]
  if folderPackedCount(f) != 1:
    raise newException(SzError, "7z: multi-stream folder unsupported")
  var packIdx: int
  if f.packIdx.len > 0:
    if f.packIdx.len != 1:
      raise newException(SzError, "7z: bad packed indices")
    packIdx = f.packIdx[0]
  else:
    packIdx = folderPackBase(arch, fi)
  if packIdx < 0 or packIdx >= arch.packOff.len:
    raise newException(SzError, "7z: pack index out of range")
  let off = arch.packOff[packIdx]
  let size = arch.packSizes[packIdx]
  if off + size > uint64(inputLen(inp)) or off < 32:
    raise newException(SzError, "7z: pack stream out of range")
  if size > uint64(high(int)):
    raise newException(SzError, "7z: pack stream too large")
  let s = spanAt(inp, int(off), int(size))
  result = newString(int(size))
  if size > 0:
    copyMem(addr result[0], s.p, int(size))
  if arch.packHasCrc[packIdx] and size > 0:
    let got = crc32Update(0xFFFFFFFF'u32, result) xor 0xFFFFFFFF'u32
    if got != arch.packCrcs[packIdx]:
      raise newException(SzError, "7z: data crc mismatch (pack stream)")

proc isCopyId(id: string): bool = id == "\x00"
proc isLzmaId(id: string): bool =
  id.len == 3 and ord(id[0]) == 0x03 and ord(id[1]) == 0x01 and
    ord(id[2]) == 0x01
proc isLzma2Id(id: string): bool = id == "\x21"
proc isDeltaId(id: string): bool = id == "\x03"
proc isBcjId(id: string): bool =
  id == "\x04" or (id.len == 4 and ord(id[0]) == 0x03 and
    ord(id[1]) == 0x03 and ord(id[2]) == 0x01 and ord(id[3]) == 0x03)

proc classifyFolder(f: SzFolder; z: Sz): string =
  ## "" when this folder's chain is decodable in v1 (Copy, LZMA, LZMA2,
  ## Delta, BCJ-x86, AES); otherwise the open-time error message.
  ## Structural problems still raise immediately.
  var totalOut = 0
  var totalIn = 0
  for c in f.coders:
    if c.complex or c.numIn != 1 or c.numOut != 1:
      return "7z: unsupported method " & coderIdName(c.id)
    totalOut += c.numOut
    totalIn += c.numIn
  if f.unpackSizes.len != totalOut:
    raise newException(SzError, "7z: bad folder unpack sizes")
  if totalIn - (totalOut - 1) != 1:
    return "7z: unsupported coder chain"
  # linear binds check: (1,0),(2,1),...
  if f.coders.len > 1:
    if f.binds.len != f.coders.len - 1:
      raise newException(SzError, "7z: bad bind pairs")
    for i in 0 ..< f.binds.len:
      if f.binds[i].inIdx != i + 1 or f.binds[i].outIdx != i:
        return "7z: unsupported coder chain"
  for c in f.coders:
    if isAesCoder(c.id):
      if z.password == "":
        return "7z: password required"
      continue
    elif isCopyId(c.id) or isLzmaId(c.id) or isLzma2Id(c.id) or
        isDeltaId(c.id) or isBcjId(c.id):
      continue
    else:
      return "7z: unsupported method " & coderIdName(c.id)
  ""

proc decodeFolder(inp: Input; arch: SzArchive; fi: int; z: Sz;
    ctx: ArchiveContext): string =
  ## Decode one folder to an owned string. Validates linear binds,
  ## applies coders in order, enforces caps, verifies folder CRC.
  let f = arch.folders[fi]
  for c in f.coders:
    if c.complex or c.numIn != 1 or c.numOut != 1:
      raise newException(SzError, "7z: unsupported method " &
        coderIdName(c.id))
  if f.unpackSizes.len != f.coders.len:
    raise newException(SzError, "7z: bad folder unpack sizes")
  if f.coders.len > 1:
    if f.binds.len != f.coders.len - 1:
      raise newException(SzError, "7z: bad bind pairs")
    for i in 0 ..< f.binds.len:
      if f.binds[i].inIdx != i + 1 or f.binds[i].outIdx != i:
        raise newException(SzError, "7z: unsupported coder chain")
  if folderPackedCount(f) != 1:
    raise newException(SzError, "7z: multi-stream folder unsupported")
  var data = packBytesOf(inp, arch, fi)
  for ci, c in f.coders:
    let want = int64(f.unpackSizes[ci])
    if want < 0:
      raise newException(SzError, "7z: bad unpack size")
    if ctx.max7zUnpackedBytes != 0 and want > ctx.max7zUnpackedBytes:
      raise newException(SzError, "7z: entry exceeds unpack cap")
    if isCopyId(c.id):
      if c.props.len != 0:
        raise newException(SzError, "7z: bad copy props")
      if data.len.int64 != want:
        raise newException(SzError, "7z: copy size mismatch")
    elif isAesCoder(c.id):
      if z.password == "":
        raise newException(SzError, "7z: password required")
      var salt: seq[byte]
      var iv: array[16, byte]
      var power: int
      try:
        let p = parseAesProps(c.props)
        salt = p.salt
        iv = p.iv
        power = p.power
      except CatchableError as e:
        raise newException(SzError, "7z: bad aes props: " & e.msg)
      var key: array[32, byte]
      try:
        key = deriveAesKey(z.password, salt, power)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
      try:
        data = aesCbcDecryptTrunc(key, iv, data, int(want))
      except CatchableError as e:
        raise newException(SzError, "7z: aes decrypt failed: " & e.msg)
    elif isLzma2Id(c.id):
      if c.props.len != 1:
        raise newException(SzError, "7z: bad lzma2 props")
      try:
        data = lzma2Decode(data, int(want), byte(ord(c.props[0])),
          ctx.max7zDictBytes)
      except LzmaError as e:
        raise newException(SzError, e.msg)
      except CatchableError as e:
        raise newException(SzError, "7z: lzma2 failed: " & e.msg)
    elif isLzmaId(c.id):
      try:
        data = lzma1Decode(c.props, data, int(want),
          ctx.max7zDictBytes)
      except LzmaError as e:
        raise newException(SzError, e.msg)
      except CatchableError as e:
        raise newException(SzError, "7z: lzma failed: " & e.msg)
    elif isDeltaId(c.id):
      var dist = 1
      try:
        dist = deltaDistance(c.props)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
      if data.len.int64 != want:
        raise newException(SzError, "7z: delta size mismatch")
      try:
        deltaDecode(data, dist)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
    elif isBcjId(c.id):
      var startOff = 0'u32
      try:
        startOff = bcjStartOffset(c.props)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
      if data.len.int64 != want:
        raise newException(SzError, "7z: bcj size mismatch")
      try:
        bcjX86Decode(data, startOff)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
    else:
      raise newException(SzError, "7z: unsupported method " &
        coderIdName(c.id))
  if f.hasCrc and data.len > 0:
    let got = crc32Update(0xFFFFFFFF'u32, data) xor 0xFFFFFFFF'u32
    if got != f.folderCrc:
      raise newException(SzError, "7z: data crc mismatch (folder)")
  elif f.hasCrc and data.len == 0:
    if 0'u32 != f.folderCrc:
      raise newException(SzError, "7z: data crc mismatch (folder)")
  data

proc verifySpanCrc(s: Span; expect: uint32; what: string) =
  let got = if s.len == 0: 0x00000000'u32
    else: crc32Update(0xFFFFFFFF'u32, s.p, s.len) xor 0xFFFFFFFF'u32
  if got != expect:
    raise newException(SzError, "7z: data crc mismatch" & what)

proc verifyStringCrc(data: string; subOff, subLen: int; expect: uint32;
    what: string) =
  let got =
    if subLen == 0: 0x00000000'u32
    elif subOff < 0 or subLen < 0 or subOff + subLen > data.len:
      raise newException(SzError, "7z: substream out of range")
    else:
      var d = data
      crc32Update(0xFFFFFFFF'u32,
        addr d[subOff], subLen) xor 0xFFFFFFFF'u32
  if got != expect:
    raise newException(SzError, "7z: data crc mismatch" & what)

proc errOpener(msg: string): proc(): Input {.closure.} =
  ## Opener factory that fails explicitly on open (listing stays cheap).
  let m = msg
  result = proc(): Input {.closure.} =
    raise newException(SzError, m)

proc storeOpener(s: Span; keep: Input; crc: uint32; hasCrc: bool;
    what: string): proc(): Input {.closure.} =
  let sp = s
  let kp: RootRef = keep
  result = proc(): Input {.closure.} =
    if hasCrc:
      verifySpanCrc(sp, crc, what)
    openInputView(sp, kp)

proc assignSubstreams(entries: var seq[SzFileEntry]; dataIdx: seq[int];
    subs: seq[seq[SzSubAssign]]; ctx: ArchiveContext) =
  ## Map data-bearing files (FilesInfo order) onto folder substreams.
  var subFlat: seq[tuple[fi: int; sub: SzSubAssign]] = @[]
  for fi in 0 ..< subs.len:
    for s in subs[fi]:
      subFlat.add((fi: fi, sub: s))
  if dataIdx.len != subFlat.len:
    raise newException(SzError, "7z: file/substream count mismatch")
  for k, ei in dataIdx:
    let slot = subFlat[k]
    entries[ei].folderIdx = slot.fi
    entries[ei].subOff = slot.sub.subOff
    entries[ei].subLen = slot.sub.subLen
    entries[ei].dataCrc = slot.sub.crc
    entries[ei].hasCrc = slot.sub.hasCrc
    entries[ei].size = int64(slot.sub.subLen)
    entries[ei].isRegular = true
    if ctx.max7zUnpackedBytes != 0 and
        entries[ei].size > ctx.max7zUnpackedBytes:
      raise newException(SzError, "7z: entry exceeds unpack cap")

proc parseFilesInfo(inp: Input; numFiles: int):
    tuple[entries: seq[SzFileEntry]; dataIdx: seq[int]] =
  ## File properties without folder assignment (order-independent pass).
  ## Returns entries plus the indices holding data, for assignSubstreams.
  if numFiles > szMaxEntries:
    raise newException(SzError, "7z: too many files")
  var emptyStream = newSeq[bool](numFiles)
  var hasEmptyStream = false
  var emptyFile = newSeq[bool]()
  var anti = newSeq[bool]()
  var names: seq[string] = @[]
  var mtimes = newSeq[tuple[has: bool; t: Time]](numFiles)
  var attrs = newSeq[tuple[has: bool; a: uint32]](numFiles)
  for i in 0 ..< numFiles:
    mtimes[i] = (has: false, t: fromUnix(0))
    attrs[i] = (has: false, a: 0)
  var seenProp = -1
  while true:
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated files info")
    let pid = int(readByte(inp))
    if pid == 0x00:
      break
    # 0x19 Dummy is padding 7z emits anywhere (even out of order);
    # exempt it from the ascending-order rule.
    if pid != 0x19:
      if pid <= seenProp:
        raise newException(SzError, "7z: files properties out of order")
      seenProp = pid
    let size = readNum(inp)
    if size > uint64(remaining(inp)):
      raise newException(SzError, "7z: file property past end")
    let propEnd = inputPos(inp) + int(size)
    case pid
    of 0x0E: # EmptyStream: bare bitmap, no AllAreDefined byte
      let bits = readRawBits(inp, numFiles)
      if inputPos(inp) != propEnd:
        raise newException(SzError, "7z: bad empty-stream size")
      emptyStream = bits
      hasEmptyStream = true
    of 0x0F, 0x10: # EmptyFile / Anti: bare bitmaps over empty entries
      var count = 0
      for b in emptyStream:
        if b:
          inc count
      if not hasEmptyStream:
        if size != 0:
          raise newException(SzError, "7z: bad empty-file size")
      else:
        let bits = readRawBits(inp, count)
        if inputPos(inp) != propEnd:
          raise newException(SzError, "7z: bad empty-file size")
        if pid == 0x0F:
          emptyFile = bits
        else:
          anti = bits
    of 0x11: # Names (UTF-16LE NUL-terminated each)
      let ext = readByte(inp)
      var blob = ""
      if ext == 0x00:
        blob = readBytes(inp, uint64(propEnd - inputPos(inp)))
      elif ext == 0x01:
        raise newException(SzError, "7z: external names unsupported")
      else:
        raise newException(SzError, "7z: bad name external byte")
      if inputPos(inp) != propEnd:
        raise newException(SzError, "7z: bad name size")
      var parts: seq[string] = @[]
      var cur = ""
      var i = 0
      while i + 1 < blob.len:
        if ord(blob[i]) == 0 and ord(blob[i + 1]) == 0:
          parts.add(cur)
          cur = ""
          i += 2
        else:
          cur.add(blob[i])
          cur.add(blob[i + 1])
          i += 2
      if cur.len != 0 or parts.len != numFiles:
        raise newException(SzError, "7z: name count mismatch")
      for p in parts:
        names.add(utf16leToUtf8(p))
    of 0x12, 0x13: # CTime/ATime: validated framing, not mapped
      let defined = readBoolBitField(inp, numFiles)
      if remaining(inp) <= 0:
        raise newException(SzError, "7z: truncated time flags")
      let external = readByte(inp)
      if external != 0x00:
        raise newException(SzError, "7z: external times unsupported")
      for i in 0 ..< numFiles:
        if defined[i]:
          if inputPos(inp) + 8 > propEnd:
            raise newException(SzError, "7z: time past property end")
          discard rdU64le(inp)
      if inputPos(inp) != propEnd:
        raise newException(SzError, "7z: bad time size")
    of 0x14: # MTime mapped to Time
      let defined = readBoolBitField(inp, numFiles)
      if remaining(inp) <= 0:
        raise newException(SzError, "7z: truncated time flags")
      let external = readByte(inp)
      if external != 0x00:
        raise newException(SzError, "7z: external times unsupported")
      for i in 0 ..< numFiles:
        if defined[i]:
          if inputPos(inp) + 8 > propEnd:
            raise newException(SzError, "7z: time past property end")
          mtimes[i] = (has: true, t: filetimeToTime(rdU64le(inp)))
      if inputPos(inp) != propEnd:
        raise newException(SzError, "7z: bad time size")
    of 0x15: # Attributes
      let defined = readBoolBitField(inp, numFiles)
      if remaining(inp) <= 0:
        raise newException(SzError, "7z: truncated attr flags")
      let external = readByte(inp)
      if external != 0x00:
        raise newException(SzError, "7z: external attrs unsupported")
      for i in 0 ..< numFiles:
        if defined[i]:
          if inputPos(inp) + 4 > propEnd:
            raise newException(SzError, "7z: attr past property end")
          attrs[i] = (has: true, a: rdU32le(inp))
      if inputPos(inp) != propEnd:
        raise newException(SzError, "7z: bad attr size")
    of 0x16, 0x19: # Comment / Dummy: skip via Size framing
      seek(inp, propEnd)
    else:
      # Unknown property: skip (Size-framed per spec).
      seek(inp, propEnd)
    if inputPos(inp) > propEnd:
      raise newException(SzError, "7z: file property overrun")
    seek(inp, propEnd)
  if names.len != 0 and names.len != numFiles:
    raise newException(SzError, "7z: name count mismatch")
  var entries: seq[SzFileEntry] = @[]
  var dataIdx: seq[int] = @[]
  var emptyIdx = 0
  for i in 0 ..< numFiles:
    let nm = if names.len > 0: names[i] else: ""
    let isEmpty = hasEmptyStream and emptyStream[i]
    var fe = SzFileEntry(name: nm, mtime: mtimes[i].t,
      hasTime: mtimes[i].has, mode: 0, isDir: false, isSymlink: false,
      isRegular: false, folderIdx: -1)
    if attrs[i].has:
      let a = attrs[i].a
      # High word is a Unix mode only when bit 15 flags Unix extensions;
      # otherwise fall back to the Windows dir bit.
      if (a and 0x8000'u32) != 0 and (a shr 16) != 0:
        fe.mode = int((a shr 16) and 0xFFFF)
        let ftype = (a shr 28) and 0xF
        fe.isDir = ftype == 4
        fe.isSymlink = ftype == 10
        fe.isRegular = not fe.isDir and not fe.isSymlink
      else:
        fe.isDir = (a and 0x10) != 0
        fe.isRegular = not fe.isDir
        fe.mode = if fe.isDir: 0o755 else: 0o644
    if isEmpty:
      let isFile = if emptyIdx < emptyFile.len: emptyFile[emptyIdx]
        else: false
      let isAnti = if emptyIdx < anti.len: anti[emptyIdx] else: false
      inc emptyIdx
      if isAnti:
        continue # delete-on-extract marker: not materialized on read
      if (fe.mode and 0o170000) == 0o120000:
        # Symlink (possibly with an empty target): keep the type from
        # the mode bits instead of rederiving from EmptyFile.
        fe.isSymlink = true
        fe.isDir = false
        fe.isRegular = false
      else:
        fe.isDir = not isFile
        fe.isRegular = isFile
      fe.size = 0
      if fe.mode == 0:
        fe.mode = if fe.isDir: 0o755 else: 0o644
      if fe.isDir and not fe.name.endsWith("/"):
        fe.name.add('/')
      entries.add(fe)
    else:
      dataIdx.add(entries.len)
      entries.add(fe)
  (entries, dataIdx)

proc walkHeader(inp: Input; ctx: ArchiveContext; base: uint64): SzArchive =
  ## Parse a plain (0x01) header database into folders, substream
  ## assignment and file entries. Section order is tolerated (FilesInfo
  ## assignment runs after all sections are known).
  if remaining(inp) <= 0:
    raise newException(SzError, "7z: truncated header")
  if readByte(inp) != 0x01:
    raise newException(SzError, "7z: bad header id")
  result = SzArchive()
  var seen = -1
  var filesNum = -1
  var filesParsed = false
  var dataIdx: seq[int] = @[]
  while true:
    if remaining(inp) <= 0:
      raise newException(SzError, "7z: truncated header")
    let id = int(readByte(inp))
    if id == 0x00:
      break
    if id <= seen:
      raise newException(SzError, "7z: header out of order")
    seen = id
    case id
    of 0x02: # ArchiveProperties: skip properties
      while true:
        if remaining(inp) <= 0:
          raise newException(SzError, "7z: truncated properties")
        let pid = readByte(inp)
        if pid == 0x00:
          break
        let sz = readNum(inp)
        need(inp, sz)
        skip(inp, int(sz))
    of 0x04:
      var seenS = -1
      while true:
        if remaining(inp) <= 0:
          raise newException(SzError, "7z: truncated streams info")
        let sid = int(readByte(inp))
        if sid == 0x00:
          break
        if sid <= seenS:
          raise newException(SzError, "7z: streams info out of order")
        seenS = sid
        case sid
        of 0x06:
          parsePackInfo(inp, base, result)
        of 0x07:
          parseUnpackInfo(inp, result)
        of 0x08:
          seek(inp, inputPos(inp) - 1) # parseSubStreams peeks for 0x08
          result.subs = parseSubStreams(inp, result)
        else:
          raise newException(SzError, "7z: bad streams info id")
    of 0x05:
      let n = readNum(inp)
      if n > szMaxEntries.uint64:
        raise newException(SzError, "7z: too many files")
      filesNum = int(n)
      let parsed = parseFilesInfo(inp, filesNum)
      result.files = parsed.entries
      dataIdx = parsed.dataIdx
      filesParsed = true
    else:
      raise newException(SzError, "7z: bad header id")
  if filesParsed:
    if result.subs.len == 0 and result.folders.len > 0:
      # No 0x08 section: one substream per folder (parsed lazily here;
      # parseSubStreams rewinds since the next byte is not 0x08).
      result.subs = parseSubStreams(inp, result)
    assignSubstreams(result.files, dataIdx, result.subs, ctx)
  elif result.folders.len > 0:
    raise newException(SzError, "7z: files info missing")
  # else: empty archive (no files, no folders).
proc parseEncodedHeaderFolder(inp: Input; hinp: Input; ctx: ArchiveContext;
    z: Sz): string =
  ## Parse 0x17 PackInfo/UnpackInfo after the marker, decode the single
  ## folder to owned header bytes. `inp` is the whole file (pack source).
  var tmp = SzArchive()
  if remaining(hinp) <= 0:
    raise newException(SzError, "7z: truncated encoded header")
  if readByte(hinp) != 0x06:
    raise newException(SzError, "7z: bad encoded header")
  parsePackInfo(hinp, 32, tmp)
  if remaining(hinp) <= 0 or readByte(hinp) != 0x07:
    raise newException(SzError, "7z: bad encoded header")
  parseUnpackInfo(hinp, tmp)
  if remaining(hinp) <= 0 or readByte(hinp) != 0x00:
    raise newException(SzError, "7z: bad encoded header terminator")
  if tmp.folders.len != 1:
    raise newException(SzError, "7z: unsupported encoded header")
  # Bound decoded header size before allocating (last unpack size is
  # the folder output; AES chains have 2).
  if tmp.folders[0].unpackSizes.len == 0:
    raise newException(SzError, "7z: bad encoded header sizes")
  let want = tmp.folders[0].unpackSizes[^1]
  if want == 0 or want > uint64(szMaxHeaderBytes):
    raise newException(SzError, "7z: bad header size")
  if ctx.max7zHeaderBytes != 0 and want > uint64(ctx.max7zHeaderBytes):
    raise newException(SzError, "7z: header exceeds cap")
  try:
    result = decodeFolder(inp, tmp, 0, z, ctx)
  except SzError as e:
    # Missing password surfaces as password-required, not generic.
    raise e
  if result.len.uint64 != want:
    raise newException(SzError, "7z: header size mismatch")

proc parseHeaderFromInput(hinp: Input; inp: Input; ctx: ArchiveContext;
    z: Sz; depth: int): SzArchive =
  ## Parse header bytes (plain or encoded-recursive). `hinp` is the
  ## header view, `inp` the whole file for encoded pack resolution.
  if depth > szMaxFolderDepth:
    raise newException(SzError, "7z: header nesting too deep")
  if remaining(hinp) <= 0:
    raise newException(SzError, "7z: truncated header")
  let first = readByte(hinp)
  if first == 0x01:
    seek(hinp, 0)
    result = walkHeader(hinp, ctx, 32)
    if inputPos(hinp) != inputLen(hinp):
      discard # trailing tolerated (forward compat)
  elif first == 0x17:
    let inner = parseEncodedHeaderFolder(inp, hinp, ctx, z)
    let innerInp = openInputString(inner)
    result = parseHeaderFromInput(innerInp, inp, ctx, z, depth + 1)
  else:
    raise newException(SzError, "7z: bad header id")

# ---------- extraction walk ----------

proc extractSz*(z: Sz; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  ## Walk entries in archive order. Folders decode on first use and are
  ## cached per call (solid sharing); decode failures surface on open
  ## with explicit unsupported-method / password-required errors.
  ## Symlink targets resolve from the folder output at walk time.
  ctx.checkCancelled()
  if remaining(inp) < 32:
    raise newException(SzError, "7z: truncated signature")
  let (headOff, headSize, headCrc) = parseSignature(inp, ctx)
  let hout = headerInput(inp, headOff, headSize)
  # Verify outer header CRC before any decode (fail fast).
  let hs = spanAt(inp, int(32 + headOff), int(headSize))
  let hgot = if hs.len == 0: 0x00000000'u32
    else: crc32Update(0xFFFFFFFF'u32, hs.p, hs.len) xor 0xFFFFFFFF'u32
  if hgot != headCrc.uint32:
    raise newException(SzError, "7z: header CRC mismatch")
  var arch = parseHeaderFromInput(hout, inp, ctx, z, 0)
  # Folder cache: decoded outputs + open-time errors.
  var folderOut = newSeq[string](arch.folders.len)
  var folderErr = newSeq[string](arch.folders.len)
  var folderDone = newSeq[bool](arch.folders.len)
  var folderIsStore = newSeq[bool](arch.folders.len)
  var folderStoreSpan = newSeq[Span](arch.folders.len)
  for fi in 0 ..< arch.folders.len:
    let err = classifyFolder(arch.folders[fi], z)
    if err != "":
      folderErr[fi] = err
      folderDone[fi] = true
      continue
    # Single Copy folder stays zero-copy; others decode on first use.
    let f = arch.folders[fi]
    if f.coders.len == 1 and isCopyId(f.coders[0].id):
      try:
        let ps = resolvePackSpan(inp, arch, fi)
        var packIdx =
          if f.packIdx.len > 0: f.packIdx[0]
          else: folderPackBase(arch, fi)
        if arch.packHasCrc[packIdx] and ps.len > 0:
          verifySpanCrc(ps, arch.packCrcs[packIdx], " (pack stream)")
        if uint64(ps.len) != f.unpackSizes[0]:
          raise newException(SzError, "7z: copy size mismatch")
        folderIsStore[fi] = true
        folderStoreSpan[fi] = ps
        folderDone[fi] = true
      except SzError as e:
        folderErr[fi] = e.msg
        folderDone[fi] = true
    # else: lazy decode below
  proc ensureFolder(fi: int) =
    if folderDone[fi]:
      return
    folderDone[fi] = true
    try:
      folderOut[fi] = decodeFolder(inp, arch, fi, z, ctx)
    except SzError as e:
      folderErr[fi] = e.msg
  var index = 0
  var skipDirs: seq[string] = @[]
  template handleSz(fi: FileInfo) =
    ## Deliver one entry, honoring SkipAll/SkipDir/continueOnError like
    ## the zip/tar walks. Decode failures surface inside `handle`
    ## (lazy openers) and skip cleanly when enabled.
    try:
      {.gcsafe.}:
        handle(ctx, fi)
    except SkipAll:
      break
    except SkipDir:
      if fi.isDir():
        skipDirs.add(fi.nameInArchive)
    except CatchableError as e:
      if z.continueOnError and not ctx.cancelled():
        continue
      raise newException(SzError,
        "7z handling file: " & fe.name & ": " & e.msg)
  for fe in arch.files:
    ctx.checkCancelled()
    var skipped = false
    for sd in skipDirs:
      if fe.name.startsWith(sd):
        skipped = true
        break
    if skipped:
      continue
    ctx.reportProgress(fe.name, index, arch.files.len, fe.size)
    inc index
    var meta = FileMeta(name: baseNameV(fe.name), size: fe.size,
      mode: fe.mode, modTime: (if fe.hasTime: fe.mtime else: fromUnix(0)),
      isDir: fe.isDir, isSymlink: fe.isSymlink,
      isRegular: fe.isRegular)
    if fe.isDir:
      let fi = FileInfo(meta: meta, nameInArchive: fe.name,
        linkTarget: "", open: stringOpener(""))
      handleSz(fi)
      continue
    if fe.folderIdx < 0:
      # Empty file: no data, no substream.
      let fi = FileInfo(meta: meta, nameInArchive: fe.name,
        linkTarget: "", open: stringOpener(""))
      handleSz(fi)
      continue
    let fiIdx = fe.folderIdx
    if fiIdx < 0 or fiIdx >= arch.folders.len:
      raise newException(SzError, "7z: folder index out of range")
    if folderIsStore[fiIdx]:
      let fspan = folderStoreSpan[fiIdx]
      if fe.subOff + fe.subLen > uint64(fspan.len):
        raise newException(SzError, "7z: substream out of range")
      let sub = Span(p: cast[pointer](cast[int](fspan.p) + int(fe.subOff)),
        len: int(fe.subLen))
      if fe.isSymlink:
        var target = newString(sub.len)
        if sub.len > 0:
          copyMem(addr target[0], sub.p, sub.len)
        let fi = FileInfo(meta: meta, nameInArchive: fe.name,
          linkTarget: target, open: stringOpener(""))
        handleSz(fi)
        continue
      let opener = storeOpener(sub, inp, fe.dataCrc, fe.hasCrc,
        " (" & fe.name & ")")
      let fi = FileInfo(meta: meta, nameInArchive: fe.name,
        linkTarget: "", open: opener)
      handleSz(fi)
      continue
    # Compressed folder.
    if folderDone[fiIdx] and folderErr[fiIdx] != "":
      let fi = FileInfo(meta: meta, nameInArchive: fe.name,
        linkTarget: "", open: errOpener(folderErr[fiIdx]))
      handleSz(fi)
      continue
    if fe.isSymlink:
      # Target needed at walk time: decode now.
      ensureFolder(fiIdx)
      if folderErr[fiIdx] != "":
        let fi = FileInfo(meta: meta, nameInArchive: fe.name,
          linkTarget: "", open: errOpener(folderErr[fiIdx]))
        handleSz(fi)
        continue
      let outp = folderOut[fiIdx]
      if fe.subOff + fe.subLen > uint64(outp.len):
        raise newException(SzError, "7z: substream out of range")
      var target = newString(int(fe.subLen))
      if fe.subLen > 0:
        var o = outp
        copyMem(addr target[0], addr o[int(fe.subOff)],
          int(fe.subLen))
      let fi = FileInfo(meta: meta, nameInArchive: fe.name,
        linkTarget: target, open: stringOpener(""))
      handleSz(fi)
      continue
    # Regular file: lazy decode on open, cached per folder.
    let fOut = addr folderOut
    let fErr = addr folderErr
    let fDone = addr folderDone
    let subOff = int(fe.subOff)
    let subLen = int(fe.subLen)
    let dcrc = fe.dataCrc
    let dhas = fe.hasCrc
    let wmsg = " (" & fe.name & ")"
    let whatArch = addr arch
    let opener = proc(): Input {.closure.} =
      if not fDone[][fiIdx]:
        fDone[][fiIdx] = true
        try:
          fOut[][fiIdx] = decodeFolder(inp, whatArch[] , fiIdx, z, ctx)
        except SzError as e:
          fErr[][fiIdx] = e.msg
      if fErr[][fiIdx] != "":
        raise newException(SzError, fErr[][fiIdx])
      let outp = fOut[][fiIdx]
      if subOff < 0 or subLen < 0 or subOff + subLen > outp.len:
        raise newException(SzError, "7z: substream out of range")
      if dhas:
        verifyStringCrc(outp, subOff, subLen, dcrc, wmsg)
      if subLen == 0:
        return openInputString("")
      # Owned copy via intermediate var (addr on var is stable;
      # unsafeAddr on a let index can yield a temporary). One extra
      # copy per open, bounded by entry size.
      var sl = newString(subLen)
      var o = outp
      copyMem(addr sl[0], addr o[subOff], subLen)
      openInputCopy(unsafeAddr sl[0], sl.len)
    let fi = FileInfo(meta: meta, nameInArchive: fe.name,
      linkTarget: "", open: opener)
    handleSz(fi)


# ---------- STORE-only writer ----------

proc modeForWrite(f: FileInfo; isDir, isSymlink: bool): int =
  var m = f.meta.mode
  if m == 0:
    m = if isDir: 0o40755 elif isSymlink: 0o120777 else: 0o100644
  else:
    let typ = m and 0o170000
    if typ == 0:
      m = m or (if isDir: 0o40000 elif isSymlink: 0o120000 else: 0o100000)
  m

type SzPend = object
  arcName: string
  mode: int
  modTime: Time
  isDir: bool
  isSymlink: bool
  isRegular: bool
  raw: string
  crc: uint32

proc collectSzPend(ctx: ArchiveContext;
    files: seq[FileInfo]): seq[SzPend] =
  var keeps: seq[Input] = @[]
  for i, f in files:
    ctx.checkCancelled()
    var arcName = f.nameInArchive
    if arcName == "":
      arcName = f.name
    arcName = arcName.replace('\\', '/')
    while arcName.startsWith("/"):
      arcName = arcName[1 .. ^1]
    while arcName.startsWith("./"):
      arcName = arcName[2 .. ^1]
    if arcName == "" or arcName == ".":
      continue
    if f.meta.isDir:
      while arcName.endsWith("/") and arcName.len > 1:
        arcName = arcName[0 ..< ^1]
      result.add(SzPend(arcName: arcName & "/", mode: modeForWrite(f,
        true, false), modTime: f.meta.modTime, isDir: true))
    elif f.meta.isSymlink:
      result.add(SzPend(arcName: arcName, mode: modeForWrite(f, false,
        true), modTime: f.meta.modTime, isSymlink: true,
        raw: f.linkTarget,
        crc: crc32Update(0xFFFFFFFF'u32, f.linkTarget) xor
          0xFFFFFFFF'u32))
    elif f.meta.isRegular:
      var fr: Input
      {.gcsafe.}:
        fr = f.open()
      keeps.add(fr)
      let content = readSpan(fr, remaining(fr))
      var raw = newString(content.len)
      if content.len > 0:
        copyMem(addr raw[0], content.p, content.len)
      let c = if raw.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, unsafeAddr raw[0],
          raw.len) xor 0xFFFFFFFF'u32
      result.add(SzPend(arcName: arcName, mode: modeForWrite(f, false,
        false), modTime: f.meta.modTime, isRegular: true, raw: raw,
        crc: c))
    else:
      continue # hardlinks/fifos: skipped like the generic extractor
    ctx.reportProgress(arcName, i, files.len,
      if result[^1].isRegular: result[^1].raw.len.int64 else: 0)

proc writeSzFilesInfo(hdr: Output; pend: seq[SzPend]) =
  ## Shared FilesInfo writer (names, mtimes, attrs, empty bitmaps).
  writeByte(hdr, char(0x05))
  writeNum(hdr, pend.len.uint64)
  var hasEmpty = false
  for p in pend:
    if p.isDir or p.raw.len == 0:
      hasEmpty = true
      break
  if hasEmpty:
    var bits = newSeq[byte]((pend.len + 7) div 8)
    for i, p in pend:
      if p.isDir or p.raw.len == 0:
        bits[i div 8] = bits[i div 8] or byte(1 shl (7 - (i mod 8)))
    writeByte(hdr, char(0x0E))
    writeNum(hdr, bits.len.uint64)
    for b in bits:
      writeByte(hdr, char(b))
    var ecount = 0
    for p in pend:
      if p.isDir or p.raw.len == 0:
        inc ecount
    var ebits = newSeq[byte]((ecount + 7) div 8)
    var ei = 0
    for p in pend:
      if p.isDir or p.raw.len == 0:
        if p.isRegular:
          ebits[ei div 8] = ebits[ei div 8] or byte(1 shl (7 - (ei mod 8)))
        inc ei
    writeByte(hdr, char(0x0F))
    writeNum(hdr, ebits.len.uint64)
    for b in ebits:
      writeByte(hdr, char(b))
  if pend.len > 0:
    var nout = newOutput()
    for p in pend:
      let u16 = utf8ToUtf16le(p.arcName)
      if u16.len > 0:
        writeBytes(nout, unsafeAddr u16[0], u16.len)
      wrU16le(nout, 0)
    let nb = outputBytes(nout)
    writeByte(hdr, char(0x11))
    writeNum(hdr, (nb.len + 1).uint64)
    writeByte(hdr, char(0x00))
    if nb.len > 0:
      writeBytes(hdr, nb.p, nb.len)
    writeByte(hdr, char(0x14))
    writeNum(hdr, (2 + 8 * pend.len).uint64)
    writeByte(hdr, char(0x01))
    writeByte(hdr, char(0x00))
    for p in pend:
      wrU64le(hdr, timeToFiletime(p.modTime))
    writeByte(hdr, char(0x15))
    writeNum(hdr, (2 + 4 * pend.len).uint64)
    writeByte(hdr, char(0x01))
    writeByte(hdr, char(0x00))
    for p in pend:
      let win = if p.isDir: 0x8010'u32 else: 0x8020'u32
      wrU32le(hdr, (p.mode.uint32 shl 16) or win)
  writeByte(hdr, char(0x00))
  writeByte(hdr, char(0x00))

proc writeSzSignature(dst: Output; packBytes, hstr: string) =
  let hCrc = crc32Update(0xFFFFFFFF'u32, hstr) xor 0xFFFFFFFF'u32
  var start = newOutput()
  wrU64le(start, packBytes.len.uint64)
  wrU64le(start, hstr.len.uint64)
  wrU32le(start, hCrc)
  let sb = outputBytes(start)
  var startBytes = newString(sb.len)
  copyMem(addr startBytes[0], sb.p, sb.len)
  let sCrc = crc32Update(0xFFFFFFFF'u32, startBytes) xor 0xFFFFFFFF'u32
  for c in szMagic:
    writeByte(dst, c)
  writeByte(dst, char(0))
  writeByte(dst, char(4))
  wrU32le(dst, sCrc)
  writeBytes(dst, unsafeAddr startBytes[0], startBytes.len)
  if packBytes.len > 0:
    var pb = packBytes
    writeBytes(dst, addr pb[0], pb.len)
  if hstr.len > 0:
    var hs = hstr
    writeBytes(dst, addr hs[0], hs.len)

proc writeSzSignatureEnc(dst: Output; packBytes, hstr: string; z: Sz;
    ctx: ArchiveContext) =
  ## Header-encrypted write: LZMA2-compress + AES-encrypt the plain
  ## header, then emit an 0x17 EncodedHeader pointing at the header
  ## pack stream. Requires `password`.
  if z.password == "":
    raise newException(SzError, "7z: header encryption requires password")
  var power = 19
  if z.kdfLg2 != 0:
    if z.kdfLg2 < 0 or z.kdfLg2 > 30:
      raise newException(SzError, "7z: bad kdf length")
    power = z.kdfLg2
  var lzmaHdr: string
  try:
    lzmaHdr = lzma2EncodeSolid(hstr, byte(0x10), ctx.max7zDictBytes)
  except CatchableError as e:
    raise newException(SzError, "7z: header compress failed: " & e.msg)
  let (salt, iv) = randomAesSaltIv()
  var key: array[32, byte]
  var aprops: string
  try:
    key = deriveAesKey(z.password, salt, power)
    aprops = buildAesProps(salt, iv, power)
  except CatchableError as e:
    raise newException(SzError, "7z: " & e.msg)
  var ivArr: array[16, byte]
  for i in 0 ..< 16:
    ivArr[i] = iv[i]
  var cipher: string
  try:
    cipher = aesCbcEncryptPad(key, ivArr, lzmaHdr)
  except CatchableError as e:
    raise newException(SzError, "7z: header encrypt failed: " & e.msg)
  # Encoded header: 0x17 PackInfo UnpackInfo 0x00.
  var enc = newOutput()
  writeByte(enc, char(0x17))
  writeByte(enc, char(0x06))
  writeNum(enc, packBytes.len.uint64) # PackPos: after main packs
  writeNum(enc, 1)
  writeByte(enc, char(0x09))
  writeNum(enc, cipher.len.uint64)
  writeByte(enc, char(0x00))
  writeByte(enc, char(0x07))
  writeByte(enc, char(0x0B))
  writeNum(enc, 1)
  writeByte(enc, char(0x00))
  writeNum(enc, 2)
  writeByte(enc, char(0x24))
  writeByte(enc, char(0x06))
  writeByte(enc, char(0xF1))
  writeByte(enc, char(0x07))
  writeByte(enc, char(0x01))
  writeNum(enc, aprops.len.uint64)
  var ap = aprops
  writeBytes(enc, addr ap[0], ap.len)
  writeByte(enc, char(0x21))
  writeByte(enc, char(0x21))
  writeNum(enc, 1)
  writeByte(enc, char(0x10))
  writeNum(enc, 1)
  writeNum(enc, 0)
  writeByte(enc, char(0x0C))
  writeNum(enc, lzmaHdr.len.uint64)
  writeNum(enc, hstr.len.uint64)
  writeByte(enc, char(0x00))
  writeByte(enc, char(0x00))
  let eb = outputBytes(enc)
  var estr = newString(eb.len)
  if eb.len > 0:
    copyMem(addr estr[0], eb.p, eb.len)
  writeSzSignature(dst, packBytes & cipher, estr)

proc curLenOf(pend: seq[SzPend]; g: seq[int]): int =
  result = 0
  for ei in g:
    result += pend[ei].raw.len

proc archiveSzLzma2*(z: Sz; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  ## LZMA2-solid writer: data files share LZMA2 folders (≤8MiB solid
  ## data each, file-aligned). Plain headers, per-substream CRCs.
  ctx.checkCancelled()
  let pend = collectSzPend(ctx, files)
  # Group consecutive data entries (raw.len > 0) into ≤8MiB folders.
  const maxGroup = 8 * 1024 * 1024
  var groups: seq[seq[int]] = @[]
  var cur: seq[int] = @[]
  var curLen = 0
  for i, p in pend:
    if p.raw.len == 0:
      continue
    if cur.len > 0 and curLen + p.raw.len > maxGroup:
      groups.add(cur)
      cur = @[]
      curLen = 0
    cur.add(i)
    curLen += p.raw.len
  if cur.len > 0:
    groups.add(cur)
  # Encode groups: optional Delta pre-filter (auto-tried), LZMA2,
  # optional AES wrap. Per-group coder chain in decode order.
  let useAes = z.password != ""
  if useAes and z.meth != 1:
    raise newException(SzError,
      "7z: AES write requires LZMA2-solid (meth 1)")
  var power = 19
  if z.kdfLg2 != 0:
    if z.kdfLg2 < 0 or z.kdfLg2 > 30:
      raise newException(SzError, "7z: bad kdf length")
    power = z.kdfLg2
  var packOut = newOutput()
  var groupPack: seq[string] = @[]
  var groupSolid: seq[int] = @[]
  var groupCoders: seq[seq[tuple[id, props: string]]] = @[]
  var groupUnpack: seq[seq[uint64]] = @[]
  for gi, g in groups:
    var solid = newString(curLenOf(pend, g))
    var o = 0
    for ei in g:
      if pend[ei].raw.len > 0:
        var src = pend[ei].raw
        copyMem(addr solid[o], addr src[0], src.len)
        o += src.len
    # Filter candidates: plain, Delta(1), Delta(4). Delta preserves
    # length, so substream sizes never change.
    var bestPack = ""
    var bestDelta = ""
    var bestDist = 0
    var tried = 0
    var cands: seq[tuple[props: string; data: string]] = @[]
    cands.add(("", solid))
    if z.useFilters and solid.len > 0:
      for dist in [1, 4]:
        var f = solid
        try:
          deltaEncode(f, dist)
        except CatchableError as e:
          raise newException(SzError, "7z: " & e.msg)
        var pc = newString(1)
        pc[0] = chr(dist - 1)
        cands.add((props: pc, data: f))
    for c in cands:
      var pack: string
      try:
        pack = lzma2EncodeSolid(c.data, byte(0x10),
          ctx.max7zDictBytes)
      except CatchableError as e:
        raise newException(SzError, "7z: lzma2 encode failed: " & e.msg)
      inc tried
      if bestPack == "" or pack.len < bestPack.len:
        bestPack = pack
        bestDelta = c.props
        bestDist = tried
    discard bestDist
    var coders: seq[tuple[id, props: string]] = @[]
    var unpacks: seq[uint64] = @[]
    var lzmaLen = bestPack.len
    if useAes:
      let (salt, iv) = randomAesSaltIv()
      var key: array[32, byte]
      var aprops = ""
      try:
        key = deriveAesKey(z.password, salt, power)
        aprops = buildAesProps(salt, iv, power)
      except CatchableError as e:
        raise newException(SzError, "7z: " & e.msg)
      var ivArr: array[16, byte]
      for i in 0 ..< 16:
        ivArr[i] = iv[i]
      try:
        bestPack = aesCbcEncryptPad(key, ivArr, bestPack)
      except CatchableError as e:
        raise newException(SzError, "7z: aes encrypt failed: " & e.msg)
      coders.add((id: "\x06\xF1\x07\x01", props: aprops))
      unpacks.add(lzmaLen.uint64)
    coders.add((id: "\x21", props: "\x10"))
    unpacks.add(solid.len.uint64)
    if bestDelta != "":
      coders.add((id: "\x03", props: bestDelta))
      unpacks.add(solid.len.uint64)
    groupPack.add(bestPack)
    groupSolid.add(solid.len)
    groupCoders.add(coders)
    groupUnpack.add(unpacks)
    if bestPack.len > 0:
      var pp = bestPack
      writeBytes(packOut, addr pp[0], pp.len)
    ctx.reportProgress(pend[g[0]].arcName, gi, groups.len,
      solid.len.int64)
  let packSpan = outputBytes(packOut)
  var packBytes = newString(packSpan.len)
  if packSpan.len > 0:
    copyMem(addr packBytes[0], packSpan.p, packSpan.len)
  # Header.
  var hdr = newOutput()
  writeByte(hdr, char(0x01))
  if groups.len > 0:
    writeByte(hdr, char(0x04))
    writeByte(hdr, char(0x06))
    writeNum(hdr, 0)
    writeNum(hdr, groups.len.uint64)
    writeByte(hdr, char(0x09))
    for p in groupPack:
      writeNum(hdr, p.len.uint64)
    writeByte(hdr, char(0x00))
    writeByte(hdr, char(0x07))
    writeByte(hdr, char(0x0B))
    writeNum(hdr, groups.len.uint64)
    writeByte(hdr, char(0x00))
    for gi in 0 ..< groups.len:
      let coders = groupCoders[gi]
      writeNum(hdr, coders.len.uint64)
      for c in coders:
        var flags = c.id.len
        if c.props.len > 0:
          flags = flags or 0x20
        writeByte(hdr, char(flags))
        var mid = c.id
        writeBytes(hdr, addr mid[0], mid.len)
        if c.props.len > 0:
          writeNum(hdr, c.props.len.uint64)
          var mp = c.props
          writeBytes(hdr, addr mp[0], mp.len)
      if coders.len > 1:
        for i in 1 ..< coders.len:
          writeNum(hdr, i.uint64)
          writeNum(hdr, (i - 1).uint64)
    writeByte(hdr, char(0x0C))
    for gi in 0 ..< groups.len:
      for v in groupUnpack[gi]:
        writeNum(hdr, v)
    writeByte(hdr, char(0x00))
    # SubStreams: counts (only when a folder holds >1 file), sizes,
    # and one AllAreDefined CRC list (mirrors 7z's own layout).
    writeByte(hdr, char(0x08))
    var needCounts = false
    for g in groups:
      if g.len > 1:
        needCounts = true
        break
    if needCounts:
      writeByte(hdr, char(0x0D))
      for g in groups:
        writeNum(hdr, g.len.uint64)
      writeByte(hdr, char(0x09))
      for g in groups:
        for k in 0 ..< g.len - 1:
          writeNum(hdr, pend[g[k]].raw.len.uint64)
    writeByte(hdr, char(0x0A))
    writeByte(hdr, char(0x01))
    for g in groups:
      for ei in g:
        wrU32le(hdr, pend[ei].crc)
    writeByte(hdr, char(0x00))
    writeByte(hdr, char(0x00))
  writeSzFilesInfo(hdr, pend)
  # FilesInfo writer ends with FilesInfo 0x00 + header 0x00;
  # MainStreamsInfo was already closed above.
  let hb = outputBytes(hdr)
  var hstr = newString(hb.len)
  if hb.len > 0:
    copyMem(addr hstr[0], hb.p, hb.len)
  if z.encHeaders:
    writeSzSignatureEnc(dst, packBytes, hstr, z, ctx)
  else:
    writeSzSignature(dst, packBytes, hstr)

proc archiveSz*(z: Sz; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  ## Writer dispatcher: meth 0 = STORE (one Copy folder per data file),
  ## meth 1 = LZMA2-solid (fast level, shared folders, optional AES).
  ## Plain headers. Dirs and empty files carry no streams. Symlinks store
  ## the UTF-8 target as file data with a symlink mode.
  if z.meth == 1:
    archiveSzLzma2(z, ctx, dst, files)
    return
  elif z.meth != 0:
    raise newException(SzError, "7z: unknown write method")
  if z.password != "" and not z.encHeaders:
    raise newException(SzError,
      "7z: AES content write requires LZMA2-solid (meth 1)")
  ctx.checkCancelled()
  type SzPending = object
    arcName: string
    mode: int
    modTime: Time
    isDir: bool
    isSymlink: bool
    isRegular: bool
    raw: string
    crc: uint32
  var pend: seq[SzPending] = @[]
  var keeps: seq[Input] = @[]
  for i, f in files:
    ctx.checkCancelled()
    var arcName = f.nameInArchive
    if arcName == "":
      arcName = f.name
    arcName = arcName.replace('\\', '/')
    while arcName.startsWith("/"):
      arcName = arcName[1 .. ^1]
    while arcName.startsWith("./"):
      arcName = arcName[2 .. ^1]
    if arcName == "" or arcName == ".":
      continue
    if f.meta.isDir:
      while arcName.endsWith("/") and arcName.len > 1:
        arcName = arcName[0 ..< ^1]
      pend.add(SzPending(arcName: arcName & "/", mode: modeForWrite(f,
        true, false), modTime: f.meta.modTime, isDir: true))
    elif f.meta.isSymlink:
      pend.add(SzPending(arcName: arcName, mode: modeForWrite(f, false,
        true), modTime: f.meta.modTime, isSymlink: true,
        raw: f.linkTarget,
        crc: crc32Update(0xFFFFFFFF'u32, f.linkTarget) xor
          0xFFFFFFFF'u32))
    elif f.meta.isRegular:
      var fr: Input
      {.gcsafe.}:
        fr = f.open()
      keeps.add(fr)
      let content = readSpan(fr, remaining(fr))
      var raw = newString(content.len)
      if content.len > 0:
        copyMem(addr raw[0], content.p, content.len)
      let c = if raw.len == 0: 0'u32
        else: crc32Update(0xFFFFFFFF'u32, unsafeAddr raw[0],
          raw.len) xor 0xFFFFFFFF'u32
      pend.add(SzPending(arcName: arcName, mode: modeForWrite(f, false,
        false), modTime: f.meta.modTime, isRegular: true, raw: raw,
        crc: c))
    else:
      continue # hardlinks/fifos: skipped like the generic extractor
    ctx.reportProgress(arcName, i, files.len,
      if pend[^1].isRegular: pend[^1].raw.len.int64 else: 0)
  # Pack data: concatenated raw bytes, one stream per data file.
  var packIdxOf = newSeq[int](pend.len)
  var packOut = newOutput()
  var npack = 0
  for i, p in pend:
    # Only entries with bytes get pack streams; zero-length files and
    # empty-target symlinks are pure metadata (EmptyStream entries).
    if p.raw.len > 0:
      packIdxOf[i] = npack
      inc npack
      writeBytes(packOut, unsafeAddr p.raw[0], p.raw.len)
    else:
      packIdxOf[i] = -1
  let packBytes = outputBytes(packOut)
  # Header.
  var hdr = newOutput()
  writeByte(hdr, char(0x01))
  if npack > 0:
    writeByte(hdr, char(0x04))
    writeByte(hdr, char(0x06)) # PackInfo
    writeNum(hdr, 0) # PackPos
    writeNum(hdr, npack.uint64)
    writeByte(hdr, char(0x09))
    for i, p in pend:
      if packIdxOf[i] >= 0:
        writeNum(hdr, p.raw.len.uint64)
    writeByte(hdr, char(0x00))
    # No pack digests and no folder CRCs: like 7z, per-substream CRCs
    # live in SubStreamsInfo. PackInfo has no terminator of its own.
    writeByte(hdr, char(0x07)) # UnpackInfo
    writeByte(hdr, char(0x0B))
    writeNum(hdr, npack.uint64)
    writeByte(hdr, char(0x00)) # inline folders
    for i, p in pend:
      if packIdxOf[i] < 0:
        continue
      writeNum(hdr, 1) # NumCoders
      writeByte(hdr, char(0x01)) # idSize 1, simple, no props
      writeByte(hdr, char(0x00)) # Copy
      # no bind pairs (1 in, 1 out), implicit packed index
    writeByte(hdr, char(0x0C))
    for i, p in pend:
      if packIdxOf[i] >= 0:
        writeNum(hdr, p.raw.len.uint64)
    writeByte(hdr, char(0x00)) # end UnpackInfo
    # SubStreams with per-file CRCs (always explicit, like 7z).
    writeByte(hdr, char(0x08))
    writeByte(hdr, char(0x0A))
    writeByte(hdr, char(0x01)) # all substreams defined
    for i, p in pend:
      if packIdxOf[i] >= 0:
        wrU32le(hdr, p.crc)
    writeByte(hdr, char(0x00)) # end SubStreamsInfo
    writeByte(hdr, char(0x00)) # end MainStreamsInfo
  # FilesInfo.
  writeByte(hdr, char(0x05))
  writeNum(hdr, pend.len.uint64)
  var hasEmpty = false
  for p in pend:
    if p.isDir or p.raw.len == 0:
      hasEmpty = true
      break
  if hasEmpty:
    var bits = newSeq[byte]((pend.len + 7) div 8)
    for i, p in pend:
      if p.isDir or p.raw.len == 0:
        bits[i div 8] = bits[i div 8] or byte(1 shl (7 - (i mod 8)))
    writeByte(hdr, char(0x0E))
    writeNum(hdr, bits.len.uint64)
    for b in bits:
      writeByte(hdr, char(b))
    var ecount = 0
    for p in pend:
      if p.isDir or p.raw.len == 0:
        inc ecount
    var ebits = newSeq[byte]((ecount + 7) div 8)
    var ei = 0
    for p in pend:
      if p.isDir or p.raw.len == 0:
        if p.isRegular:
          ebits[ei div 8] = ebits[ei div 8] or byte(1 shl (7 - (ei mod 8)))
        inc ei
    writeByte(hdr, char(0x0F))
    writeNum(hdr, ebits.len.uint64)
    for b in ebits:
      writeByte(hdr, char(b))
  # Names.
  if pend.len > 0:
    var nout = newOutput()
    for p in pend:
      let u16 = utf8ToUtf16le(p.arcName)
      if u16.len > 0:
        writeBytes(nout, unsafeAddr u16[0], u16.len)
      wrU16le(nout, 0)
    let nb = outputBytes(nout)
    writeByte(hdr, char(0x11))
    writeNum(hdr, (nb.len + 1).uint64)
    writeByte(hdr, char(0x00)) # inline
    if nb.len > 0:
      writeBytes(hdr, nb.p, nb.len)
    # MTime: all defined, inline.
    writeByte(hdr, char(0x14))
    writeNum(hdr, (2 + 8 * pend.len).uint64)
    writeByte(hdr, char(0x01))
    writeByte(hdr, char(0x00))
    for p in pend:
      wrU64le(hdr, timeToFiletime(p.modTime))
    # Attrs: all defined, inline.
    writeByte(hdr, char(0x15))
    writeNum(hdr, (2 + 4 * pend.len).uint64)
    writeByte(hdr, char(0x01))
    writeByte(hdr, char(0x00))
    for p in pend:
      # Low word: Windows attrs plus bit 15, which flags the high word
      # as a Unix mode (7z convention; readers use it to find S_IFLNK).
      let win = if p.isDir: 0x8010'u32 else: 0x8020'u32
      wrU32le(hdr, (p.mode.uint32 shl 16) or win)
  writeByte(hdr, char(0x00)) # end FilesInfo
  writeByte(hdr, char(0x00)) # end header
  # Assemble: signature + packs + header (optionally header-encrypted).
  let hb = outputBytes(hdr)
  var hstr = newString(hb.len)
  if hb.len > 0:
    copyMem(addr hstr[0], hb.p, hb.len)
  let pb = outputBytes(packOut)
  var packStr = newString(pb.len)
  if pb.len > 0:
    copyMem(addr packStr[0], pb.p, pb.len)
  if z.encHeaders:
    writeSzSignatureEnc(dst, packStr, hstr, z, ctx)
  else:
    writeSzSignature(dst, packStr, hstr)
