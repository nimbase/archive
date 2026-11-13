## 7z AES-256-CBC decryption, clean-room implementation.
##
## Property parsing follows 7z-written ground truth (NOT the stale docs
## page): byte0 = (saltFlag<<7)|(ivFlag<<6)|(power&0x3F), byte1 =
## (saltExtra<<4)|(ivExtra), saltLen = 1+extra if flagged else 0
## (0..16 max), same for IV, layout header+salt+IV with exact length.
## KDF: iterations = 2^power (reject >30), block = salt || UTF16LE(pw)
## || LE64(i) per iteration fed into one running SHA-256. CBC decrypt
## with zero-padded IV, truncate to the AES unpack size. Raises
## ArchiveError with "7z: ..." messages.

import nimcypher/hash as ncHash
import nimcypher/aes as ncAes
import ../types

type AesError* = object of ArchiveError

proc utf16leBytes*(password: string): seq[byte] =
  ## UTF-16LE without BOM or terminator. Rejects unpaired surrogates
  ## by encoding runes (astral -> surrogate pair).
  result = @[]
  var i = 0
  while i < password.len:
    let b0 = ord(password[i])
    var cp = 0
    var nb = 1
    if b0 < 0x80:
      cp = b0
    elif (b0 and 0xE0) == 0xC0:
      nb = 2
      cp = b0 and 0x1F
    elif (b0 and 0xF0) == 0xE0:
      nb = 3
      cp = b0 and 0x0F
    elif (b0 and 0xF8) == 0xF0:
      nb = 4
      cp = b0 and 0x07
    else:
      raise newException(AesError, "7z: bad password encoding")
    if i + nb > password.len:
      raise newException(AesError, "7z: bad password encoding")
    for k in 1 ..< nb:
      let bx = ord(password[i + k])
      if (bx and 0xC0) != 0x80:
        raise newException(AesError, "7z: bad password encoding")
      cp = (cp shl 6) or (bx and 0x3F)
    i += nb
    if cp < 0x10000:
      if cp >= 0xD800 and cp <= 0xDFFF:
        raise newException(AesError, "7z: bad password encoding")
      result.add(byte(cp and 0xFF))
      result.add(byte((cp shr 8) and 0xFF))
    else:
      let v = cp - 0x10000
      let hi = 0xD800 + (v shr 10)
      let lo = 0xDC00 + (v and 0x3FF)
      result.add(byte(hi and 0xFF))
      result.add(byte((hi shr 8) and 0xFF))
      result.add(byte(lo and 0xFF))
      result.add(byte((lo shr 8) and 0xFF))

proc parseAesProps*(props: string): tuple[salt: seq[byte]; iv: array[16,
    byte]; power: int] =
  if props.len < 1:
    raise newException(AesError, "7z: truncated aes props")
  let b0 = ord(props[0])
  let hasSalt = (b0 and 0x80) != 0
  let hasIv = (b0 and 0x40) != 0
  let power = b0 and 0x3F
  if power > 30:
    raise newException(AesError, "7z: aes iterations too large")
  var saltLen = 0
  var ivLen = 0
  var off = 1
  if not hasSalt and not hasIv:
    if props.len != 1:
      raise newException(AesError, "7z: bad aes props length")
  else:
    if props.len < 2:
      raise newException(AesError, "7z: truncated aes props")
    let b1 = ord(props[1])
    off = 2
    if hasSalt:
      saltLen = ((b1 shr 4) and 0x0F) + 1
    if hasIv:
      ivLen = (b1 and 0x0F) + 1
    if saltLen > 16 or ivLen > 16:
      raise newException(AesError, "7z: bad aes salt/iv length")
    if props.len != off + saltLen + ivLen:
      raise newException(AesError, "7z: bad aes props length")
  result.power = power
  result.salt = @[]
  for i in 0 ..< 16:
    result.iv[i] = 0
  for i in 0 ..< saltLen:
    result.salt.add(byte(ord(props[off + i])))
  for i in 0 ..< ivLen:
    result.iv[i] = byte(ord(props[off + saltLen + i]))

proc deriveAesKey*(password: string; salt: openArray[byte];
    power: int): array[32, byte] =
  if power < 0 or power > 30:
    raise newException(AesError, "7z: aes iterations too large")
  let pw = utf16leBytes(password)
  let iters = 1 shl power
  var st = ncHash.initSha256()
  var counter = newSeq[byte](8)
  # scratch = salt || pw || counter(8)
  var blockLen = salt.len + pw.len + 8
  var blk = newSeq[byte](blockLen)
  for i in 0 ..< salt.len:
    blk[i] = salt[i]
  for i in 0 ..< pw.len:
    blk[salt.len + i] = pw[i]
  for it in 0 ..< iters:
    for k in 0 ..< 8:
      blk[salt.len + pw.len + k] = byte((it shr (8 * k)) and 0xFF)
    st.update(blk)
    discard counter
  result = st.finish()

proc aesCbcDecryptTrunc*(key: array[32, byte]; iv: array[16, byte];
    data: string; truncLen: int): string =
  if data.len mod 16 != 0:
    raise newException(AesError, "7z: aes block misaligned")
  if truncLen < 0 or truncLen > data.len:
    raise newException(AesError, "7z: bad aes unpack size")
  if data.len == 0:
    if truncLen != 0:
      raise newException(AesError, "7z: bad aes unpack size")
    return ""
  let pt = ncAes.aesCbcDecrypt(key, iv, data.toOpenArrayByte(0,
      data.len - 1), padded = false)
  if pt.len < truncLen:
    raise newException(AesError, "7z: aes short output")
  result = newString(truncLen)
  if truncLen > 0:
    copyMem(addr result[0], unsafeAddr pt[0], truncLen)
