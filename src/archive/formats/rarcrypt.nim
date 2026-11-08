## RAR5/7.0 AES-256-CBC file and header encryption (CRYPT_RAR50).
##
## Clean-room implementation from the format specification (Appendix C and
## ENCRYPTION_WRITE_SIDE §5): PBKDF2-HMAC-SHA256 chain with three taps
## (Key after Count iterations, HashKey 16 later, PswCheck material 16
## after that), AES-256-CBC with zero padding, PswCheck folding, and
## HashMAC CRC conversion. No BLAKE2sp dependency: writers emit CRC32
## only, which is the authoritative check when no hash record is present.
##
## No globals; all state is per-call. Passwords flow per call (truncated
## to 127 Unicode scalars per the cross-version ceiling) and derived
## keys are wiped on scope exit by the caller where practical.

import std/unicode
import nimcypher/hash as ncHash
import nimcypher/aes as ncAes
import nimcypher/utils as ncUtils
import ../types

type RarCryptError* = object of ArchiveError

const
  rarKdfDefaultLg2* = 15
    ## WinRAR default: 32768 iterations.
  rarKdfMaxLg2* = 24
    ## Decoder hard maximum; writers must never exceed it.
  rarKdfMinLg2* = 10
    ## Soft floor: below 1024 iterations is evidence of a hostile encoder.
  rarSaltLen* = 16
  rarIvLen* = 16

proc truncRarPassword*(pwd: string): string =
  ## Truncate to the first 127 Unicode scalars. All RAR versions copy the
  ## password into a 127-entry buffer; anything past that never reaches
  ## the KDF, so an encoder that skips the clamp derives a key no
  ## official tool can reproduce. BMP passwords are unaffected.
  var runes: seq[Rune] = @[]
  for r in pwd.runes:
    if runes.len >= 127:
      break
    runes.add(r)
  if runes.len == 0 and pwd.len == 0:
    return ""
  result = ""
  for r in runes:
    result.add($r)

proc pwdBytes*(pwd: string): seq[byte] =
  ## UTF-8 bytes of the truncated password (RAR5 uses UTF-8, no NUL).
  let t = truncRarPassword(pwd)
  result = newSeq[byte](t.len)
  if t.len > 0:
    copyMem(addr result[0], unsafeAddr t[0], t.len)

proc rarPbkdf2Chain*(pwd: openArray[byte]; salt: openArray[byte];
    count: int): tuple[key, hashKey, checkRaw: array[32, byte]] =
  ## One PBKDF2-HMAC-SHA256 chain tapped at three points. U1 =
  ## HMAC(Pwd, Salt || 0x00000001); Fn is the running XOR of all Ui.
  ## Key = Fn after Count iterations, HashKey 16 later, check material
  ## 16 after that. Raises on non-positive counts.
  if count <= 0:
    raise newException(RarCryptError, "rar: bad KDF iteration count")
  if salt.len == 0:
    raise newException(RarCryptError, "rar: bad salt length")
  var msg0 = newSeq[byte](salt.len + 4)
  for i in 0 ..< salt.len:
    msg0[i] = salt[i]
  msg0[salt.len] = 0
  msg0[salt.len + 1] = 0
  msg0[salt.len + 2] = 0
  msg0[salt.len + 3] = 1
  var u: array[32, byte] = ncHash.sha256Hmac(pwd, msg0)
  var fn = u
  for _ in 2 .. count:
    u = ncHash.sha256Hmac(pwd, u)
    for j in 0 .. 31:
      fn[j] = fn[j] xor u[j]
  result.key = fn
  for _ in 0 ..< 16:
    u = ncHash.sha256Hmac(pwd, u)
    for j in 0 .. 31:
      fn[j] = fn[j] xor u[j]
  result.hashKey = fn
  for _ in 0 ..< 16:
    u = ncHash.sha256Hmac(pwd, u)
    for j in 0 .. 31:
      fn[j] = fn[j] xor u[j]
  result.checkRaw = fn
  ncUtils.wipe(u)
  ncUtils.wipe(msg0)

proc rarFoldCheck*(checkRaw: array[32, byte]): array[8, byte] =
  ## XOR-fold the 32-byte check material into 8 bytes (quarters).
  for i in 0 ..< 8:
    result[i] = checkRaw[i] xor checkRaw[i + 8] xor checkRaw[i + 16] xor
      checkRaw[i + 24]

proc rarCheckStored*(checkRaw: array[32, byte]): array[12, byte] =
  ## 12-byte stored Check Value: 8 folded bytes + SHA-256(folded)[0..4].
  ## The trailing 4 bytes are a truncated SHA-256 digest, not a CRC32.
  let folded = rarFoldCheck(checkRaw)
  let digest = ncHash.sha256(folded)
  for i in 0 ..< 8:
    result[i] = folded[i]
  for i in 0 ..< 4:
    result[8 + i] = digest[i]

proc rarVerifyCheck*(stored12: openArray[byte];
    checkRaw: array[32, byte]): bool =
  ## Verify the stored 12-byte check value. All-zero folded bytes skip
  ## the explicit check (WinRAR 5.21 quirk): return true and let the
  ## data checksum decide.
  if stored12.len != 12:
    return false
  var allZero = true
  for i in 0 ..< 8:
    if stored12[i] != 0:
      allZero = false
      break
  if allZero:
    return true
  let folded = rarFoldCheck(checkRaw)
  for i in 0 ..< 8:
    if stored12[i] != folded[i]:
      return false
  let digest = ncHash.sha256(folded)
  for i in 0 ..< 4:
    if stored12[8 + i] != digest[i]:
      return false
  true

proc rarHashMacCrc*(hashKey: array[32, byte]; crc: uint32): uint32 =
  ## Convert a CRC32 into its key-dependent MAC: serialize LE, compute
  ## HMAC-SHA256(HashKey, bytes), XOR-fold the 32-byte digest into a
  ## 32-bit LE integer (each output byte gets 8 input bytes).
  var le: array[4, byte]
  le[0] = byte(crc and 0xFF)
  le[1] = byte((crc shr 8) and 0xFF)
  le[2] = byte((crc shr 16) and 0xFF)
  le[3] = byte((crc shr 24) and 0xFF)
  let digest = ncHash.sha256Hmac(hashKey, le)
  var outLe: array[4, byte] = [0'u8, 0, 0, 0]
  for i in 0 ..< 32:
    outLe[i and 3] = outLe[i and 3] xor digest[i]
  result = outLe[0].uint32 or (outLe[1].uint32 shl 8) or
    (outLe[2].uint32 shl 16) or (outLe[3].uint32 shl 24)

proc rarAesEncrypt*(key: array[32, byte]; iv: array[16, byte];
    plaintext: openArray[byte]): seq[byte] =
  ## AES-256-CBC with zero padding to 16 bytes. Returns the ciphertext.
  let paddedLen = ((plaintext.len + 15) div 16) * 16
  var padded = newSeq[byte](paddedLen)
  if plaintext.len > 0:
    copyMem(addr padded[0], unsafeAddr plaintext[0], plaintext.len)
  if paddedLen == 0:
    return @[]
  result = ncAes.aesCbcEncrypt(key, iv, padded, padded = false)

proc rarAesDecrypt*(key: array[32, byte]; iv: array[16, byte];
    ciphertext: openArray[byte]): seq[byte] =
  ## AES-256-CBC decrypt. Ciphertext must be a multiple of 16 bytes;
  ## the caller truncates padding via framing (LZ last-block or header
  ## sizes). Returns the full padded plaintext.
  if ciphertext.len == 0:
    return @[]
  if ciphertext.len mod 16 != 0:
    raise newException(RarCryptError, "rar: ciphertext not block-aligned")
  result = ncAes.aesCbcDecrypt(key, iv, ciphertext, padded = false)

proc rarRandomSalt*(): array[16, byte] =
  ncUtils.randomBytes[16]()

proc rarRandomIv*(): array[16, byte] =
  ncUtils.randomBytes[16]()

proc checkLg2*(lg2: int) =
  if lg2 > rarKdfMaxLg2:
    raise newException(RarCryptError,
      "rar: KDF count exceeds decoder maximum")
  if lg2 < 0:
    raise newException(RarCryptError, "rar: bad KDF count")
