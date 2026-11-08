## Encrypted blobs via pkg/nimcypher (XChaCha20-Poly1305 chunked AEAD).
##
## Envelope encryption around whole blobs: callers archive, optionally
## compress, then encrypt (reverse on read). No key material is retained:
## raw keys flow per call, password keys derive per call via Argon2id and
## wipe on scope exit, and the ratchet state is wiped after each message.
## File-to-file paths reuse fixed buffers (never hold full contents);
## one-shot paths hold only the output, like every other codec here.

from std/os import removeFile, getFileSize
import nimcypher/algos/aead as ncAead
import nimcypher/utils as ncUtils
import nimcypher/password as ncPass
import ./types
import ./io

type CryptoError* = object of ArchiveError

const
  encMagic* = "NIMENC01"
    ## 8-byte file magic. Operational, not cryptographic: rejects
    ## non-blobs before the (expensive) Argon2id KDF runs and lets
    ## `identify`-style sniffing name the format.
  encVersion* = 1'u8
  encKdfRaw* = 0'u8
  encKdfArgon2* = 1'u8
  encSaltLen* = 16
  encNonceLen* = 24
  encMacLen* = 16
  encHeaderLen* = 62
    ## magic 8 + version 1 + kdf 1 + salt 16 + nonce 24 + chunkSize u32
    ## LE + totalLen u64 LE. Fixed size: parse is one bounds check.
  encChunkDefault* = 65536
  encChunkMax* = 4 * 1024 * 1024
    ## Header chunkSize above this is rejected before any buffer is
    ## allocated, so malicious headers cannot trigger huge allocs.

proc putLe32(dst: Output; v: uint32) =
  writeByte(dst, byte(v and 0xFF))
  writeByte(dst, byte((v shr 8) and 0xFF))
  writeByte(dst, byte((v shr 16) and 0xFF))
  writeByte(dst, byte((v shr 24) and 0xFF))

proc getLe32(b: openArray[byte]; off: int): uint32 =
  result = b[off].uint32 or (b[off + 1].uint32 shl 8) or
    (b[off + 2].uint32 shl 16) or (b[off + 3].uint32 shl 24)

proc getLe64(b: openArray[byte]; off: int): uint64 =
  result = getLe32(b, off).uint64 or (getLe32(b, off + 4).uint64 shl 32)

proc buildHeader(kdf: uint8; salt: openArray[byte]; nonce: ncUtils.Nonce24;
    chunkSize: int; totalLen: uint64): seq[byte] =
  ## Fixed 62-byte header; the full header authenticates chunk 0 as AD.
  result = newSeq[byte](encHeaderLen)
  for i in 0 ..< 8:
    result[i] = byte(encMagic[i])
  result[8] = encVersion
  result[9] = kdf
  for i in 0 ..< encSaltLen:
    result[10 + i] = if i < salt.len: salt[i] else: 0
  for i in 0 ..< encNonceLen:
    result[26 + i] = nonce[i]
  let cs = chunkSize.uint32
  result[50] = byte(cs and 0xFF)
  result[51] = byte((cs shr 8) and 0xFF)
  result[52] = byte((cs shr 16) and 0xFF)
  result[53] = byte((cs shr 24) and 0xFF)
  for i in 0 ..< 8:
    result[54 + i] = byte((totalLen shr (8 * i)) and 0xFF)

type EncHeader* = object
  kdf*: uint8
  salt*: array[16, byte]
  nonce*: array[24, byte]
  chunkSize*: int
  totalLen*: uint64

proc parseHeader(hdr: openArray[byte]): EncHeader =
  ## Validate a 62-byte header; raises CryptoError, never allocates.
  if hdr.len < encHeaderLen:
    raise newException(CryptoError, "crypto: truncated header")
  for i in 0 ..< 8:
    if hdr[i] != byte(encMagic[i]):
      raise newException(CryptoError, "crypto: not an encrypted blob")
  if hdr[8] != encVersion:
    raise newException(CryptoError, "crypto: unsupported version")
  if hdr[9] != encKdfRaw and hdr[9] != encKdfArgon2:
    raise newException(CryptoError, "crypto: unknown kdf")
  let cs = getLe32(hdr, 50).int
  if cs <= 0 or cs > encChunkMax:
    raise newException(CryptoError, "crypto: invalid chunk size")
  result.kdf = hdr[9]
  for i in 0 ..< encSaltLen:
    result.salt[i] = hdr[10 + i]
  for i in 0 ..< encNonceLen:
    result.nonce[i] = hdr[26 + i]
  result.chunkSize = cs
  result.totalLen = getLe64(hdr, 54)

proc checkChunkSize*(chunkSize: int) =
  if chunkSize <= 0 or chunkSize > encChunkMax:
    raise newException(CryptoError, "crypto: invalid chunk size")

proc encryptInto*(data: openArray[byte]; key: ncUtils.Key32; dst: Output;
    chunkSize = encChunkDefault) =
  ## Encrypt `data` into `dst` (header + chunk records). Fixed reused
  ## buffers; no full-plaintext or full-ciphertext holding besides the
  ## caller's `data` and `dst`. Always emits at least one chunk so even
  ## empty input authenticates the header.
  checkChunkSize(chunkSize)
  let nonce = ncUtils.randomBytes[24]()
  let hdr = buildHeader(encKdfRaw, [], nonce, chunkSize, data.len.uint64)
  var st: ncAead.AeadContext
  ncAead.initX(st, key, nonce)
  try:
    writeBytes(dst, unsafeAddr hdr[0], hdr.len)
    var plain = newSeq[byte](chunkSize)
    var cipher = newSeq[byte](chunkSize)
    var ad: seq[byte] = hdr
    var off = 0
    while true:
      let n = min(chunkSize, data.len - off)
      if n > 0:
        copyMem(addr plain[0], unsafeAddr data[off], n)
      let mac = ncAead.writeInto(st, cipher.toOpenArray(0, n - 1),
        plain.toOpenArray(0, n - 1), ad)
      ad = @[]
      putLe32(dst, n.uint32)
      if n > 0:
        writeBytes(dst, addr cipher[0], n)
      writeBytes(dst, unsafeAddr mac, encMacLen)
      off += n
      if off >= data.len:
        break
  finally:
    ncUtils.wipe(st.key)

proc encryptInto*(data: openArray[byte]; password: string; dst: Output;
    chunkSize = encChunkDefault) =
  ## Password variant: fresh random salt per message, Argon2id KDF.
  checkChunkSize(chunkSize)
  let salt = ncUtils.generateSalt()
  let sk = ncPass.deriveKeyFromPassword(password, salt)
  let nonce = ncUtils.randomBytes[24]()
  let hdr = buildHeader(encKdfArgon2, salt, nonce, chunkSize,
    data.len.uint64)
  var st: ncAead.AeadContext
  ncAead.initX(st, sk.data, nonce)
  try:
    writeBytes(dst, unsafeAddr hdr[0], hdr.len)
    var plain = newSeq[byte](chunkSize)
    var cipher = newSeq[byte](chunkSize)
    var ad: seq[byte] = hdr
    var off = 0
    while true:
      let n = min(chunkSize, data.len - off)
      if n > 0:
        copyMem(addr plain[0], unsafeAddr data[off], n)
      let mac = ncAead.writeInto(st, cipher.toOpenArray(0, n - 1),
        plain.toOpenArray(0, n - 1), ad)
      ad = @[]
      putLe32(dst, n.uint32)
      if n > 0:
        writeBytes(dst, addr cipher[0], n)
      writeBytes(dst, unsafeAddr mac, encMacLen)
      off += n
      if off >= data.len:
        break
  finally:
    ncUtils.wipe(st.key)

proc decryptInto*(inp: Input; key: ncUtils.Key32; dst: Output) =
  ## Decrypt a blob from `inp` into `dst`. Verifies magic, version and
  ## every chunk MAC; the trailing length check catches truncation.
  ## Fixed reused buffers; holds only the output, like other codecs.
  if remaining(inp) < encHeaderLen:
    raise newException(CryptoError, "crypto: truncated header")
  let hspan = readSpan(inp, encHeaderLen)
  var hdr = newSeq[byte](encHeaderLen)
  copyMem(addr hdr[0], hspan.p, encHeaderLen)
  let h = parseHeader(hdr)
  if h.kdf != encKdfRaw:
    raise newException(CryptoError,
      "crypto: password-encrypted blob needs a password")
  var st: ncAead.AeadContext
  ncAead.initX(st, key, h.nonce)
  try:
    var plain = newSeq[byte](h.chunkSize)
    var cipher = newSeq[byte](h.chunkSize)
    var ad: seq[byte] = hdr
    var produced: uint64 = 0
    while produced < h.totalLen or (produced == 0 and h.totalLen == 0 and
        ad.len > 0):
      # Always read at least one chunk: empty input still carries a
      # header-authenticating empty record.
      if remaining(inp) < 4:
        raise newException(CryptoError, "crypto: truncated chunk")
      let lspan = readSpan(inp, 4)
      var lb = [0'u8, 0, 0, 0]
      copyMem(addr lb[0], lspan.p, 4)
      let n = getLe32(lb, 0).int
      if n < 0 or n > h.chunkSize:
        raise newException(CryptoError, "crypto: invalid chunk length")
      if produced + n.uint64 > h.totalLen:
        raise newException(CryptoError, "crypto: length overflow")
      if remaining(inp) < n + encMacLen:
        raise newException(CryptoError, "crypto: truncated chunk")
      if n > 0:
        let cspan = readSpan(inp, n)
        copyMem(addr cipher[0], cspan.p, n)
      let mspan = readSpan(inp, encMacLen)
      var mac: array[16, byte]
      copyMem(addr mac[0], mspan.p, encMacLen)
      if not ncAead.readInto(st, plain.toOpenArray(0, n - 1),
          cipher.toOpenArray(0, n - 1), mac, ad):
        raise newException(CryptoError, "crypto: authentication failed")
      ad = @[]
      if n > 0:
        writeBytes(dst, addr plain[0], n)
      produced += n.uint64
      if h.totalLen == 0:
        break
    if produced != h.totalLen:
      raise newException(CryptoError, "crypto: truncated stream")
    if remaining(inp) != 0:
      raise newException(CryptoError, "crypto: trailing data")
  finally:
    ncUtils.wipe(st.key)

proc decryptInto*(inp: Input; password: string; dst: Output) =
  ## Password variant: salt comes from the header, Argon2id derives the
  ## key. Wrong passwords fail at the first chunk MAC.
  if remaining(inp) < encHeaderLen:
    raise newException(CryptoError, "crypto: truncated header")
  let hspan = readSpan(inp, encHeaderLen)
  var hdr = newSeq[byte](encHeaderLen)
  copyMem(addr hdr[0], hspan.p, encHeaderLen)
  let h = parseHeader(hdr)
  if h.kdf != encKdfArgon2:
    raise newException(CryptoError,
      "crypto: raw-key blob needs a key, not a password")
  let sk = ncPass.deriveKeyFromPassword(password, h.salt)
  var st: ncAead.AeadContext
  ncAead.initX(st, sk.data, h.nonce)
  try:
    var plain = newSeq[byte](h.chunkSize)
    var cipher = newSeq[byte](h.chunkSize)
    var ad: seq[byte] = hdr
    var produced: uint64 = 0
    while produced < h.totalLen or (produced == 0 and h.totalLen == 0 and
        ad.len > 0):
      if remaining(inp) < 4:
        raise newException(CryptoError, "crypto: truncated chunk")
      let lspan = readSpan(inp, 4)
      var lb = [0'u8, 0, 0, 0]
      copyMem(addr lb[0], lspan.p, 4)
      let n = getLe32(lb, 0).int
      if n < 0 or n > h.chunkSize:
        raise newException(CryptoError, "crypto: invalid chunk length")
      if produced + n.uint64 > h.totalLen:
        raise newException(CryptoError, "crypto: length overflow")
      if remaining(inp) < n + encMacLen:
        raise newException(CryptoError, "crypto: truncated chunk")
      if n > 0:
        let cspan = readSpan(inp, n)
        copyMem(addr cipher[0], cspan.p, n)
      let mspan = readSpan(inp, encMacLen)
      var mac: array[16, byte]
      copyMem(addr mac[0], mspan.p, encMacLen)
      if not ncAead.readInto(st, plain.toOpenArray(0, n - 1),
          cipher.toOpenArray(0, n - 1), mac, ad):
        raise newException(CryptoError, "crypto: authentication failed")
      ad = @[]
      if n > 0:
        writeBytes(dst, addr plain[0], n)
      produced += n.uint64
      if h.totalLen == 0:
        break
    if produced != h.totalLen:
      raise newException(CryptoError, "crypto: truncated stream")
    if remaining(inp) != 0:
      raise newException(CryptoError, "crypto: trailing data")
  finally:
    ncUtils.wipe(st.key)

proc encryptBytes*(data: string; key: ncUtils.Key32;
    chunkSize = encChunkDefault): string =
  ## One-shot encrypt to a fresh string.
  let dst = newOutput()
  encryptInto(data.toOpenArrayByte(0, data.len - 1), key, dst, chunkSize)
  take(dst)

proc encryptBytes*(data: string; password: string;
    chunkSize = encChunkDefault): string =
  ## Password one-shot encrypt to a fresh string.
  let dst = newOutput()
  encryptInto(data.toOpenArrayByte(0, data.len - 1), password, dst,
    chunkSize)
  take(dst)

proc decryptBytes*(data: string; key: ncUtils.Key32): string =
  ## One-shot decrypt to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  decryptInto(inp, key, dst)
  take(dst)

proc decryptBytes*(data: string; password: string): string =
  ## Password one-shot decrypt to a fresh string.
  let inp = openInputString(data)
  let dst = newOutput()
  decryptInto(inp, password, dst)
  take(dst)

proc isEncryptedBytes*(data: openArray[byte]): bool =
  ## Magic sniff without consuming: true when `data` opens with the
  ## encrypted-blob header magic.
  if data.len < 8:
    return false
  for i in 0 ..< 8:
    if data[i] != byte(encMagic[i]):
      return false
  true

proc isEncryptedFile*(path: string): bool =
  ## Magic sniff of a file's first bytes. False (not an error) when the
  ## file cannot be opened; callers fall through to normal handling.
  var f: File
  if not open(f, path, fmRead):
    return false
  try:
    var magic: array[8, byte]
    if readBuffer(f, addr magic[0], 8) != 8:
      return false
    for i in 0 ..< 8:
      if magic[i] != byte(encMagic[i]):
        return false
    true
  finally:
    close(f)

proc encryptFile*(srcPath, dstPath: string; key: ncUtils.Key32;
    chunkSize = encChunkDefault) =
  ## Streaming file-to-file encrypt with fixed reused buffers: 64KB
  ## input staging + chunkSize cipher window, never full contents.
  ## Partial output deleted on failure.
  checkChunkSize(chunkSize)
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(CryptoError,
      "crypto: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(CryptoError,
      "crypto: cannot open for writing: " & dstPath)
  var ok = false
  try:
    let totalLen = getFileSize(srcPath).uint64
    let nonce = ncUtils.randomBytes[24]()
    let hdr = buildHeader(encKdfRaw, [], nonce, chunkSize, totalLen)
    var st: ncAead.AeadContext
    ncAead.initX(st, key, nonce)
    try:
      var plain = newSeq[byte](chunkSize)
      var cipher = newSeq[byte](chunkSize)
      if writeBuffer(wf, unsafeAddr hdr[0], hdr.len) != hdr.len:
        raise newException(CryptoError, "crypto: short write")
      var ad: seq[byte] = hdr
      var off: uint64 = 0
      while true:
        let n = min(chunkSize, (totalLen - off).int)
        if n > 0:
          if readBuffer(rf, addr plain[0], n) != n:
            raise newException(CryptoError, "crypto: short read")
        let mac = ncAead.writeInto(st, cipher.toOpenArray(0, n - 1),
          plain.toOpenArray(0, n - 1), ad)
        ad = @[]
        let tmp = newOutput(4)
        putLe32(tmp, n.uint32)
        let lb = outputBytes(tmp)
        if writeBuffer(wf, lb.p, lb.len) != lb.len:
          raise newException(CryptoError, "crypto: short write")
        if n > 0:
          if writeBuffer(wf, addr cipher[0], n) != n:
            raise newException(CryptoError, "crypto: short write")
        if writeBuffer(wf, unsafeAddr mac, encMacLen) != encMacLen:
          raise newException(CryptoError, "crypto: short write")
        off += n.uint64
        if off >= totalLen:
          break
    finally:
      ncUtils.wipe(st.key)
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard

proc encryptFile*(srcPath, dstPath: string; password: string;
    chunkSize = encChunkDefault) =
  ## Password streaming file-to-file encrypt (fresh random salt).
  checkChunkSize(chunkSize)
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(CryptoError,
      "crypto: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(CryptoError,
      "crypto: cannot open for writing: " & dstPath)
  var ok = false
  try:
    let totalLen = getFileSize(srcPath).uint64
    let salt = ncUtils.generateSalt()
    let sk = ncPass.deriveKeyFromPassword(password, salt)
    let nonce = ncUtils.randomBytes[24]()
    let hdr = buildHeader(encKdfArgon2, salt, nonce, chunkSize, totalLen)
    var st: ncAead.AeadContext
    ncAead.initX(st, sk.data, nonce)
    try:
      var plain = newSeq[byte](chunkSize)
      var cipher = newSeq[byte](chunkSize)
      if writeBuffer(wf, unsafeAddr hdr[0], hdr.len) != hdr.len:
        raise newException(CryptoError, "crypto: short write")
      var ad: seq[byte] = hdr
      var off: uint64 = 0
      while true:
        let n = min(chunkSize, (totalLen - off).int)
        if n > 0:
          if readBuffer(rf, addr plain[0], n) != n:
            raise newException(CryptoError, "crypto: short read")
        let mac = ncAead.writeInto(st, cipher.toOpenArray(0, n - 1),
          plain.toOpenArray(0, n - 1), ad)
        ad = @[]
        let tmp = newOutput(4)
        putLe32(tmp, n.uint32)
        let lb = outputBytes(tmp)
        if writeBuffer(wf, lb.p, lb.len) != lb.len:
          raise newException(CryptoError, "crypto: short write")
        if n > 0:
          if writeBuffer(wf, addr cipher[0], n) != n:
            raise newException(CryptoError, "crypto: short write")
        if writeBuffer(wf, unsafeAddr mac, encMacLen) != encMacLen:
          raise newException(CryptoError, "crypto: short write")
        off += n.uint64
        if off >= totalLen:
          break
    finally:
      ncUtils.wipe(st.key)
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard

proc decryptFile*(srcPath, dstPath: string; key: ncUtils.Key32) =
  ## Streaming file-to-file decrypt with fixed reused buffers. Verifies
  ## magic, version and every chunk MAC; truncation and trailing data
  ## raise CryptoError. Partial output deleted on failure.
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(CryptoError,
      "crypto: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(CryptoError,
      "crypto: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var hdr = newSeq[byte](encHeaderLen)
    if readBuffer(rf, addr hdr[0], encHeaderLen) != encHeaderLen:
      raise newException(CryptoError, "crypto: truncated header")
    let h = parseHeader(hdr)
    if h.kdf != encKdfRaw:
      raise newException(CryptoError,
        "crypto: password-encrypted blob needs a password")
    var st: ncAead.AeadContext
    ncAead.initX(st, key, h.nonce)
    try:
      var plain = newSeq[byte](h.chunkSize)
      var cipher = newSeq[byte](h.chunkSize)
      var ad: seq[byte] = hdr
      var produced: uint64 = 0
      while produced < h.totalLen or (produced == 0 and h.totalLen == 0 and
          ad.len > 0):
        var lb = [0'u8, 0, 0, 0]
        if readBuffer(rf, addr lb[0], 4) != 4:
          raise newException(CryptoError, "crypto: truncated chunk")
        let n = getLe32(lb, 0).int
        if n < 0 or n > h.chunkSize:
          raise newException(CryptoError, "crypto: invalid chunk length")
        if produced + n.uint64 > h.totalLen:
          raise newException(CryptoError, "crypto: length overflow")
        if n > 0:
          if readBuffer(rf, addr cipher[0], n) != n:
            raise newException(CryptoError, "crypto: truncated chunk")
        var mac: array[16, byte]
        if readBuffer(rf, addr mac[0], encMacLen) != encMacLen:
          raise newException(CryptoError, "crypto: truncated chunk")
        if not ncAead.readInto(st, plain.toOpenArray(0, n - 1),
            cipher.toOpenArray(0, n - 1), mac, ad):
          raise newException(CryptoError, "crypto: authentication failed")
        ad = @[]
        if n > 0:
          if writeBuffer(wf, addr plain[0], n) != n:
            raise newException(CryptoError, "crypto: short write")
        produced += n.uint64
        if h.totalLen == 0:
          break
      if produced != h.totalLen:
        raise newException(CryptoError, "crypto: truncated stream")
      var tail = [0'u8]
      if readBuffer(rf, addr tail[0], 1) != 0:
        raise newException(CryptoError, "crypto: trailing data")
    finally:
      ncUtils.wipe(st.key)
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard

proc decryptFile*(srcPath, dstPath: string; password: string) =
  ## Password streaming file-to-file decrypt.
  var rf: File
  if not open(rf, srcPath, fmRead):
    raise newException(CryptoError,
      "crypto: cannot open for reading: " & srcPath)
  var wf: File
  if not open(wf, dstPath, fmWrite):
    close(rf)
    raise newException(CryptoError,
      "crypto: cannot open for writing: " & dstPath)
  var ok = false
  try:
    var hdr = newSeq[byte](encHeaderLen)
    if readBuffer(rf, addr hdr[0], encHeaderLen) != encHeaderLen:
      raise newException(CryptoError, "crypto: truncated header")
    let h = parseHeader(hdr)
    if h.kdf != encKdfArgon2:
      raise newException(CryptoError,
        "crypto: raw-key blob needs a key, not a password")
    let sk = ncPass.deriveKeyFromPassword(password, h.salt)
    var st: ncAead.AeadContext
    ncAead.initX(st, sk.data, h.nonce)
    try:
      var plain = newSeq[byte](h.chunkSize)
      var cipher = newSeq[byte](h.chunkSize)
      var ad: seq[byte] = hdr
      var produced: uint64 = 0
      while produced < h.totalLen or (produced == 0 and h.totalLen == 0 and
          ad.len > 0):
        var lb = [0'u8, 0, 0, 0]
        if readBuffer(rf, addr lb[0], 4) != 4:
          raise newException(CryptoError, "crypto: truncated chunk")
        let n = getLe32(lb, 0).int
        if n < 0 or n > h.chunkSize:
          raise newException(CryptoError, "crypto: invalid chunk length")
        if produced + n.uint64 > h.totalLen:
          raise newException(CryptoError, "crypto: length overflow")
        if n > 0:
          if readBuffer(rf, addr cipher[0], n) != n:
            raise newException(CryptoError, "crypto: truncated chunk")
        var mac: array[16, byte]
        if readBuffer(rf, addr mac[0], encMacLen) != encMacLen:
          raise newException(CryptoError, "crypto: truncated chunk")
        if not ncAead.readInto(st, plain.toOpenArray(0, n - 1),
            cipher.toOpenArray(0, n - 1), mac, ad):
          raise newException(CryptoError, "crypto: authentication failed")
        ad = @[]
        if n > 0:
          if writeBuffer(wf, addr plain[0], n) != n:
            raise newException(CryptoError, "crypto: short write")
        produced += n.uint64
        if h.totalLen == 0:
          break
      if produced != h.totalLen:
        raise newException(CryptoError, "crypto: truncated stream")
      var tail = [0'u8]
      if readBuffer(rf, addr tail[0], 1) != 0:
        raise newException(CryptoError, "crypto: trailing data")
    finally:
      ncUtils.wipe(st.key)
    ok = true
  finally:
    close(rf)
    close(wf)
    if not ok:
      try: removeFile(dstPath)
      except CatchableError: discard
