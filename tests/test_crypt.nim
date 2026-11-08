import std/[unittest, strutils, tables, syncio, options]
from std/os import joinPath, getTempDir, removeFile, fileExists
import nimcypher/utils as ncUtils
import archive
import archive/types
import archive/io
import archive/crypt
import archive/files
import archive/vfs

suite "crypt smoke":
  test "raw key round trip":
    let key = ncUtils.randomBytes[32]()
    let data = "hello encrypted world! ".repeat(1000)
    let enc = encryptBytes(data, key)
    check enc.len > data.len
    check decryptBytes(enc, key) == data

  test "empty and tiny":
    let key = ncUtils.randomBytes[32]()
    check decryptBytes(encryptBytes("", key), key) == ""
    check decryptBytes(encryptBytes("x", key), key) == "x"

  test "password round trip":
    let enc = encryptBytes("secret message", "correct horse")
    check decryptBytes(enc, "correct horse") == "secret message"

  test "wrong key fails":
    let key = ncUtils.randomBytes[32]()
    let bad = ncUtils.randomBytes[32]()
    let enc = encryptBytes("data", key)
    expect(CryptoError):
      discard decryptBytes(enc, bad)

  test "tamper fails":
    let key = ncUtils.randomBytes[32]()
    var enc = encryptBytes("tamper me ".repeat(100), key)
    enc[100] = chr(ord(enc[100]) xor 1)
    expect(CryptoError):
      discard decryptBytes(enc, key)

suite "crypt framing":
  test "chunk boundaries round trip":
    let key = ncUtils.randomBytes[32]()
    for ln in [65535, 65536, 65537, 200000]:
      var data = newString(ln)
      for i in 0 ..< ln: data[i] = chr((i * 31 + 7) and 0xFF)
      check decryptBytes(encryptBytes(data, key), key) == data
    # tiny chunks force many rekeyed records incl. a short tail
    check decryptBytes(encryptBytes("hello world, hello chunks", key, 16),
      key) == "hello world, hello chunks"

  test "header rejects garbage":
    let key = ncUtils.randomBytes[32]()
    expect(CryptoError):
      discard decryptBytes("short", key)
    var bad = encryptBytes("data", key)
    bad[0] = 'X'
    expect(CryptoError):
      discard decryptBytes(bad, key)
    var badVer = encryptBytes("data", key)
    badVer[8] = chr(99)
    expect(CryptoError):
      discard decryptBytes(badVer, key)
    var badKdf = encryptBytes("data", key)
    badKdf[9] = chr(7)
    expect(CryptoError):
      discard decryptBytes(badKdf, key)
    var badChunk = encryptBytes("data", key)
    for i in 0 ..< 4: badChunk[50 + i] = chr(0xFF)
    expect(CryptoError):
      discard decryptBytes(badChunk, key)

  test "truncation and trailing data fail":
    let key = ncUtils.randomBytes[32]()
    let enc = encryptBytes("cut me off ".repeat(5000), key)
    expect(CryptoError):
      discard decryptBytes(enc[0 ..< enc.len - 1], key)
    expect(CryptoError):
      discard decryptBytes(enc[0 ..< enc.len div 2], key)
    expect(CryptoError):
      discard decryptBytes(enc & "!", key)

  test "kdf mismatch is explicit":
    let key = ncUtils.randomBytes[32]()
    let raw = encryptBytes("data", key)
    expect(CryptoError):
      discard decryptBytes(raw, "password")
    let pw = encryptBytes("data", "password")
    expect(CryptoError):
      discard decryptBytes(pw, key)

  test "wrong password fails":
    let enc = encryptBytes("secret", "right horse")
    expect(CryptoError):
      discard decryptBytes(enc, "wrong horse")

suite "crypt files":
  test "file round trip raw and password":
    let key = ncUtils.randomBytes[32]()
    let src = joinPath(getTempDir(), "crypt_plain.bin")
    var payload = newString(300000)
    for i in 0 ..< payload.len: payload[i] = chr((i * 17 + 3) and 0xFF)
    writeFile(src, payload)
    let enc1 = joinPath(getTempDir(), "crypt_raw.enc")
    let dec1 = joinPath(getTempDir(), "crypt_raw.bin")
    encryptFile(src, enc1, key)
    decryptFile(enc1, dec1, key)
    check readFile(dec1) == payload
    let enc2 = joinPath(getTempDir(), "crypt_pw.enc")
    let dec2 = joinPath(getTempDir(), "crypt_pw.bin")
    encryptFile(src, enc2, "file password")
    decryptFile(enc2, dec2, "file password")
    check readFile(dec2) == payload
    for f in [src, enc1, dec1, enc2, dec2]: removeFile(f)

  test "empty file round trip":
    let key = ncUtils.randomBytes[32]()
    let src = joinPath(getTempDir(), "crypt_empty.bin")
    writeFile(src, "")
    let enc = joinPath(getTempDir(), "crypt_empty.enc")
    let dec = joinPath(getTempDir(), "crypt_empty_out.bin")
    encryptFile(src, enc, key)
    decryptFile(enc, dec, key)
    check readFile(dec) == ""
    for f in [src, enc, dec]: removeFile(f)

  test "failed decrypt deletes partial output":
    let key = ncUtils.randomBytes[32]()
    let bad = ncUtils.randomBytes[32]()
    let src = joinPath(getTempDir(), "crypt_part.bin")
    writeFile(src, "partial ".repeat(10000))
    let enc = joinPath(getTempDir(), "crypt_part.enc")
    let dec = joinPath(getTempDir(), "crypt_part_out.bin")
    encryptFile(src, enc, key)
    expect(CryptoError):
      decryptFile(enc, dec, bad)
    check not fileExists(dec)
    for f in [src, enc]: removeFile(f)

  test "sniffers detect the magic":
    let key = ncUtils.randomBytes[32]()
    let enc = encryptBytes("data", key)
    check isEncryptedBytes(enc.toOpenArrayByte(0, enc.len - 1))
    check not isEncryptedBytes("hello".toOpenArrayByte(0, 4))
    check not isEncryptedBytes(newSeq[byte](0))
    let path = joinPath(getTempDir(), "crypt_sniff.enc")
    writeFile(path, enc)
    check isEncryptedFile(path)
    check not isEncryptedFile(joinPath(getTempDir(), "crypt_nope.bin"))
    removeFile(path)

suite "crypt composition":
  test "encryptArchive tar round trip":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "note.txt", meta: FileMeta(name: "note.txt", size: 4,
        isRegular: true), data: "note")], ".", "")
    let key = ncUtils.randomBytes[32]()
    let blob = encryptArchive(afTar, files, key, ctx)
    check isEncryptedBytes(blob.toOpenArrayByte(0, blob.len - 1))
    var names: seq[string] = @[]
    var ctx2: ArchiveContext
    decryptExtract(openInputString(blob), key, ctx2,
      proc(c: ArchiveContext; info: FileInfo) =
        names.add(info.nameInArchive))
    check names == @["note.txt"]

  test "encryptArchive tar.gz round trip with password":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "alpha"),
       FsEntry(path: "sub/b.txt", meta: FileMeta(name: "sub/b.txt", size: 4,
        isRegular: true), data: "beta")], ".", "")
    let blob = encryptArchive(afTar, files, "archive password", ctx,
      compression = some(cfGz))
    let path = joinPath(getTempDir(), "crypt_comp.tar.gz.enc")
    writeFile(path, blob)
    var got = initTable[string, string]()
    var ctx2: ArchiveContext
    decryptExtract(path, "archive password", ctx2,
      proc(c: ArchiveContext; info: FileInfo) =
        if info.isRegular():
          got[info.nameInArchive] = readAll(info.open()))
    check got["a.txt"] == "alpha"
    check got["sub/b.txt"] == "beta"
    removeFile(path)

  test "extractFile refuses encrypted blobs":
    var ctx: ArchiveContext
    let blob = encryptBytes("x".repeat(100), ncUtils.randomBytes[32]())
    let path = joinPath(getTempDir(), "crypt_refuse.enc")
    writeFile(path, blob)
    try:
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) = discard, ctx)
      check false
    except ArchiveError as e:
      check "decryptExtract" in e.msg
    try:
      discard fileSystem(ctx, path, nil)
      check false
    except ArchiveError as e:
      check "decryptExtract" in e.msg
    removeFile(path)
