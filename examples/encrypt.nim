## Encrypted archives via pkg/nimcypher (XChaCha20-Poly1305 chunked AEAD).
## Envelope encryption around whole blobs: archive, optionally compress,
## then encrypt. Run from this directory:
##   `clue build examples/encrypt.nim --out:/tmp/encrypt && (cd examples && /tmp/encrypt)`

import std/[options, tables, strutils]
import nimcypher/utils as ncUtils
import archive
import archive/crypt
import archive/files

var ctx: ArchiveContext

# file layer: password in, fixed reused buffers, never full contents
writeFile("secret.txt", "top secret ".repeat(1000))
encryptFile("secret.txt", "secret.txt.enc", "correct horse")
decryptFile("secret.txt.enc", "secret_back.txt", "correct horse")
assert readFile("secret_back.txt") == readFile("secret.txt")
echo "file round trip ok"

# archive layer: tar.gz -> encrypt -> blob, then decrypt -> entries
let flist = filesFromEntries(ctx, FromFSOptions(),
  [FsEntry(path: "note.txt", meta: FileMeta(name: "note.txt", size: 4,
    isRegular: true), data: "note")], ".", "")
let blob = encryptArchive(afTar, flist, "correct horse", ctx,
  compression = some(cfGz))
writeFile("backup.tar.gz.enc", blob)
var names: seq[string] = @[]
decryptExtract("backup.tar.gz.enc", "correct horse", ctx,
  proc(c: ArchiveContext; info: FileInfo) =
    names.add(info.nameInArchive))
echo "archive entries: ", names

# raw keys work anywhere a password does
let key = ncUtils.randomBytes[32]()
let enc = encryptBytes("keyed message", key)
assert decryptBytes(enc, key) == "keyed message"
echo "raw key ok"
