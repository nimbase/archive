# Encryption (src/archive/crypt.nim, src/archive.nim:137-232)

Envelope encryption around whole blobs: archive, optionally compress, then encrypt. No key is retained; `AeadContext.key` is wiped in `finally`. Password keys derive per call via Argon2id. Uses XChaCha20-Poly1305 chunked AEAD via `pkg/nimcypher`.

## Framing (src/archive/crypt.nim:20-102)

| constant | value |
| -------- | ----- |
| `encMagic` | `"NIMENC01"` |
| `encVersion` | `1` |
| `encKdfRaw / encKdfArgon2` | `0 / 1` |
| `encSaltLen / encNonceLen / encMacLen` | `16 / 24 / 16` |
| `encHeaderLen` | `62` (8 magic + 1 ver + 1 kdf + 16 salt + 24 nonce + 4 chunkSize LE + 8 totalLen LE) |
| `encChunkDefault / encChunkMax` | `64 KB / 4 MB` |

`buildHeader` writes the full header (used as AD for chunk 0). `parseHeader` rejects bad magic/version/kdf and oversized `chunkSize` before allocation. `checkChunkSize` validates the size.

`Key32` is `nimcypher/utils.Key32` (`array[32, byte]`). Every API has two overloads: raw-key (`encKdfRaw`, random 24-byte nonce per message, no salt) and `password: string` (`encKdfArgon2`, fresh salt plus `deriveKeyFromPassword` per message). KDF mismatch raises explicit `CryptoError`.

Chunking: each record is `u32LE len + cipher + 16-byte MAC`. There is always at least one chunk (empty input authenticates the header). Streaming uses fixed plain/cipher buffers with `totalLen` overflow and trailing-data checks.

## Byte and file layer (src/archive/crypt.nim:104-340)

| proc | behavior |
| ---- | -------- |
| `encryptInto(key/password, inp, dst, chunkSize)` | streaming encrypt |
| `decryptInto(key/password, inp, dst)` | streaming decrypt; raises `CryptoError` on bad magic, truncation, MAC failure |
| `encryptBytes(data, key/password)` / `decryptBytes` | one-shot string forms |
| `encryptFile(src, dst, key/password)` / `decryptFile` | file to file with 64 KB staging; `getFileSize` for `totalLen`; partial output removed on failure |
| `isEncryptedBytes(data)` / `isEncryptedFile(path)` | 8-byte magic check; file form returns false when unopenable |

`extractFile` and `vfs.fileSystem` refuse encrypted blobs with `use decryptExtract/decryptFile`.

## Archive layer (src/archive.nim:137-232)

```nim
encryptArchive(afTar, files, "correct horse", ctx, compression = some(cfGz))
decryptExtract("backup.tar.gz.enc", "correct horse", ctx, proc(c, info) = ...)
```

- `encryptArchive(archival, files, key/password, ctx, compression, level, chunkSize)` archives, optionally compresses, then encrypts to a blob.
- `decryptExtract(inp/path, key/password, ctx, handle)` decrypts to a temp `Output`, runs `identify`, rewinds, then `extractIdentified`. Path variants strip `.enc` for the identify hint only; content magic decides.

```nim
import archive/crypt
encryptFile("backup.tar.gz", "backup.tar.gz.enc", "correct horse")
decryptFile("backup.tar.gz.enc", "backup.tar.gz", "correct horse")
```

See `examples/encrypt.nim` for password file round trip, `encryptArchive` plus `decryptExtract`, and raw `Key32` `encryptBytes` / `decryptBytes`.
