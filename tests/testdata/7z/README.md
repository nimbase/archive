# 7z reference fixtures

Generated with `7zz` 26.03 (macports). Password for `aes*.7z` is `password`
(same convention as the RAR fixtures). Sources in `sources/` are generated
by the same python snippet; `lorem.txt` is compressible prose, `random.bin`
is incompressible, `x86.bin` is E8-call synthetic x86, `docs/` is small
shared-phrase files for solid coverage.

| file | coder chain | notes |
|---|---|---|
| `store.7z` | Copy | `-mx0`, incl. incompressible input |
| `lzma-nosolid.7z` | LZMA, `-ms=off` | one folder per file |
| `lzma-solid.7z` | LZMA, solid | shared dictionary across files |
| `lzma2-solid.7z` | LZMA2, solid | the common real-world shape |
| `solid-1k.7z` | LZMA2, `-ms=1k` | 7 folders: multi-folder walk |
| `delta.7z` | Delta:4 + LZMA2 | filter chain |
| `bcj.7z` | BCJ + LZMA2 | x86 filter on synthetic code |
| `bcj2.7z` | LZMA + LZMA + BCJ2 | **refuses cleanly** (out of v1 scope) |
| `ppmd.7z` | PPMD | **refuses cleanly** (out of v1 scope) |
| `aes.7z` | LZMA2 + 7zAES (2^19) | file-content encryption, packed headers |
| `aes_plainhdr.7z` | LZMA2 + 7zAES (2^19) | same, plain headers (`-mhc=off`) |
| `aes_hdr.7z` | LZMA2 + 7zAES (2^19) | header encryption (`-mhe=on`) |
| `empty.7z` | dirs only | no data streams |
| `*_plain.7z` | same as base | plain-header twins (`-mhc=off`) for the container phase |

Oracle matrix (all verified 2026-11-13, decode verified 2026-11-14):
- Clear archives (plain headers): `bsdtar -tf/-xf` (BSD oracle) and `7z l/x`.
- Packed-header archives: `7z l/x` (bsdtar reads them too, except AES).
  Our reader extracts all of these byte-identical (STORE, LZMA, LZMA2
  solid/non-solid/multi-folder, Delta, BCJ).
- AES content/headers: `7z x -ppassword` only (`bsdtar` refuses both
  cleanly: "content encrypted, currently not supported" / "header is
  encrypted, currently not supported"). Our reader decrypts with
  `Sz(password: ...)` and extracts byte-identical.
- `bcj2`/`ppmd`: `bsdtar` reads them; we fail closed with an
  explicit unsupported-method error (out of v1 scope).
- Our writers: STORE (one Copy folder per file) and LZMA2-solid
  (`Sz(meth: 1)`: shared LZMA2 folders, 1MiB dict, fast greedy matches,
  ≤8MiB solid groups, plain headers) — both validated by `bsdtar -xf`
  and `7z x` byte-identical, incl. symlinks, dirs, empty files.

Wire notes that override the stale docs page:
- 7z NUMBER = `(value_bits << 8*extra) + extraLE` (spec formula confirmed).
- PackInfo has no terminator; unpack sizes are count-delimited.
- EmptyStream/EmptyFile/Anti are bare bitmaps (no AllAreDefined byte).
- Bit 15 (`0x8000`) flags Unix-mode high words (symlink restore).
- AES props are flags-based (`saltFlag<<7|ivFlag<<6|power`,
  nibble lens), NOT saltSize|ivSize<<4 — verified against 7z output.
