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
| `bcj2.7z` | LZMA + LZMA + BCJ2 | **must refuse cleanly** (deferred) |
| `ppmd.7z` | PPMD | **must refuse cleanly** (deferred) |
| `aes.7z` | LZMA2 + 7zAES (2^19) | file-content encryption, packed headers |
| `aes_plainhdr.7z` | LZMA2 + 7zAES (2^19) | same, plain headers (`-mhc=off`) |
| `aes_hdr.7z` | LZMA2 + 7zAES (2^19) | header encryption (`-mhe=on`) |
| `empty.7z` | dirs only | no data streams |
| `*_plain.7z` | same as base | plain-header twins (`-mhc=off`) for the container phase |

Oracle matrix (all verified 2026-11-13):
- Clear archives (plain headers): `bsdtar -tf/-xf` (BSD oracle) and `7z l/x`.
- Packed-header archives: `7z l/x` (bsdtar reads them too, except AES).
- AES content/headers: `7z x -ppassword` only (`bsdtar` refuses both
  cleanly: "content encrypted, currently not supported" / "header is
  encrypted, currently not supported").
- `bcj2`/`ppmd`: `bsdtar` reads them; we fail closed with an
  explicit unsupported-method error (deferred to the LZMA phase).
- Our STORE writer output: validated by both `bsdtar -xf` and `7z x`
  (incl. symlinks, dirs, empty files).
