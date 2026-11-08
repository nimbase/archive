import std/[unittest, tables, strutils, options]
from std/os import joinPath, getTempDir, removeFile
import archive/types
import archive/io
import archive/files
import archive/crc32
import archive/formats/rar
import archive/formats/rarcodec
import archive/formats/rarenc
import archive/vfs
import archive

suite "rar5 store":
  test "round trip regular files and dirs":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "dir", meta: FileMeta(name: "dir", isDir: true),
        data: ""),
      FsEntry(path: "dir/a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "top.txt", meta: FileMeta(name: "top.txt", size: 5,
        isRegular: true), data: "world"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    let blob = take(dst)
    check blob.len > 8
    check blob[0 .. 7] == rar5Magic
    var seen: seq[string] = @[]
    var bodies = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      seen.add(info.nameInArchive)
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check("dir" in seen)
    check("dir/a.txt" in seen)
    check("top.txt" in seen)
    check(bodies["dir/a.txt"] == "hello")
    check(bodies["top.txt"] == "world")

  test "symlink round trip":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "real.txt", meta: FileMeta(name: "real.txt", size: 4,
        isRegular: true), data: "data"),
      FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
        isSymlink: true), data: "", linkTarget: "real.txt"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var links = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isSymlink():
        links[info.nameInArchive] = info.linkTarget
    check(links["link.txt"] == "real.txt")

  test "empty files and empty archive":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "empty.txt", meta: FileMeta(name: "empty.txt", size: 0,
        isRegular: true), data: ""),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var got = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, toInput(dst)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        got[info.nameInArchive] = readAll(info.open())
    check(got["empty.txt"] == "")
    # empty archive lists nothing
    let dst2 = newOutput()
    archiveRar(Rar(), ctx, dst2, @[])
    var n = 0
    extractRar(Rar(), ctx, toInput(dst2)) do (
        c: ArchiveContext; info: FileInfo):
      inc n
    check n == 0

  test "high-level archiveData/extractFile":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "alpha"),
    ], ".", "")
    let blob = archiveData(afRar, files, ctx)
    let path = joinPath(getTempDir(), "nim_arc_rar_hl.rar")
    writeFile(path, blob)
    try:
      var names: seq[string] = @[]
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
        names.add(info.nameInArchive), ctx)
      check names == @["a.txt"]
      check listEntries(path) == @["a.txt"]
      for p, e in walkFs(path):
        check p == "a.txt"
    finally:
      removeFile(path)

  test "bad signature and truncation fail":
    var ctx: ArchiveContext
    expect(ArchiveError):
      extractRar(Rar(), ctx, openInputString("not a rar")) do (
          c: ArchiveContext; info: FileInfo):
        discard
    var ctx2: ArchiveContext
    let files = filesFromEntries(ctx2, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx2, dst, files)
    let blob = take(dst)
    expect(ArchiveError):
      extractRar(Rar(), ctx2,
        openInputString(blob[0 ..< blob.len div 2])) do (
          c: ArchiveContext; info: FileInfo):
        discard

  test "header crc mismatch fails":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var blob = take(dst)
    # corrupt a byte inside the first file header (past MARK+MAIN)
    blob[20] = chr(ord(blob[20]) xor 0xFF)
    expect(ArchiveError):
      extractRar(Rar(), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        discard

  test "unknown method lists but fails on open":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    var blob = take(dst)
    # Patch CompInfo method 0 -> 7 (out of range). Value 7 << 7 = 896
    # needs a 2-byte vint (0x80 0x07), so splice it in and grow the
    # header size by one.
    let at = blob.find("a.txt")
    check at > 6
    let compPos = at - 3
    check ord(blob[compPos]) == 0
    blob = blob[0 ..< compPos] & "\x80\x07" & blob[compPos + 1 .. ^1]
    check ord(blob[20]) < 127 # hsize stays 1 byte
    blob[20] = chr(ord(blob[20]) + 1)
    # Recompute the file header CRC (header at offset 16: CRC + hsize + body).
    let fhCrcAt = 16
    var hsVal = 0'u64
    var hsLen = 0
    var shift = 0
    while true:
      let b = ord(blob[20 + hsLen]).uint64
      hsVal += (b and 0x7F) shl shift
      inc hsLen
      shift += 7
      if (b and 0x80) == 0: break
    let crcStart = 20
    let crcEnd = crcStart + hsLen + int(hsVal)
    var crc = crc32Update(0xFFFFFFFF'u32,
      unsafeAddr blob[crcStart], crcEnd - crcStart) xor 0xFFFFFFFF'u32
    blob[fhCrcAt] = chr(int(crc and 0xFF))
    blob[fhCrcAt + 1] = chr(int((crc shr 8) and 0xFF))
    blob[fhCrcAt + 2] = chr(int((crc shr 16) and 0xFF))
    blob[fhCrcAt + 3] = chr(int((crc shr 24) and 0xFF))
    # Walk lists the entry (meta available without decoding) ...
    var names: seq[string] = @[]
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      names.add(info.nameInArchive)
    check names == @["a.txt"]
    # ... but opening content fails with a clear method error.
    var opened = false
    try:
      extractRar(Rar(), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())
    except ArchiveError as e:
      opened = true
      check "unknown compression method" in e.msg
    check opened

  test "unpacked cap enforced on open":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt", size: 100,
        isRegular: true), data: "x".repeat(100)),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    let blob = take(dst)
    var ctxCap = ArchiveContext(maxRarUnpackedBytes: 10)
    expect(ArchiveError):
      extractRar(Rar(), ctxCap, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          discard readAll(info.open())

suite "rar5 filters":
  # Forward transforms transliterated independently from the forward
  # pseudocode (different text than the reverse the codec implements);
  # round-trip validates the pairing, including wrap edges. Real
  # WinRAR DELTA fixtures are covered by the archive-level comparison.

  # le32 helpers (rarcodec keeps its own private copies).
  proc le32At(s: string; at: int): uint32 =
    ord(s[at]).uint32 or (ord(s[at + 1]).uint32 shl 8) or
      (ord(s[at + 2]).uint32 shl 16) or (ord(s[at + 3]).uint32 shl 24)

  proc putLe32At(s: var string; at: int; v: uint32) =
    s[at] = chr(int(v and 0xFF))
    s[at + 1] = chr(int((v shr 8) and 0xFF))
    s[at + 2] = chr(int((v shr 16) and 0xFF))
    s[at + 3] = chr(int((v shr 24) and 0xFF))

  proc fwdE8(buf: string; fileOff: uint64; e9: bool): string =
    const FS = 0x1000000'u32
    result = buf
    var pos = 0
    while pos + 5 <= result.len:
      let b = ord(result[pos])
      if (if e9: (b and 0xFE) == 0xE8 else: b == 0xE8):
        let disp = le32At(result, pos + 1)
        let off = uint32((fileOff + uint64(pos) + 1) and (FS - 1))
        let a = disp + off
        if a < FS:
          putLe32At(result, pos + 1, a)
        else:
          let bb = disp - FS
          if bb > 0xFFFFFFFF'u32 - off:
            putLe32At(result, pos + 1, bb)
        pos += 5
      else:
        inc pos

  proc fwdArm(buf: string; fileOff: uint64): string =
    result = buf
    var pos = 0
    while pos + 4 <= result.len:
      if ord(result[pos + 3]) == 0xEB:
        let insn = le32At(result, pos)
        let off = (pos.uint64 + fileOff) shr 2
        let low24 = (insn and 0x00FFFFFF'u32) + uint32(off and 0xFFFFFF'u64)
        putLe32At(result, pos, (low24 and 0x00FFFFFF'u32) or 0xEB000000'u32)
      pos += 4

  proc fwdDelta(buf: string; channels: int): string =
    result = newString(buf.len)
    var sp = 0
    for c in 0 ..< channels:
      var prev = 0
      var i = c
      while i < buf.len:
        result[sp] = chr((prev - ord(buf[i])) and 0xFF)
        prev = ord(buf[i])
        inc sp
        i += channels

  # le32At/putLe32At are defined above for the forward transforms.

  test "e8/e8e9 forward-reverse round trip":
    var raw = newString(4096)
    for i in 0 ..< 4096:
      raw[i] = chr((i * 37 + 11) and 0xFF)
    # sprinkle CALL/JMP sites incl. wrap-edge displacements
    for at in [0, 1, 7, 100, 1000, 4090]:
      raw[at] = chr(0xE8)
      putLe32At(raw, at + 1, [0'u32, 1, 0xFFFFFF, 0x1000000, 0xFFFFFF00'u32,
        0xFFFFFFFF'u32][at mod 6])
    raw[2000] = chr(0xE9)
    putLe32At(raw, 2001, 0x123456)
    for e9 in [false, true]:
      for off in [0'u64, 7, 0xFFFFFF, 0x1000005]:
        let enc = fwdE8(raw, off, e9)
        var dec = enc
        applyE8(dec, 0, dec.len, off, e9)
        check dec == raw

  test "arm forward-reverse round trip":
    var raw = newString(1024)
    for i in 0 ..< 1024:
      raw[i] = chr((i * 13 + 5) and 0xFF)
    for at in countup(0, 1020, 4):
      raw[at + 3] = chr(0xEB)
      putLe32At(raw, at, (uint32(at * 7919) and 0x00FFFFFF'u32) or
        0xEB000000'u32)
    raw[5] = chr(0xEB) # misaligned EB untouched by both directions
    for off in [0'u64, 4, 0x100, 0x1_0000_0005'u64]:
      let enc = fwdArm(raw, off)
      var dec = enc
      applyArm(dec, 0, dec.len, off)
      check dec == raw
    # region-relative stride: an absolutely-unaligned region still
    # steps +4 from its own start (encoder must emit it that way).
    let sub = raw[1 .. ^1]
    let subEnc = fwdArm(sub, 1)
    var subDec = subEnc
    applyArm(subDec, 0, subDec.len, 1)
    check subDec == sub

  test "delta forward-reverse round trip":
    for ch in [1, 2, 3, 4, 6, 32]:
      var raw = newString(4 * ch * 64 + ch - 1)
      for i in 0 ..< raw.len:
        raw[i] = chr((i * 17 + ch) and 0xFF)
      let enc = fwdDelta(raw, ch)
      var dec = enc
      applyDelta(dec, 0, dec.len, ch)
      check dec == raw
    # empty and single byte
    var e0 = ""
    applyDelta(e0, 0, 0, 4)
    check e0 == ""

suite "rar5 encode":
  # Round-trip the clean-room encoder through the decoder at every
  # method. Interop with third-party readers (bsdtar/libarchive) is
  # verified manually; these hermetic vectors pin the behavior here.

  proc encRoundTrip(data: string; meth: int): string =
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "f.bin", meta: FileMeta(name: "f.bin", size: data.len,
        isRegular: true), data: data),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: meth), ctx, dst, files)
    let blob = take(dst)
    var back = ""
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        back = readAll(info.open())
    check back == data
    blob

  test "methods 1..5 round trip":
    for m in 1 .. 5:
      discard encRoundTrip("", m) # empty always stores, never encodes
      discard encRoundTrip("x", m)
      discard encRoundTrip("hello, world! ".repeat(3), m)
      discard encRoundTrip("abc".repeat(1000), m)
      discard encRoundTrip(newString(70000), m)

  test "random and text payloads round trip":
    var rnd = newString(4096)
    var s = 0x12345
    for i in 0 ..< rnd.len:
      s = (s * 1103515245 + 12345) and 0x7FFFFFFF
      rnd[i] = chr(s mod 256)
    for m in [1, 3, 5]:
      discard encRoundTrip(rnd, m)
      var txt = newString(70000)
      for i in 0 ..< txt.len:
        txt[i] = chr((i * 31 + 7) mod 6)
      discard encRoundTrip(txt, m)
      discard encRoundTrip("lorem ipsum dolor sit amet ".repeat(8000), m)

  test "multi-block streams round trip":
    # 1 MiB of zeros spans 16 blocks; solid groups stay non-solid here.
    for m in [1, 5]:
      let blob = encRoundTrip(newString(1 shl 20), m)
      check blob.len < 2000

  test "incompressible input falls back to store":
    var rnd = newString(4096)
    var s = 99
    for i in 0 ..< rnd.len:
      s = (s * 1103515245 + 12345) and 0x7FFFFFFF
      rnd[i] = chr(s mod 256)
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "r.bin", meta: FileMeta(name: "r.bin", size: rnd.len,
        isRegular: true), data: rnd),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 3), ctx, dst, files)
    let blob = take(dst)
    # random data cannot compress: STORE fallback keeps the blob at
    # input size plus header overhead (no table bloat).
    check blob.len < rnd.len + 200
    var back = ""
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        back = readAll(info.open())
    check back == rnd

  test "bad method rejected":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.bin", meta: FileMeta(name: "a.bin", size: 1,
        isRegular: true), data: "x"),
    ], ".", "")
    expect(ArchiveError):
      archiveRar(Rar(meth: 7), ctx, newOutput(), files)

  test "huffman builder stays valid":
    # Kraft-checked on adversarial frequency shapes incl. singletons.
    for n in [1, 2, 3, 20, 64, 306]:
      var freqs = newSeq[int](n)
      for i in 0 ..< n:
        freqs[i] = (i * 37 + 11) mod 5
      let lens = huffmanLengths(freqs)
      var sum = 0
      for L in lens:
        check L >= 0 and L <= 15
        if L != 0:
          sum += 1 shl (15 - L)
      check sum <= 1 shl 15
