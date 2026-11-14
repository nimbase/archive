import std/[unittest, tables, strutils, options, random]
import std/unicode
import buffalo
from std/os import joinPath, getTempDir, removeFile, removeDir, symlinkExists
import archive/types
import archive/io
import archive/files
import archive/crc32
import archive/formats/rar
import archive/formats/rarcodec
import archive/formats/rarenc
import archive/formats/rarcrypt
import nimcypher/utils as ncUtils
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

suite "rar5 encryption":
  test "pbkdf2 vectors":
    let v1 = rarPbkdf2Chain(ncUtils.toBytes("password"), ncUtils.toBytes("salt"), 1)
    check ncUtils.toHex(v1.key) == "120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B"
    let v2 = rarPbkdf2Chain(ncUtils.toBytes("password"), ncUtils.toBytes("salt"), 4096)
    check ncUtils.toHex(v2.key) == "C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A"

  test "per-file aes round trip":
    for m in [0, 1, 3, 5]:
      var ctx: ArchiveContext
      let files = filesFromEntries(ctx, FromFSOptions(), [
        FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5, isRegular: true), data: "hello"),
        FsEntry(path: "b.bin", meta: FileMeta(name: "b.bin", size: 3000, isRegular: true), data: "abc".repeat(1000)),
      ], ".", "")
      let dst = newOutput()
      archiveRar(Rar(meth: m, password: "hunter2", kdfLg2: 4), ctx, dst, files)
      let blob = take(dst)
      var backs: seq[string] = @[]
      extractRar(Rar(password: "hunter2"), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          backs.add(readAll(info.open()))
      check backs == @["hello", "abc".repeat(1000)]
      # wrong password fails
      var wrongFailed = false
      try:
        extractRar(Rar(password: "wrong"), ctx, openInputString(blob)) do (
            c: ArchiveContext; info: FileInfo):
          if info.isRegular():
            discard readAll(info.open())
      except ArchiveError:
        wrongFailed = true
      check wrongFailed
      # missing password fails
      var missingFailed = false
      try:
        extractRar(Rar(), ctx, openInputString(blob)) do (
            c: ArchiveContext; info: FileInfo):
          if info.isRegular():
            discard readAll(info.open())
      except ArchiveError:
        missingFailed = true
      check missingFailed

  test "header encryption round trip":
    for m in [0, 3]:
      var ctx: ArchiveContext
      let files = filesFromEntries(ctx, FromFSOptions(), [
        FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5, isRegular: true), data: "hello"),
      ], ".", "")
      let dst = newOutput()
      archiveRar(Rar(meth: m, password: "hunter2", kdfLg2: 4, encHeaders: true), ctx, dst, files)
      let blob = take(dst)
      var back = ""
      extractRar(Rar(password: "hunter2"), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          back = readAll(info.open())
      check back == "hello"
      var wrongFailed = false
      try:
        extractRar(Rar(password: "wrong"), ctx, openInputString(blob)) do (
            c: ArchiveContext; info: FileInfo):
          if info.isRegular():
            discard readAll(info.open())
      except ArchiveError:
        wrongFailed = true
      check wrongFailed

suite "rar5 multivolume":
  test "split round trip store and compressed":
    randomize(42)
    var data = newString(4096)
    for i in 0 ..< data.len:
      data[i] = chr(rand(255))
    for m in [0, 3]:
      var ctx: ArchiveContext
      let files = filesFromEntries(ctx, FromFSOptions(), [
        FsEntry(path: "r.bin", meta: FileMeta(name: "r.bin", size: data.len, isRegular: true), data: data),
      ], ".", "")
      let vols = archiveRarVolumes(Rar(meth: m), ctx, files, 2048)
      check vols.len >= 2
      for v in vols:
        check v.len <= 2048
      var inps: seq[Input] = @[]
      for v in vols:
        inps.add(openInputString(v))
      var back = ""
      extractRarVolumes(Rar(), ctx, inps, proc(c: ArchiveContext; info: FileInfo) =
        if info.isRegular():
          back = readAll(info.open())
      )
      check back == data

  test "multivolume with per-file encryption":
    randomize(99)
    var data = newString(5000)
    for i in 0 ..< data.len:
      data[i] = chr(rand(255))
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "s.bin", meta: FileMeta(name: "s.bin", size: data.len, isRegular: true), data: data),
    ], ".", "")
    let vols = archiveRarVolumes(Rar(meth: 0, password: "pw", kdfLg2: 4), ctx, files, 2048)
    check vols.len >= 2
    var inps: seq[Input] = @[]
    for v in vols:
      inps.add(openInputString(v))
    var back = ""
    extractRarVolumes(Rar(password: "pw"), ctx, inps, proc(c: ArchiveContext; info: FileInfo) =
      if info.isRegular():
        back = readAll(info.open())
    )
    check back == data

suite "rar5 filters on write":
  test "filtered encode round trips and wins on x86":
    # Repeated CALLs to one target: relative disps differ per site (LZ
    # misses), absolute targets match after the forward transform.
    var x86 = newString(20000)
    for i in 0 ..< x86.len:
      x86[i] = chr(0)
    const target = 0x1000'u32
    var at = 0
    while at + 5 <= x86.len:
      x86[at] = chr(0xE8)
      let disp = (target - uint32(at + 5)) and 0xFFFFFFFF'u32
      x86[at+1] = chr(int(disp and 0xFF))
      x86[at+2] = chr(int((disp shr 8) and 0xFF))
      x86[at+3] = chr(int((disp shr 16) and 0xFF))
      x86[at+4] = chr(int((disp shr 24) and 0xFF))
      at += 64
    var ctx: ArchiveContext
    let flist = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "x.bin", meta: FileMeta(name: "x.bin", size: x86.len, isRegular: true), data: x86),
    ], ".", "")
    let d0 = newOutput()
    archiveRar(Rar(meth: 3), ctx, d0, flist)
    let b0 = take(d0)
    let d1 = newOutput()
    archiveRar(Rar(meth: 3, useFilters: true), ctx, d1, flist)
    let b1 = take(d1)
    check b1.len < b0.len
    var back = ""
    extractRar(Rar(), ctx, openInputString(b1)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        back = readAll(info.open())
    check back == x86

  test "delta filtered encode round trips":
    var pcm = newString(4096)
    for i in 0 ..< pcm.len:
      pcm[i] = chr((i * 3 + 11) and 0xFF)
    let enc = fwdDelta(pcm, 2)
    let specs = [RarFilterSpec(start: 0, len: enc.len, kind: 0, channels: 2)]
    let packed = encodeRarMemberFiltered(enc.toOpenArrayByte(0, enc.len - 1), 3, rarEncDict, specs, 0)
    var st = UnpackState()
    resetUnpack(st, rarEncDict, 0)
    let dec = decodeMember(st, unsafeAddr packed[0], packed.len, uint64(pcm.len), 0)
    check dec == pcm

suite "rar5 unpack70":
  test "v1 forced round trips":
    for m in [1, 3, 5]:
      var ctx: ArchiveContext
      let files = filesFromEntries(ctx, FromFSOptions(), [
        FsEntry(path: "t.txt", meta: FileMeta(name: "t.txt", size: 3000, isRegular: true), data: "abc".repeat(1000)),
      ], ".", "")
      let dst = newOutput()
      archiveRar(Rar(meth: m, algoVer: 1), ctx, dst, files)
      let blob = take(dst)
      var back = ""
      extractRar(Rar(), ctx, openInputString(blob)) do (
          c: ArchiveContext; info: FileInfo):
        if info.isRegular():
          back = readAll(info.open())
      check back == "abc".repeat(1000)

  test "v1 compinfo carries version and fraction":
    let ci0 = rarCompInfo(3, 1 shl 20)
    check (ci0 and 0x3F) == 0
    let ci1 = rarCompInfo70(3, 1 shl 20)
    check (ci1 and 0x3F) == 1
    # Non-power-of-two needs fraction (v1).
    let ciF = rarCompInfo70(3, (1 shl 20) + (1 shl 15))
    check ((ciF shr 15) and 0x1F) != 0

proc putBitsMSBT(buf: var seq[byte]; acc: var uint64; nbits: var int;
    v: uint64; n: int) =
  ## Test-local MSB-first bit writer (mirrors rarenc BitWriter).
  doAssert n >= 0 and n <= 32
  let mask =
    if n == 0: 0'u64
    elif n == 32: 0xFFFFFFFF'u64
    else: (1'u64 shl n) - 1
  acc = (acc shl n) or (v and mask)
  nbits += n
  while nbits >= 8:
    nbits -= 8
    buf.add(byte((acc shr nbits) and 0xFF))

proc putBitsWideT(buf: var seq[byte]; acc: var uint64; nbits: var int;
    v: uint64; n: int) =
  ## Test-local 16-bit-chunked wide emit (mirrors putBitsWide).
  var left = n
  while left > 0:
    let take = min(left, 16)
    let sh = left - take
    putBitsMSBT(buf, acc, nbits, (v shr sh) and
      ((1'u64 shl take) - 1), take)
    left -= take

proc buildFarBlock(dslot: int; dextra: uint64; nbits: int): string =
  ## Synthetic Unpack70 block: literals A B, a 300-byte match at distance
  ## slot `dslot` (extra `dextra`/`nbits`), trailing literal C, all tables
  ## inline, last-block set. The distance is astronomic so the decoder
  ## must zero-fill; the trailing C proves the wide extra bits consumed
  ## exactly `nbits` (any bit shift corrupts it). New matches carry the
  ## length slot in the main symbol (262 + slot), so no len-table code is
  ## emitted for them (reps only use the len table).
  var mainLens = newSeq[int](rarMainSyms)
  mainLens[65] = 2
  mainLens[66] = 2
  mainLens[67] = 2
  mainLens[290] = 2 # 262 + length slot 28 (encoder length 297)
  var distLens = newSeq[int](rarDistSyms70)
  distLens[0] = 1
  distLens[dslot] = 1
  var alen = newSeq[int](rarAlignSyms)
  for i in 0 ..< rarAlignSyms:
    alen[i] = 4 # raw direct-bit path (alignMode off)
  var lenLens = newSeq[int](rarLenSyms)
  lenLens[0] = 1
  lenLens[1] = 1 # unused by new matches (reps only); kept Kraft-valid
  var lvlLens = newSeq[int](20)
  lvlLens[0] = 1
  lvlLens[1] = 3
  lvlLens[2] = 4
  lvlLens[4] = 4
  let mainC = assignCodes(mainLens)
  let distC = assignCodes(distLens)
  let lvlC = assignCodes(lvlLens)
  var pay: seq[byte] = @[]
  var acc = 0'u64
  var nb = 0
  for L in lvlLens:
    putBitsMSBT(pay, acc, nb, L.uint64, 4)
  template emitLen(L: int) =
    let ec = lvlC[L]
    putBitsMSBT(pay, acc, nb, ec.code.uint64, ec.len)
  for L in mainLens: emitLen(L)
  for L in distLens: emitLen(L)
  for L in alen: emitLen(L)
  for L in lenLens: emitLen(L)
  template tok(sym: int) =
    let tc = mainC[sym]
    putBitsMSBT(pay, acc, nb, tc.code.uint64, tc.len)
  tok(65)
  tok(66)
  tok(290)
  putBitsMSBT(pay, acc, nb, 39, 6) # 297 = ((4 or 0) shl 6 or 39) + 2
  let dc = distC[dslot]
  putBitsMSBT(pay, acc, nb, dc.code.uint64, dc.len)
  putBitsWideT(pay, acc, nb, dextra, nbits)
  tok(67)
  if nb > 0:
    pay.add(byte((acc shl (8 - nb)) and 0xFF))
  doAssert pay.len <= 255
  let flags = 0xC7'u8 # tables + last + 1 size byte + 8 final bits
  let sizeb = byte(pay.len)
  let chk = byte(0x5Au8 xor flags xor sizeb)
  result = newString(3 + pay.len)
  result[0] = chr(int(flags))
  result[1] = chr(int(chk))
  result[2] = chr(int(sizeb))
  for i, b in pay:
    result[3 + i] = chr(int(b))

suite "rar5 unpack70 far distances":
  test "far slots decode via zero fill with wide extra bits":
    # Slot -> extra-bit count: 64 -> 31, 70 -> 34, 79 -> 38. The last
    # two exceed 32 bits and exercise the 16-bit-chunked wide path.
    for (dslot, nbits) in [(64, 31), (70, 34), (79, 38)]:
      let blk = buildFarBlock(dslot, 0, nbits)
      var st = UnpackState()
      resetUnpack(st, rarEncDict, 1)
      let dec = decodeMember(st, unsafeAddr blk[0], blk.len, 303, 1)
      check dec == "AB" & '\0'.repeat(300) & "C"

  test "far slot nonzero extra bits stay aligned":
    # Extra pattern spans all three 16-bit chunks of the 38-bit field.
    let blk = buildFarBlock(79, 0x2AAAAAAAAA'u64, 38)
    var st = UnpackState()
    resetUnpack(st, rarEncDict, 1)
    let dec = decodeMember(st, unsafeAddr blk[0], blk.len, 303, 1)
    check dec == "AB" & '\0'.repeat(300) & "C"

suite "rar5 solid":
  test "solid single volume round trips and wins on shared data":
    var ctx: ArchiveContext
    let a = "lorem ipsum dolor sit amet ".repeat(120)
    let b = "lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(72)
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: a.len, isRegular: true), data: a),
      FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: b.len, isRegular: true), data: b),
    ], ".", "")
    let d0 = newOutput()
    archiveRar(Rar(meth: 3), ctx, d0, files)
    let d1 = newOutput()
    archiveRar(Rar(meth: 3, solid: true), ctx, d1, files)
    let b0 = take(d0)
    let b1 = take(d1)
    check b1.len < b0.len
    var backs: seq[string] = @[]
    extractRar(Rar(), ctx, openInputString(b1)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        backs.add(readAll(info.open()))
    check backs == @[a, b]

  test "solid groups split at dirs empties and store fallbacks":
    randomize(7)
    var noise = newString(3000)
    for i in 0 ..< noise.len:
      noise[i] = chr(rand(255))
    let a = "shared phrase one ".repeat(150)
    let b = "shared phrase two ".repeat(150)
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "d", meta: FileMeta(name: "d", isDir: true), data: ""),
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: a.len, isRegular: true), data: a),
      FsEntry(path: "empty.txt", meta: FileMeta(name: "empty.txt", size: 0, isRegular: true), data: ""),
      FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: b.len, isRegular: true), data: b),
      FsEntry(path: "n.bin", meta: FileMeta(name: "n.bin", size: noise.len, isRegular: true), data: noise),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 3, solid: true), ctx, dst, files)
    let blob = take(dst)
    var seen: seq[string] = @[]
    var bodies = initOrderedTable[string, string]()
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      seen.add(info.nameInArchive)
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    check bodies["a.txt"] == a
    check bodies["b.txt"] == b
    check bodies["n.bin"] == noise
    check bodies["empty.txt"] == ""
    check "d" in seen

  test "solid with per-file encryption round trips":
    let a = "solid secret one ".repeat(200)
    let b = "solid secret two ".repeat(200)
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: a.len, isRegular: true), data: a),
      FsEntry(path: "b.txt", meta: FileMeta(name: "b.txt", size: b.len, isRegular: true), data: b),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 3, solid: true, password: "pw", kdfLg2: 4), ctx, dst, files)
    let blob = take(dst)
    var backs: seq[string] = @[]
    extractRar(Rar(password: "pw"), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        backs.add(readAll(info.open()))
    check backs == @[a, b]

suite "rar5 solid multivolume":
  test "solid split round trip":
    randomize(11)
    var datas: seq[string] = @[]
    for f in 0 ..< 3:
      var d = newString(6000)
      for j in 0 ..< d.len:
        d[j] = chr(rand(255))
      datas.add(d)
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "h0.bin", meta: FileMeta(name: "h0.bin", size: datas[0].len, isRegular: true), data: datas[0]),
      FsEntry(path: "h1.bin", meta: FileMeta(name: "h1.bin", size: datas[1].len, isRegular: true), data: datas[1]),
      FsEntry(path: "h2.bin", meta: FileMeta(name: "h2.bin", size: datas[2].len, isRegular: true), data: datas[2]),
    ], ".", "")
    let vols = archiveRarVolumes(Rar(meth: 3, solid: true), ctx, files, 4096)
    check vols.len >= 2
    var inps: seq[Input] = @[]
    for v in vols:
      inps.add(openInputString(v))
    var backs: seq[string] = @[]
    extractRarVolumes(Rar(), ctx, inps, proc(c: ArchiveContext; info: FileInfo) =
      if info.isRegular():
        backs.add(readAll(info.open()))
    )
    check backs == datas

suite "rar5 header-encrypted multivolume":
  test "split round trip with header encryption":
    randomize(13)
    var datas: seq[string] = @[]
    for f in 0 ..< 3:
      var d = newString(6000)
      for j in 0 ..< d.len:
        d[j] = chr(rand(255))
      datas.add(d)
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "h0.bin", meta: FileMeta(name: "h0.bin", size: datas[0].len, isRegular: true), data: datas[0]),
      FsEntry(path: "h1.bin", meta: FileMeta(name: "h1.bin", size: datas[1].len, isRegular: true), data: datas[1]),
      FsEntry(path: "h2.bin", meta: FileMeta(name: "h2.bin", size: datas[2].len, isRegular: true), data: datas[2]),
    ], ".", "")
    let vols = archiveRarVolumes(Rar(meth: 0, password: "pw123", kdfLg2: 4,
      encHeaders: true), ctx, files, 4096)
    check vols.len >= 2
    var inps: seq[Input] = @[]
    for v in vols:
      inps.add(openInputString(v))
    var backs: seq[string] = @[]
    extractRarVolumes(Rar(password: "pw123"), ctx, inps, proc(c: ArchiveContext; info: FileInfo) =
      if info.isRegular():
        backs.add(readAll(info.open()))
    )
    check backs == datas

  test "wrong password fails on header-encrypted volumes":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "h.bin", meta: FileMeta(name: "h.bin", size: 3000, isRegular: true), data: "x".repeat(3000)),
    ], ".", "")
    let vols = archiveRarVolumes(Rar(meth: 0, password: "pw123", kdfLg2: 4,
      encHeaders: true), ctx, files, 2048)
    check vols.len >= 2
    var inps: seq[Input] = @[]
    for v in vols:
      inps.add(openInputString(v))
    var failed = false
    try:
      extractRarVolumes(Rar(password: "bad"), ctx, inps, proc(c: ArchiveContext; info: FileInfo) = discard)
    except RarError as e:
      failed = "incorrect password" in e.msg
    check failed

suite "rar5 archive comment":
  test "comment write and readback":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "f.txt", meta: FileMeta(name: "f.txt", size: 2, isRegular: true), data: "hi"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, comment: "hello comment"), ctx, dst, files)
    let blob = take(dst)
    check readRarComment(ctx, openInputString(blob)) == "hello comment"
    # Files still walk normally past the CMT service header.
    var back = ""
    extractRar(Rar(), ctx, openInputString(blob)) do (
        c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        back = readAll(info.open())
    check back == "hi"

  test "no comment reads empty":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "f.txt", meta: FileMeta(name: "f.txt", size: 2, isRegular: true), data: "hi"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1), ctx, dst, files)
    check readRarComment(ctx, openInputString(take(dst))) == ""

  test "header-encrypted comment readback":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "f.txt", meta: FileMeta(name: "f.txt", size: 2, isRegular: true), data: "hi"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, password: "pw", kdfLg2: 4, encHeaders: true,
      comment: "secret note"), ctx, dst, files)
    let blob = take(dst)
    check readRarComment(ctx, openInputString(blob), "pw") == "secret note"
    var failed = false
    try:
      discard readRarComment(ctx, openInputString(blob), "bad")
    except RarError:
      failed = true
    check failed

  test "oversize comment refused":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "f.txt", meta: FileMeta(name: "f.txt", size: 2, isRegular: true), data: "hi"),
    ], ".", "")
    let dst = newOutput()
    var failed = false
    try:
      archiveRar(Rar(meth: 0, comment: "z".repeat(300 * 1024)), ctx, dst, files)
    except RarError:
      failed = true
    check failed

suite "rar5 streaming to-dir":
  test "store to-dir via extractFile dispatch":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "sub", meta: FileMeta(name: "sub", isDir: true),
        data: ""),
      FsEntry(path: "sub/b.txt", meta: FileMeta(name: "b.txt", size: 5,
        isRegular: true), data: "world"),
      FsEntry(path: "empty.txt", meta: FileMeta(name: "empty.txt", size: 0,
        isRegular: true), data: ""),
      FsEntry(path: "link.txt", meta: FileMeta(name: "link.txt",
        isSymlink: true), data: "", linkTarget: "a.txt"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(), ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_store.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_store_out")
    removeDir(outd)
    try:
      extractFile(src, outd)
      check(readFile(joinPath(outd, "a.txt")) == "hello")
      check(readFile(joinPath(outd, "sub/b.txt")) == "world")
      check(readFile(joinPath(outd, "empty.txt")) == "")
      check(symlinkExists(joinPath(outd, "link.txt")))
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "compressed m1 to-dir via extractFile dispatch":
    var ctx: ArchiveContext
    var big = newString(512 * 1024)
    const phrase = "the quick brown fox jumps over the lazy dog. "
    for i in 0 ..< big.len:
      big[i] = phrase[i mod phrase.len]
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "small.txt", meta: FileMeta(name: "small.txt", size: 5,
        isRegular: true), data: "hello"),
      FsEntry(path: "big.txt", meta: FileMeta(name: "big.txt",
        size: big.len, isRegular: true), data: big),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1), ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_m1.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_m1_out")
    removeDir(outd)
    try:
      extractFile(src, outd)
      check(readFile(joinPath(outd, "small.txt")) == "hello")
      check(readFile(joinPath(outd, "big.txt")) == big)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "solid group streams in walk order without retention":
    var ctx: ArchiveContext
    var entries: seq[FsEntry] = @[]
    for i in 0 ..< 4:
      var data = newString(64 * 1024)
      for j in 0 ..< data.len:
        data[j] = chr(((i * 37 + j div 16) and 0xFF))
      entries.add(FsEntry(path: "f" & $i & ".bin",
        meta: FileMeta(name: "f" & $i & ".bin", size: data.len,
          isRegular: true), data: data))
    let files = filesFromEntries(ctx, FromFSOptions(), entries, ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, solid: true), ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_solid.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_solid_out")
    removeDir(outd)
    try:
      extractFile(src, outd)
      for i in 0 ..< 4:
        var want = newString(64 * 1024)
        for j in 0 ..< want.len:
          want[j] = chr(((i * 37 + j div 16) and 0xFF))
        check(readFile(joinPath(outd, "f" & $i & ".bin")) == want)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "filters round trip through file patching":
    var ctx: ArchiveContext
    # x86-like bytes trigger the E8/E9 forward filter on write.
    var exe = newString(64 * 1024)
    var rnd = initRand(1234)
    for i in 0 ..< exe.len:
      if i mod 7 == 0:
        exe[i] = chr(0xE8)
        if i + 4 < exe.len:
          for k in 1 .. 4:
            exe[i + k] = chr(rnd.rand(255))
      else:
        exe[i] = chr(rnd.rand(255))
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "prog.bin", meta: FileMeta(name: "prog.bin",
        size: exe.len, isRegular: true), data: exe),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, useFilters: true), ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_filt.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_filt_out")
    removeDir(outd)
    try:
      extractFile(src, outd)
      check(readFile(joinPath(outd, "prog.bin")) == exe)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "streaming decode applies explicit delta filter":
    # Deterministic filter-path unit test: the encoded stream carries a
    # DELTA marker, so decode must return it and the file patcher must
    # restore the original bytes (same bytes the in-memory path yields).
    var data = newString(8192)
    for i in 0 ..< data.len:
      data[i] = chr(((i * 7 + (i div 2)) and 0xFF))
    let (ds, av) = resolveWriterDict(Rar())
    let specs = @[RarFilterSpec(start: 0, len: data.len, kind: 0,
      channels: 2)]
    # The encoder takes forward-transformed bytes plus the specs (same
    # contract `archiveRar` uses via `transformWithFilters`).
    let transformed = fwdDelta(data, 2)
    let packed = encodeRarMemberFiltered(transformed.toOpenArrayByte(0,
      transformed.len - 1), 1, ds, specs, av)
    let mem = block:
      let s = UnpackState()
      resetUnpack(s, ds, av)
      decodeMember(s, unsafeAddr packed[0], packed.len, data.len.uint64,
        av)
    check(mem == data)
    let st = UnpackState()
    resetUnpack(st, ds, av)
    let tmp = joinPath(getTempDir(), "rar_stream_delta.bin")
    var wf = open(tmp, fmReadWrite)
    var stage = initPool(byte, rarFileStageCap, MaxScratchCap)
    stage.reserve(rarFileStageCap)
    let dec = decodeRarMemberToFile(st, unsafeAddr packed[0], packed.len,
      data.len.uint64, av, wf, stage)
    check(dec.filters.len == 1)
    let finalCrc = applyRarFiltersToFile(wf, dec.filters, stage)
    close(wf)
    check(readFile(tmp) == data)
    check(finalCrc == crc32Checksum(data))
    try: removeFile(tmp) except OSError: discard

  test "streaming matches handler on mixed solid+filter archive":
    var ctx: ArchiveContext
    var exe = newString(32 * 1024)
    for i in 0 ..< exe.len:
      exe[i] = if i mod 5 == 0: chr(0xE8) else: chr(i and 0xFF)
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "t.txt", meta: FileMeta(name: "t.txt", size: 30000,
        isRegular: true), data: "lorem ipsum ".repeat(2500)),
      FsEntry(path: "p.bin", meta: FileMeta(name: "p.bin", size: exe.len,
        isRegular: true), data: exe),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, solid: true, useFilters: true), ctx, dst, files)
    let blob = take(dst)
    var bodies = initOrderedTable[string, string]()
    extractRar(Rar(meth: 1, solid: true, useFilters: true), ctx,
      openInputString(blob)) do (c: ArchiveContext; info: FileInfo):
      if info.isRegular():
        bodies[info.nameInArchive] = readAll(info.open())
    let src = joinPath(getTempDir(), "rar_stream_equiv.rar")
    writeFile(src, blob)
    let outd = joinPath(getTempDir(), "rar_stream_equiv_out")
    removeDir(outd)
    try:
      extractFile(src, outd)
      for k, v in bodies:
        check(readFile(joinPath(outd, k)) == v)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "per-file encryption streams with password":
    var ctx: ArchiveContext
    var secret = newString(2 * 1024 * 1024)
    for i in 0 ..< secret.len:
      secret[i] = chr((i * 13 + 7) and 0xFF)
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "s.bin", meta: FileMeta(name: "s.bin", size: secret.len,
        isRegular: true), data: secret),
      FsEntry(path: "store.bin", meta: FileMeta(name: "store.bin",
        size: secret.len, isRegular: true), data: secret),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(password: "hunter2", kdfLg2: 4), ctx, dst, files)
    # STORE file: second entry forced to STORE via meth 0 archive below.
    let dst2 = newOutput()
    archiveRar(Rar(meth: 0, password: "hunter2", kdfLg2: 4), ctx, dst2, files)
    for (tag, blob) in [("m1", take(dst)), ("st", take(dst2))]:
      let src = joinPath(getTempDir(), "rar_stream_enc_" & tag & ".rar")
      writeFile(src, blob)
      let outd = joinPath(getTempDir(), "rar_stream_enc_" & tag & "_out")
      removeDir(outd)
      try:
        extractRarToDirStreaming(Rar(password: "hunter2"), src, outd, ctx)
        check(readFile(joinPath(outd, "s.bin")) == secret)
        check(readFile(joinPath(outd, "store.bin")) == secret)
      finally:
        try: removeFile(src) except OSError: discard
        try: removeDir(outd) except OSError: discard

  test "per-file encryption streams compressed entries with password":
    var ctx: ArchiveContext
    var text = newString(512 * 1024)
    const phrase = "the quick brown fox jumps over the lazy dog. "
    for i in 0 ..< text.len:
      text[i] = phrase[i mod phrase.len]
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "c.txt", meta: FileMeta(name: "c.txt", size: text.len,
        isRegular: true), data: text),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, password: "hunter2", kdfLg2: 4), ctx, dst, files)
    let blob = take(dst)
    check(blob.len < text.len) # actually compressed, not stored
    let src = joinPath(getTempDir(), "rar_stream_enc_c.rar")
    writeFile(src, blob)
    let outd = joinPath(getTempDir(), "rar_stream_enc_c_out")
    removeDir(outd)
    try:
      extractRarToDirStreaming(Rar(password: "hunter2"), src, outd, ctx)
      check(readFile(joinPath(outd, "c.txt")) == text)
      # Wrong password fails the same way as the one-shot opener.
      removeDir(outd)
      expect(RarError):
        extractRarToDirStreaming(Rar(password: "wrong"), src, outd, ctx)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "wrong password fails streaming":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 5,
        isRegular: true), data: "hello"),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, password: "hunter2", kdfLg2: 4), ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_wrong.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_wrong_out")
    removeDir(outd)
    try:
      expect(RarError):
        extractRarToDirStreaming(Rar(password: "wrong"), src, outd, ctx)
      expect(RarError):
        extractRarToDirStreaming(Rar(), src, outd, ctx)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "header-encrypted archive streams in place":
    var ctx: ArchiveContext
    var big = newString(256 * 1024)
    for i in 0 ..< big.len:
      big[i] = chr((i div 3) and 0xFF)
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "h.txt", meta: FileMeta(name: "h.txt", size: big.len,
        isRegular: true), data: big),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1, password: "pw", kdfLg2: 4, encHeaders: true),
      ctx, dst, files)
    let src = joinPath(getTempDir(), "rar_stream_hdr.rar")
    writeFile(src, take(dst))
    let outd = joinPath(getTempDir(), "rar_stream_hdr_out")
    removeDir(outd)
    try:
      extractRarToDirStreaming(Rar(password: "pw"), src, outd, ctx)
      check(readFile(joinPath(outd, "h.txt")) == big)
      expect(RarError):
        extractFile(src, outd) # dispatch has no password
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard

  test "corrupt and truncated archives fail streaming":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(), [
      FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 20000,
        isRegular: true), data: "x".repeat(20000)),
    ], ".", "")
    let dst = newOutput()
    archiveRar(Rar(meth: 1), ctx, dst, files)
    let blob = take(dst)
    let src = joinPath(getTempDir(), "rar_stream_bad.rar")
    let outd = joinPath(getTempDir(), "rar_stream_bad_out")
    try:
      var bad = blob
      bad[bad.len - 10] = chr(ord(bad[bad.len - 10]) xor 0xFF)
      writeFile(src, bad)
      removeDir(outd)
      expect(ArchiveError):
        extractFile(src, outd)
      writeFile(src, blob[0 ..< blob.len - 10])
      removeDir(outd)
      expect(ArchiveError):
        extractFile(src, outd)
    finally:
      try: removeFile(src) except OSError: discard
      try: removeDir(outd) except OSError: discard
