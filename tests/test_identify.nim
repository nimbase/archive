import std/[unittest, options]
import archive/types
import archive/formats/brotli
import archive/io
import archive/registry
import archive/files


suite "identify":
  test "tar by name and by stream":
    let inp = openInputFile("tests/testdata/self-tar.tar")
    let res = identifyFormat("self-tar.tar", inp)
    check(res.format == fmtTar)
    check(res.compression.isNone)

  test "zip by name and by stream":
    let inp = openInputFile("tests/testdata/test.zip")
    let res = identifyFormat("test.zip", inp)
    check(res.format == fmtZip)
    check(res.compression.isNone)

  test "gzip magic wins over unknown name":
    var ctx: ArchiveContext
    let dst = newOutput()
    let src = openInputString("hello world")
    compressInto(fmtGz, src, dst)
    let payload = take(dst)
    require(payload.len > 2)
    let res = identifyFormat("noext", openInputString(payload))
    check(res.format == fmtGz)
    check(res.compression.isNone)

  test "compressed archive tar.gz detected as two layers":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc")], ".", "root")
    let inner = newOutput()
    archiveFormat(fmtTar, ctx, inner, files)
    let innerInp = toInput(inner)
    let outer = newOutput()
    compressInto(fmtGz, innerInp, outer)
    let res = identifyFormat("example.tar.gz", toInput(outer))
    check(res.format == fmtTar)
    check(res.compression == some(fmtGz))

  test "brotli by name":
    let res = identifyFormat("hello.br", nil)
    check(res.format == fmtBrotli)
    check(res.compression.isNone)

  test "tar stream not hijacked by brotli heuristic":
    # br-hijack.tar opens with byte 0x1B, so the brotli trial decode
    # claims it by stream; the cross-format guard must defer to the
    # definite tar magic instead of wrapping tar in a phantom layer.
    let inp = openInputFile("tests/testdata/br-hijack.tar")
    check(not matchBrotli("noext", inp).byStream)
    let res = identifyFormat("br-hijack.tar", inp)
    check(res.format == fmtTar)
    check(res.compression.isNone)

  test "no match raises":
    expect(NoMatchError):
      discard identifyFormat("file.unknownext", openInputString("xyz"))
