import std/[unittest, options]
import archive/types
import archive/formats/brotli
import archive/formats/tar
import archive/io
import archive/registry
import archive/files


suite "identify":
  test "tar by name and by stream":
    let inp = openInputFile("tests/testdata/self-tar.tar")
    let res = identifyFormat("self-tar.tar", inp)
    check(res.archival == some(afTar))
    check(res.compression.isNone)

  test "zip by name and by stream":
    let inp = openInputFile("tests/testdata/test.zip")
    let res = identifyFormat("test.zip", inp)
    check(res.archival == some(afZip))
    check(res.compression.isNone)

  test "gzip magic wins over unknown name":
    var ctx: ArchiveContext
    let dst = newOutput()
    let src = openInputString("hello world")
    compressInto(cfGz, src, dst)
    let payload = take(dst)
    require(payload.len > 2)
    let res = identifyFormat("noext", openInputString(payload))
    check(res.archival.isNone) # lone stream: no archive layer
    check(res.compression == some(cfGz))

  test "compressed archive tar.gz detected as two layers":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc")], ".", "root")
    let inner = newOutput()
    archiveFormat(afTar, ctx, inner, files)
    let innerInp = toInput(inner)
    let outer = newOutput()
    compressInto(cfGz, innerInp, outer)
    let res = identifyFormat("example.tar.gz", toInput(outer))
    check(res.archival == some(afTar))
    check(res.compression == some(cfGz))

  test "brotli by name":
    let res = identifyFormat("hello.br", nil)
    check(res.archival.isNone)
    check(res.compression == some(cfBrotli))

  test "tar stream not hijacked by brotli heuristic":    # br-hijack.tar opens with byte 0x1B, so the brotli trial decode
    # claims it by stream; the cross-format guard must defer to the
    # definite tar magic instead of wrapping tar in a phantom layer.
    let inp = openInputFile("tests/testdata/br-hijack.tar")
    check(not matchBrotli("noext", inp).byStream)
    let res = identifyFormat("br-hijack.tar", inp)
    check(res.archival == some(afTar))
    check(res.compression.isNone)

  test "non-tar bytes never crash the tar matcher":
    # zip local headers fed to parseHeader used to raise OverflowDefect
    # (base-256 branch on garbage), aborting identify instead of
    # returning non-match. Matchers must be total on untrusted bytes.
    let inp = openInputFile("tests/testdata/datadesc.zip")
    check(not matchTar("noext", inp).byStream)
    let res = identifyFormat("noext", inp)
    check(res.archival == some(afZip))
    check(res.compression.isNone)

  test "no match raises":
    expect(NoMatchError):
      discard identifyFormat("file.unknownext", openInputString("xyz"))
