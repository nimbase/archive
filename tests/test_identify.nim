import std/[unittest]
import archive/types
import archive/io
import archive/registry
import archive/files
import archive/formats/tar
import archive/formats/zip
import archive/formats/gz
import archive/formats/brotli

registerTar()
registerZip()
registerGz()
registerBrotli()

suite "identify":
  test "tar by name and by stream":
    let inp = openInputFile("tests/testdata/self-tar.tar")
    let res = identifyFormat("self-tar.tar", inp)
    check(res.format != nil)
    check(res.format.ext == ".tar")

  test "zip by name and by stream":
    let inp = openInputFile("tests/testdata/test.zip")
    let res = identifyFormat("test.zip", inp)
    check(res.format != nil)
    check(res.format.ext == ".zip")

  test "gzip magic wins over unknown name":
    var ctx: ArchiveContext
    let gz = handler(fmtGz)
    let dst = newOutput()
    let src = openInputString("hello world")
    gz.compress(src, dst)
    let payload = take(dst)
    require(payload.len > 2)
    let res = identifyFormat("noext", openInputString(payload))
    check(res.format != nil)
    check(res.format.ext == ".gz")

  test "compressed archive tar.gz detected as two layers":
    var ctx: ArchiveContext
    let files = filesFromEntries(ctx, FromFSOptions(),
      [FsEntry(path: "a.txt", meta: FileMeta(name: "a.txt", size: 3,
        isRegular: true), data: "abc")], ".", "root")
    let tarH = handler(fmtTar)
    let gzH = handler(fmtGz)
    let inner = newOutput()
    tarH.archive(ctx, inner, files)
    let innerInp = toInput(inner)
    let outer = newOutput()
    gzH.compress(innerInp, outer)
    let res = identifyFormat("example.tar.gz", toInput(outer))
    check(res.compressed != nil)
    check(res.compressed.compression.ext == ".gz")
    check(res.compressed.extraction.ext == ".tar")

  test "brotli by name":
    let res = identifyFormat("hello.br", nil)
    check(res.format != nil)
    check(res.format.ext == ".br")

  test "no match raises":
    expect(NoMatchError):
      discard identifyFormat("file.unknownext", openInputString("xyz"))
