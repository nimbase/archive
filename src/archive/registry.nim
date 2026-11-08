## Format dispatch and identification.
##
## No registry, no globals: `CompressionFormat` and `ArchiveFormat` are
## distinct string-valued enums (`$fmt` is the canonical extension), so
## passing an archive to `decompress` fails at compile time. Every
## operation below dispatches statically. Safe to call from any thread.
##
## Inputs are zero-copy cursors: matching only peeks indexed spans, so
## no rewind buffering is needed at all (the Go rewindReader disappears).

import std/[options, strutils]
import nimcypher/utils as ncUtils
import ./io
import ./types
import ./crypt
import ./formats/tar
import ./formats/zip
import ./formats/gz
import ./formats/zlib
import ./formats/lz4
import ./formats/bz2
import ./formats/brotli

type
  IdentifyResult* = object
    ## Outcome of identify(). `archival` is set when an archive was
    ## matched; `compression` when it is compressed externally — or when
    ## a lone compression stream was matched (archival unset: use
    ## decompressFile for those).
    archival*: Option[ArchiveFormat]
    compression*: Option[CompressionFormat]

  CompressedArchive* = object
    ## A tar.gz-style pair as plain values: archival archive wrapped in
    ## an outer compression layer. Types enforce valid combinations, so
    ## no constructor validation is needed.
    archival*: ArchiveFormat
    compression*: CompressionFormat

  EncryptedArchive* = object
    ## Keyless pipeline descriptor: archive, optionally compress, then
    ## encrypt (reverse on read). Keys and passwords flow per call like
    ## `ctx` — never stored — so there is no secret material to wipe
    ## when the descriptor is copied or dropped.
    archival*: ArchiveFormat
    compression*: Option[CompressionFormat]

proc extension*(c: CompressedArchive): string =
  ## Multi-extension name, e.g. ".tar.gz".
  $c.archival & $c.compression

proc mediaTypeOf*(c: CompressedArchive): MediaType =
  mediaTypeOf(c.compression)

proc baseName*(filename: string): string =
  let f = filename.replace('\\', '/')
  let idx = f.rfind('/')
  if idx < 0: f else: f[idx + 1 .. ^1]

proc compressionForExt*(ext: string): CompressionFormat =
  ## Reverse lookup from an extension string (with or without dot,
  ## any case) to the enum. Pure: iterates the closed set, no table.
  ## Raises ArchiveError when unknown.
  let norm = ext.toLowerAscii().strip(chars = {'.'})
  for f in CompressionFormat:
    if ($f).strip(chars = {'.'}) == norm:
      return f
  raise newException(ArchiveError, "unknown compression extension: " & ext)

proc archiveForExt*(ext: string): ArchiveFormat =
  ## Reverse lookup for archival extensions. See compressionForExt.
  let norm = ext.toLowerAscii().strip(chars = {'.'})
  for f in ArchiveFormat:
    if ($f).strip(chars = {'.'}) == norm:
      return f
  raise newException(ArchiveError, "unknown archive extension: " & ext)

proc matchFormat*(fmt: CompressionFormat; filename: string;
    inp: Input): MatchResult =
  ## Static dispatch to the per-format matcher. Deterministic: no
  ## table iteration order involved. Overload resolves on static type.
  case fmt
  of cfGz: matchGz(filename, inp)
  of cfZlib: matchZlib(filename, inp)
  of cfLz4: matchLz4(filename, inp)
  of cfBz2: matchBz2(filename, inp)
  of cfBrotli: matchBrotli(filename, inp)

proc matchFormat*(fmt: ArchiveFormat; filename: string;
    inp: Input): MatchResult =
  ## Same, for archival formats.
  case fmt
  of afTar: matchTar(filename, inp)
  of afZip: matchZip(filename, inp)

proc compressInto*(fmt: CompressionFormat; inp: Input; dst: Output;
    level = 0) =
  ## One-shot compress. Level 0 selects the codec default
  ## (gzip/zlib/bzip2: 6; lz4: fast path, level ignored; brotli:
  ## store-encode, level ignored). Codec errors propagate raw.
  ## Archival formats are rejected by the type system, not at runtime.
  case fmt
  of cfGz: gzipCompressInto(inp, dst, level)
  of cfZlib: zlibCompressInto(inp, dst, level)
  of cfLz4: lz4CompressInto(inp, dst, level)
  of cfBz2: bz2CompressInto(inp, dst, level)
  of cfBrotli: brotliCompressInto(inp, dst)

proc decompressInto*(fmt: CompressionFormat; inp: Input; dst: Output) =
  ## One-shot decompress. Codec errors propagate raw.
  case fmt
  of cfGz: gzipDecompressInto(inp, dst)
  of cfZlib: zlibDecompressInto(inp, dst)
  of cfLz4: lz4DecompressInto(inp, dst)
  of cfBz2: bz2DecompressInto(inp, dst)
  of cfBrotli: brotliDecompressInto(inp, dst)

proc decompressFileInto*(fmt: CompressionFormat; srcPath, dstPath: string) =
  ## Bounded-memory file-to-file decompress: fixed-size working buffers
  ## (64KB input + ~96KB window, 128KB for lz4, ≤900KB per bzip2 block),
  ## never holding full compressed or uncompressed data. Codec errors
  ## propagate raw with the same types as decompressInto. Brotli keeps
  ## the one-shot path: nbrotli buffers full streams (no file-streaming
  ## entry point upstream), so it still holds full contents in memory.
  case fmt
  of cfGz: gzipDecompressFile(srcPath, dstPath)
  of cfZlib: zlibDecompressFile(srcPath, dstPath)
  of cfLz4: lz4DecompressFile(srcPath, dstPath)
  of cfBz2: bz2DecompressFile(srcPath, dstPath)
  of cfBrotli:
    let inp = openInputFile(srcPath)
    try:
      let dst = newOutput()
      brotliDecompressInto(inp, dst)
      writeFile(dstPath, take(dst))
    finally:
      close(inp)

proc archiveFormat*(fmt: ArchiveFormat; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  ## Archive with default settings. For custom settings call
  ## archiveTar/archiveZip directly and compose manually if needed.
  case fmt
  of afTar: archiveTar(Tar(), ctx, dst, files)
  of afZip: archiveZip(Zip(), ctx, dst, files)

proc extractFormat*(fmt: ArchiveFormat; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  ## Extract with default settings. For custom settings call
  ## extractTar/extractZip directly.
  case fmt
  of afTar: extractTar(Tar(), ctx, inp, handle)
  of afZip: extractZip(Zip(), ctx, inp, handle)

proc archiveTo*(c: CompressedArchive; ctx: ArchiveContext;
    dst: Output; files: seq[FileInfo]; level = 0) =
  let tmp = newOutput()
  archiveFormat(c.archival, ctx, tmp, files)
  compressInto(c.compression, toInput(tmp), dst, level)

proc extractFrom*(c: CompressedArchive; ctx: ArchiveContext;
    inp: Input; handle: FileHandler) =
  let tmp = newOutput()
  decompressInto(c.compression, inp, tmp)
  extractFormat(c.archival, ctx, toInput(tmp), handle)

proc archiveTo*(e: EncryptedArchive; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]; key: ncUtils.Key32; level = 0;
    chunkSize = encChunkDefault) =
  ## Archive, optionally compress, then encrypt into `dst`.
  let tmp = newOutput()
  if e.compression.isSome:
    CompressedArchive(archival: e.archival,
      compression: e.compression.get).archiveTo(ctx, tmp, files, level)
  else:
    archiveFormat(e.archival, ctx, tmp, files)
  let ob = outputBytes(tmp)
  if ob.len == 0:
    encryptInto(newSeq[byte](0), key, dst, chunkSize)
  else:
    encryptInto(toOpenArray(cast[ptr UncheckedArray[byte]](ob.p), 0,
      ob.len - 1), key, dst, chunkSize)

proc archiveTo*(e: EncryptedArchive; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]; password: string; level = 0;
    chunkSize = encChunkDefault) =
  ## Password variant: fresh random salt per message, Argon2id KDF.
  let tmp = newOutput()
  if e.compression.isSome:
    CompressedArchive(archival: e.archival,
      compression: e.compression.get).archiveTo(ctx, tmp, files, level)
  else:
    archiveFormat(e.archival, ctx, tmp, files)
  let ob = outputBytes(tmp)
  if ob.len == 0:
    encryptInto(newSeq[byte](0), password, dst, chunkSize)
  else:
    encryptInto(toOpenArray(cast[ptr UncheckedArray[byte]](ob.p), 0,
      ob.len - 1), password, dst, chunkSize)

proc extractFrom*(e: EncryptedArchive; ctx: ArchiveContext; inp: Input;
    handle: FileHandler; key: ncUtils.Key32) =
  ## Decrypt, optionally decompress, then extract.
  let tmp = newOutput()
  decryptInto(inp, key, tmp)
  let inner = toInput(tmp)
  if e.compression.isSome:
    CompressedArchive(archival: e.archival,
      compression: e.compression.get).extractFrom(ctx, inner, handle)
  else:
    extractFormat(e.archival, ctx, inner, handle)

proc extractFrom*(e: EncryptedArchive; ctx: ArchiveContext; inp: Input;
    handle: FileHandler; password: string) =
  ## Password variant: salt comes from the header.
  let tmp = newOutput()
  decryptInto(inp, password, tmp)
  let inner = toInput(tmp)
  if e.compression.isSome:
    CompressedArchive(archival: e.archival,
      compression: e.compression.get).extractFrom(ctx, inner, handle)
  else:
    extractFormat(e.archival, ctx, inner, handle)

proc matchOne(fmt: CompressionFormat; filename: string; inp: Input;
    inner: Input): MatchResult =
  ## inp may be nil (name-only match). inner is pre-decompressed input
  ## for matching archive formats inside compression, or nil.
  var fname = filename
  if fname == ".":
    fname = ""
  if inner != nil:
    return matchFormat(fmt, fname, inner)
  if inp == nil:
    return matchFormat(fmt, fname, nil)
  # Peek without consuming: matching reads via indices only.
  let saved = inputPos(inp)
  let res = matchFormat(fmt, fname, inp)
  seek(inp, saved)
  res

proc matchOne(fmt: ArchiveFormat; filename: string; inp: Input;
    inner: Input): MatchResult =
  ## Same, for archival formats (overload resolves on static type).
  var fname = filename
  if fname == ".":
    fname = ""
  if inner != nil:
    return matchFormat(fmt, fname, inner)
  if inp == nil:
    return matchFormat(fmt, fname, nil)
  # Peek without consuming: matching reads via indices only.
  let saved = inputPos(inp)
  let res = matchFormat(fmt, fname, inp)
  seek(inp, saved)
  res

proc identify*(ctx: ArchiveContext; filename: string;
    inp: Input = nil): IdentifyResult =
  ## Most specific match or NoMatchError. Never consumes `inp`.
  ## Probes compression candidates first with brotli last so definite
  ## magic bytes win over its heuristic stream sniff, then archival
  ## formats inside. A stream-only compression match that fails to
  ## decode is demoted (phantom layer), so heuristic sniffs can never
  ## wrap another format.
  let base = baseName(filename)

  var comp = none(CompressionFormat)
  var compByName = false
  for fmt in CompressionFormat:
    ctx.checkCancelled()
    let mr =
      try: matchOne(fmt, base, inp, nil)
      except CatchableError as e:
        raise newException(ArchiveError, "matching " & $fmt & ": " & e.msg)
    if mr.matched():
      comp = some(fmt)
      compByName = mr.byName
      break

  # Decompress once for inner matching, reused across candidates.
  var inner: Input = nil
  let scratch = newOutput()
  if comp.isSome and inp != nil:
    try:
      decompressInto(comp.get, inp, scratch)
      inner = toInput(scratch)
    except CatchableError:
      inner = nil

  var arch = none(ArchiveFormat)
  for fmt in ArchiveFormat:
    ctx.checkCancelled()
    let mr =
      try: matchOne(fmt, base, inp, inner)
      except CatchableError as e:
        raise newException(ArchiveError, "matching " & $fmt & ": " & e.msg)
    if mr.matched():
      arch = some(fmt)
      break

  if comp.isSome and inner == nil and not compByName:
    # Phantom layer: stream-only sniff that does not actually decode.
    comp = none(CompressionFormat)
  if comp.isSome and arch.isSome:
    return IdentifyResult(archival: arch, compression: comp)
  if comp.isSome:
    return IdentifyResult(compression: comp)
  if arch.isSome:
    return IdentifyResult(archival: arch)
  raise newException(NoMatchError, "no formats matched: " & filename)

proc identifyFormat*(filename: string; inp: Input = nil): IdentifyResult =
  var ctx: ArchiveContext
  identify(ctx, filename, inp)
