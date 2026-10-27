## Format dispatch and identification.
##
## No registry, no globals: `Format` is a string-valued enum (`$fmt` is
## the canonical extension), capabilities and MIME types are exhaustive
## `case` procs in types.nim, and every operation below dispatches
## statically. Safe to call from any thread.
##
## Inputs are zero-copy cursors: matching only peeks indexed spans, so
## no rewind buffering is needed at all (the Go rewindReader disappears).

import std/[options, strutils]
import ./io
import ./types
import ./formats/tar
import ./formats/zip
import ./formats/gz
import ./formats/zlib
import ./formats/lz4
import ./formats/bz2
import ./formats/brotli

type
  IdentifyResult* = object
    ## Outcome of identify(). `format` is always set: the archival
    ## format, or the lone compression format for compression-only
    ## streams (use decompressFile for those).
    format*: Format
    compression*: Option[Format]  ## some when format is compressed externally

  CompressedArchive* = object
    ## A tar.gz-style pair as plain values: archival archive wrapped
    ## in an outer compression layer. No handlers, nothing shared.
    archival*: Format
    compression*: Format

proc extension*(c: CompressedArchive): string =
  ## Multi-extension name, e.g. ".tar.gz".
  $c.archival & $c.compression

proc mediaTypeOf*(c: CompressedArchive): MediaType =
  mediaTypeOf(c.compression)

proc baseName*(filename: string): string =
  let f = filename.replace('\\', '/')
  let idx = f.rfind('/')
  if idx < 0: f else: f[idx + 1 .. ^1]

proc formatForExt*(ext: string): Format =
  ## Reverse lookup from an extension string (with or without dot,
  ## any case) to the enum. Pure: iterates the closed set, no table.
  ## Raises ArchiveError when unknown.
  let norm = ext.toLowerAscii().strip(chars = {'.'})
  for f in Format:
    if ($f).strip(chars = {'.'}) == norm:
      return f
  raise newException(ArchiveError, "unknown format extension: " & ext)

proc matchFormat*(fmt: Format; filename: string; inp: Input): MatchResult =
  ## Static dispatch to the per-format matcher. Deterministic: no
  ## table iteration order involved.
  case fmt
  of fmtTar: matchTar(filename, inp)
  of fmtZip: matchZip(filename, inp)
  of fmtGz: matchGz(filename, inp)
  of fmtZlib: matchZlib(filename, inp)
  of fmtLz4: matchLz4(filename, inp)
  of fmtBz2: matchBz2(filename, inp)
  of fmtBrotli: matchBrotli(filename, inp)

proc compressInto*(fmt: Format; inp: Input; dst: Output; level = 0) =
  ## One-shot compress. Level 0 selects the codec default
  ## (gzip/zlib/bzip2: 6; lz4: fast path, level ignored; brotli:
  ## store-encode, level ignored). Codec errors propagate raw.
  case fmt
  of fmtGz: gzipCompressInto(inp, dst, level)
  of fmtZlib: zlibCompressInto(inp, dst, level)
  of fmtLz4: lz4CompressInto(inp, dst, level)
  of fmtBz2: bz2CompressInto(inp, dst, level)
  of fmtBrotli: brotliCompressInto(inp, dst)
  of fmtTar, fmtZip:
    raise newException(ArchiveError,
      "not a compression format: " & $fmt)

proc decompressInto*(fmt: Format; inp: Input; dst: Output) =
  ## One-shot decompress. Codec errors propagate raw.
  case fmt
  of fmtGz: gzipDecompressInto(inp, dst)
  of fmtZlib: zlibDecompressInto(inp, dst)
  of fmtLz4: lz4DecompressInto(inp, dst)
  of fmtBz2: bz2DecompressInto(inp, dst)
  of fmtBrotli: brotliDecompressInto(inp, dst)
  of fmtTar, fmtZip:
    raise newException(ArchiveError,
      "not a compression format: " & $fmt)

proc archiveFormat*(fmt: Format; ctx: ArchiveContext; dst: Output;
    files: seq[FileInfo]) =
  ## Archive with default settings. For custom settings call
  ## archiveTar/archiveZip directly and compose manually if needed.
  case fmt
  of fmtTar: archiveTar(Tar(), ctx, dst, files)
  of fmtZip: archiveZip(Zip(), ctx, dst, files)
  else:
    raise newException(ArchiveError,
      "not an archival format: " & $fmt)

proc extractFormat*(fmt: Format; ctx: ArchiveContext; inp: Input;
    handle: FileHandler) =
  ## Extract with default settings. For custom settings call
  ## extractTar/extractZip directly.
  case fmt
  of fmtTar: extractTar(Tar(), ctx, inp, handle)
  of fmtZip: extractZip(Zip(), ctx, inp, handle)
  else:
    raise newException(ArchiveError,
      "not an extraction format: " & $fmt)

proc compressedArchive*(archival, compression: Format): CompressedArchive =
  ## Build a tar.gz-style pair. Extraction always uses the archival
  ## format (every archival format also extracts).
  if not archival.isArchival():
    raise newException(ArchiveError,
      "not an archival format: " & $archival)
  if not compression.isCompression():
    raise newException(ArchiveError,
      "not a compression format: " & $compression)
  CompressedArchive(archival: archival, compression: compression)

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

proc matchOne(fmt: Format; filename: string; inp: Input;
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

proc identify*(ctx: ArchiveContext; filename: string;
    inp: Input = nil): IdentifyResult =
  ## Most specific match or NoMatchError. Never consumes `inp`.
  ## Probes in enum order (deterministic): compression candidates
  ## first with brotli last so definite magic bytes win over its
  ## heuristic stream sniff, then archival formats inside.
  let base = baseName(filename)

  var comp = none(Format)
  var compByName = false
  for fmt in Format:
    if not fmt.isCompression():
      continue
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

  var arch = none(Format)
  for fmt in Format:
    if not (fmt.isArchival() or fmt.isExtraction()):
      continue
    ctx.checkCancelled()
    let mr =
      try: matchOne(fmt, base, inp, inner)
      except CatchableError as e:
        raise newException(ArchiveError, "matching " & $fmt & ": " & e.msg)
    if mr.matched():
      arch = some(fmt)
      break

  if comp.isSome and arch.isSome:
    if inner == nil and not compByName:
      # Phantom layer: stream-only sniff that does not actually decode
      # (e.g. a heuristic claiming another format's bytes). Drop it and
      # report the inner archive alone.
      return IdentifyResult(format: arch.get)
    return IdentifyResult(format: arch.get, compression: comp)
  if comp.isSome and inner == nil and not compByName:
    # Same phantom case with no inner archive at all: undecodable.
    raise newException(NoMatchError, "no formats matched: " & filename)
  if comp.isSome:
    return IdentifyResult(format: comp.get)
  if arch.isSome:
    return IdentifyResult(format: arch.get)
  raise newException(NoMatchError, "no formats matched: " & filename)

proc identifyFormat*(filename: string; inp: Input = nil): IdentifyResult =
  var ctx: ArchiveContext
  identify(ctx, filename, inp)
