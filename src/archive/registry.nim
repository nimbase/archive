## Format registry and identification, ported from formats.go.
##
## Inputs are zero-copy cursors: matching only peeks indexed spans, so
## no rewind buffering is needed at all (the Go rewindReader disappears).

import std/[tables, strutils]
import ./io
import ./types

type
  FormatKind* = enum
    fkCompression
    fkArchival
    fkExtraction

  FormatHandler* = ref object
    ## Registered format entry. Per-format settings live in the
    ## formats/* modules; the registry keeps closures bound to defaults.
    ext*: string          ## e.g. ".tar"
    mediaType*: string
    kinds*: set[FormatKind]
    doMatch*: proc(filename: string; inp: Input): MatchResult {.closure.}
    compress*: proc(inp: Input; dst: Output) {.closure.}
    decompress*: proc(inp: Input; dst: Output) {.closure.}
    archive*: proc(ctx: ArchiveContext; dst: Output;
        files: seq[FileInfo]) {.closure.}
    extract*: proc(ctx: ArchiveContext; inp: Input;
        handle: FileHandler) {.closure.}

  CompressedArchive* = ref object
    ## An archive compressed externally (e.g. tar.gz). Port of Go struct.
    archival*: FormatHandler
    extraction*: FormatHandler
    compression*: FormatHandler

  IdentifyResult* = object
    ## Exactly one of format/compressed is non-nil.
    format*: FormatHandler
    compressed*: CompressedArchive

var formats = initTable[string, FormatHandler]()

proc registerFormat*(h: FormatHandler) =
  ## Port of Go RegisterFormat. Panics (raises) on duplicate.
  let name = h.ext.toLowerAscii().strip(chars = {'.'})
  if formats.hasKey(name):
    raise newException(ArchiveError, "format " & name & " is already registered")
  formats[name] = h

proc registeredFormats*(): seq[FormatHandler] =
  for _, v in formats:
    result.add(v)

proc extension*(h: FormatHandler): string = h.ext
proc mediaTypeOf*(h: FormatHandler): string = h.mediaType
proc isCompression*(h: FormatHandler): bool = fkCompression in h.kinds
proc isArchival*(h: FormatHandler): bool = fkArchival in h.kinds
proc isExtraction*(h: FormatHandler): bool = fkExtraction in h.kinds

proc extension*(c: CompressedArchive): string =
  var base = ""
  if c.archival != nil:
    base = c.archival.ext
  elif c.extraction != nil:
    base = c.extraction.ext
  base & c.compression.ext

proc mediaTypeOf*(c: CompressedArchive): string =
  c.compression.mediaType

proc baseName*(filename: string): string =
  let f = filename.replace('\\', '/')
  let idx = f.rfind('/')
  if idx < 0: f else: f[idx + 1 .. ^1]

proc matchOne(h: FormatHandler; filename: string; inp: Input;
    inner: Input): MatchResult =
  ## inp may be nil (name-only match). inner is pre-decompressed input
  ## for matching archive formats inside compression, or nil.
  var fname = filename
  if fname == ".":
    fname = ""
  if inner != nil:
    return h.doMatch(fname, inner)
  if inp == nil:
    return h.doMatch(fname, nil)
  # Peek without consuming: matching reads via indices only.
  let saved = inputPos(inp)
  let res = h.doMatch(fname, inp)
  seek(inp, saved)
  res

proc identify*(ctx: ArchiveContext; filename: string;
    inp: Input = nil): IdentifyResult =
  ## Port of Go Identify. Returns the most specific match or raises
  ## NoMatchError. Never consumes `inp`.
  var compression, archival, extraction: FormatHandler
  let base = baseName(filename)

  for _, h in formats:
    if not h.isCompression():
      continue
    ctx.checkCancelled()
    let mr =
      try: matchOne(h, base, inp, nil)
      except CatchableError as e:
        raise newException(ArchiveError, "matching " & h.ext & ": " & e.msg)
    if mr.matched():
      compression = h
      break

  # Decompress once for inner matching, reused across candidates.
  var inner: Input = nil
  let scratch = newOutput()
  if compression != nil and inp != nil and compression.decompress != nil:
    try:
      compression.decompress(inp, scratch)
      inner = toInput(scratch)
    except CatchableError:
      inner = nil

  for _, h in formats:
    if not (h.isArchival() or h.isExtraction()):
      continue
    ctx.checkCancelled()
    let mr =
      try: matchOne(h, base, inp, inner)
      except CatchableError as e:
        raise newException(ArchiveError, "matching " & h.ext & ": " & e.msg)
    if mr.matched():
      if h.isArchival(): archival = h
      if h.isExtraction(): extraction = h
      break

  let hasComp = compression != nil
  let hasAr = archival != nil
  let hasEx = extraction != nil
  if hasComp and not hasAr and not hasEx:
    return IdentifyResult(format: compression)
  if not hasComp and hasAr and not hasEx:
    return IdentifyResult(format: archival)
  if not hasComp and not hasAr and hasEx:
    return IdentifyResult(format: extraction)
  if not hasComp and hasAr and hasEx:
    let f = if archival != nil: archival else: extraction
    return IdentifyResult(format: f)
  if hasComp and hasEx:
    return IdentifyResult(
      compressed: CompressedArchive(archival: archival,
        extraction: extraction, compression: compression))
  raise newException(NoMatchError, "no formats matched: " & filename)

proc identifyFormat*(filename: string; inp: Input = nil): IdentifyResult =
  var ctx: ArchiveContext
  identify(ctx, filename, inp)

# --- CompressedArchive operations (port of formats.go methods) ---

proc archiveTo*(c: CompressedArchive; ctx: ArchiveContext;
    dst: Output; files: seq[FileInfo]) =
  if c.archival == nil or c.archival.archive == nil:
    raise newException(ArchiveError, "no archival format")
  if c.compression != nil and c.compression.compress != nil:
    let tmp = newOutput()
    c.archival.archive(ctx, tmp, files)
    c.compression.compress(toInput(tmp), dst)
  else:
    c.archival.archive(ctx, dst, files)

proc extractFrom*(c: CompressedArchive; ctx: ArchiveContext;
    inp: Input; handle: FileHandler) =
  if c.extraction == nil or c.extraction.extract == nil:
    raise newException(ArchiveError, "no extraction format")
  if c.compression != nil and c.compression.decompress != nil:
    let tmp = newOutput()
    c.compression.decompress(inp, tmp)
    c.extraction.extract(ctx, toInput(tmp), handle)
  else:
    c.extraction.extract(ctx, inp, handle)

proc matchCompressed*(c: CompressedArchive; filename: string;
    inp: Input): MatchResult =
  ## Port of CompressedArchive.Match.
  var conglomerate: MatchResult
  if c.compression != nil:
    let mr = c.compression.doMatch(filename, inp)
    if not mr.matched():
      return mr
    let tmp = newOutput()
    try:
      c.compression.decompress(inp, tmp)
    except CatchableError:
      return mr
    let inner = toInput(tmp)
    conglomerate = mr
    if c.archival != nil:
      let mr2 = c.archival.doMatch(filename, inner)
      if not mr2.matched():
        return mr2
      conglomerate.byName = conglomerate.byName or mr2.byName
      conglomerate.byStream = conglomerate.byStream or mr2.byStream
    return conglomerate
  if c.archival != nil:
    return c.archival.doMatch(filename, inp)
  return conglomerate
