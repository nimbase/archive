## Unified archive library, ported from mholt/archives (Go).
##
## Single entry point for the high-level one-shot API (compress/decompress,
## archiveDir, extractAll...). Nothing is re-exported: import the specific
## modules you need for types and low-level access (archive/registry,
## archive/types, archive/io, archive/formats/...).
## Call registerDefaults() once before Identify/archive/extract.
## For streaming, reusable buffers, or custom handler settings, use the
## registry handlers and codec modules directly.

import std/[options]
import ./archive/types
import ./archive/io
import ./archive/registry
import ./archive/files
import ./archive/gzipf
import ./archive/zlibf
import ./archive/bz2f
import ./archive/lz4f
import ./archive/formats/tar
import ./archive/formats/zip
import ./archive/formats/gz
import ./archive/formats/zlib
import ./archive/formats/bz2
import ./archive/formats/lz4
import ./archive/formats/brotli

proc registerDefaults*() =
  ## Register the v1 format set. Safe to call once (duplicates raise).
  registerTar()
  registerZip()
  registerGz()
  registerZlib()
  registerBz2()
  registerLz4()
  registerBrotli()

type ArchiveEntry* = tuple[name: string, data: string]
  ## One extracted regular file: archive path plus its full content.

# ---------- one-shot compression ----------

proc compressInto*(fmt: Format; inp: Input; dst: Output; level = 0) =
  ## Compress the remaining input into `dst`. Level 0 selects the codec
  ## default (gzip/zlib/bzip2: 6; lz4: fast path, level ignored; brotli:
  ## store-encode, level ignored). Raises ArchiveError for archival
  ## formats; codec errors (GzipError, Bz2Error, ...) propagate raw.
  case fmt
  of fmtGz: gzipCompressInto(inp, dst, level)
  of fmtZlib: zlibCompressInto(inp, dst, level)
  of fmtLz4: lz4CompressInto(inp, dst, level)
  of fmtBz2: bz2CompressInto(inp, dst, level)
  of fmtBrotli: brotliCompressInto(inp, dst)
  of fmtTar, fmtZip, fmtCustom:
    raise newException(ArchiveError,
      "not a built-in compression format: " & $fmt)

proc decompressInto*(fmt: Format; inp: Input; dst: Output) =
  ## Decompress the remaining input into `dst`. Codec errors propagate raw.
  case fmt
  of fmtGz: gzipDecompressInto(inp, dst)
  of fmtZlib: zlibDecompressInto(inp, dst)
  of fmtLz4: lz4DecompressInto(inp, dst)
  of fmtBz2: bz2DecompressInto(inp, dst)
  of fmtBrotli: brotliDecompressInto(inp, dst)
  of fmtTar, fmtZip, fmtCustom:
    raise newException(ArchiveError,
      "not a built-in compression format: " & $fmt)

proc compress*(fmt: Format; data: string; level = 0): string =
  ## One-shot compress to a fresh string.
  let dst = newOutput(data.len div 2 + 32)
  compressInto(fmt, openInputString(data), dst, level)
  take(dst)

proc decompress*(fmt: Format; data: string): string =
  ## One-shot decompress to a fresh string.
  let dst = newOutput()
  decompressInto(fmt, openInputString(data), dst)
  take(dst)

proc compressFile*(fmt: Format; srcPath, dstPath: string; level = 0) =
  ## Compress a file to a path (memory-mapped input, zero-copy reads).
  let inp = openInputFile(srcPath)
  try:
    let dst = newOutput()
    compressInto(fmt, inp, dst, level)
    writeFile(dstPath, take(dst))
  finally:
    close(inp)

proc decompressFile*(fmt: Format; srcPath, dstPath: string) =
  ## Decompress a file to a path.
  let inp = openInputFile(srcPath)
  try:
    let dst = newOutput()
    decompressInto(fmt, inp, dst)
    writeFile(dstPath, take(dst))
  finally:
    close(inp)

# ---------- archives ----------

proc compressedArchive*(archival, compression: Format): CompressedArchive =
  ## Build a tar.gz-style pair from enums: extraction = archival handler.
  ## Replaces the verbose CompressedArchive(archival: handlerFor(".tar"),
  ## extraction: ..., compression: ...) struct literal.
  let a = handler(archival)
  if fkArchival notin a.kinds:
    raise newException(ArchiveError,
      "not an archival format: " & $archival)
  let c = handler(compression)
  if fkCompression notin c.kinds:
    raise newException(ArchiveError,
      "not a compression format: " & $compression)
  CompressedArchive(archival: a, extraction: a, compression: c)

proc archiveData*(archival: Format; files: seq[FileInfo];
    ctx = ArchiveContext(); compression = none(Format)): string =
  ## Archive a file list to a blob, optionally compressed
  ## (compression = some(fmtGz)). Raises ArchiveError when archival is
  ## not an archival format.
  let h = handler(archival)
  if h.archive == nil or fkArchival notin h.kinds:
    raise newException(ArchiveError,
      "not an archival format: " & $archival)
  let dst = newOutput()
  if compression.isSome:
    compressedArchive(archival, compression.get).archiveTo(ctx, dst, files)
  else:
    h.archive(ctx, dst, files)
  take(dst)

proc archiveToFile*(archival: Format; files: seq[FileInfo]; path: string;
    ctx = ArchiveContext(); compression = none(Format)) =
  ## Archive a file list straight to a path.
  writeFile(path, archiveData(archival, files, ctx, compression))

proc archiveDir*(archival: Format; srcDir, dstPath: string;
    rootInArchive = ""; ctx = ArchiveContext();
    compression = none(Format); followSymlinks = false) =
  ## Archive a directory from disk in one call (files are memory-mapped
  ## lazily; nothing is read up front).
  let files = filesFromDisk(ctx,
    FromDiskOptions(followSymlinks: followSymlinks), [(srcDir, rootInArchive)])
  archiveToFile(archival, files, dstPath, ctx, compression)

# ---------- extraction ----------

proc extractIdentified*(res: IdentifyResult; ctx: ArchiveContext;
    inp: Input; handle: FileHandler) =
  ## Dispatch an identify() result to the right extractor. Raises
  ## ArchiveError for compression-only results (use decompressFile).
  if res.compressed != nil:
    res.compressed.extractFrom(ctx, inp, handle)
  elif res.format != nil:
    if res.format.extract == nil:
      raise newException(ArchiveError,
        "compression-only format, use decompressFile: " & res.format.ext)
    res.format.extract(ctx, inp, handle)
  else:
    raise newException(NoMatchError, "nothing identified")

proc identifyPath*(path: string): IdentifyResult =
  ## Identify an archive by filename and magic bytes.
  let inp = openInputFile(path)
  try:
    identifyFormat(path, inp)
  finally:
    close(inp)

proc extractFile*(path: string; handle: FileHandler;
    ctx = ArchiveContext()) =
  ## Extract an archive by path with auto-identify. Opens the file twice
  ## (once to identify, once to extract) because identify may advance
  ## the cursor while probing the compression layer.
  let res = identifyPath(path)
  let inp = openInputFile(path)
  try:
    extractIdentified(res, ctx, inp, handle)
  finally:
    close(inp)

proc extractAll*(path: string; ctx = ArchiveContext()): seq[ArchiveEntry] =
  ## Extract all regular files to (archive path, content) pairs.
  var acc: seq[ArchiveEntry] = @[]
  extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
    if info.isRegular():
      acc.add((info.nameInArchive, readAll(info.open()))), ctx)
  acc

proc listEntries*(path: string; ctx = ArchiveContext()): seq[string] =
  ## List every entry path in an archive without reading contents.
  var acc: seq[string] = @[]
  extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
    acc.add(info.nameInArchive), ctx)
  acc
