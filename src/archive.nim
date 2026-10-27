## Unified archive library, ported from mholt/archives (Go).
##
## Single entry point for the high-level one-shot API (compress/decompress,
## archiveDir, extractAll...). Nothing is re-exported and nothing is
## registered: import the specific modules you need for types and
## low-level access (archive/registry, archive/types, archive/io,
## archive/formats/...), then call. Every proc is safe to call from
## any thread — no shared state exists anywhere in the library.

import std/[options]
import ./archive/types
import ./archive/io
import ./archive/registry
import ./archive/files

type ArchiveEntry* = tuple[name: string, data: string]
  ## One extracted regular file: archive path plus its full content.

# ---------- one-shot compression (strings and files) ----------

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

proc archiveData*(archival: Format; files: seq[FileInfo];
    ctx = ArchiveContext(); compression = none(Format)): string =
  ## Archive a file list to a blob, optionally compressed
  ## (compression = some(fmtGz)). For custom archive settings call
  ## archiveTar/archiveZip directly.
  let dst = newOutput()
  if compression.isSome:
    compressedArchive(archival, compression.get).archiveTo(ctx, dst, files)
  else:
    archiveFormat(archival, ctx, dst, files)
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
  if res.compression.isSome:
    CompressedArchive(archival: res.format,
      compression: res.compression.get).extractFrom(ctx, inp, handle)
  elif res.format.isArchival() or res.format.isExtraction():
    extractFormat(res.format, ctx, inp, handle)
  else:
    raise newException(ArchiveError,
      "compression-only format, use decompressFile: " & $res.format)

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
