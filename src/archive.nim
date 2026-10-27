## Unified archive library, ported from mholt/archives (Go).
##
## Single entry point for the high-level one-shot API (compress/decompress,
## archiveDir, extractAll...). Nothing is re-exported and nothing is
## registered: import the specific modules you need for types and
## low-level access (archive/registry, archive/types, archive/io,
## archive/formats/...), then call. Every proc is safe to call from
## any thread — no shared state exists anywhere in the library.

import std/[options, strutils]
from std/os import createDir, joinPath, parentDir, isAbsolute, createSymlink,
  DirSep, removeFile
import ./archive/types
import ./archive/io
import ./archive/registry
import ./archive/files
import ./archive/zipfile

export registry
export types

type ArchiveEntry* = tuple[name: string, data: string]
  ## One extracted regular file: archive path plus its full content.

# ---------- one-shot compression (strings and files) ----------

proc compress*(fmt: CompressionFormat; data: string; level = 0): string =
  ## One-shot compress to a fresh string.
  let dst = newOutput(data.len div 2 + 32)
  compressInto(fmt, openInputString(data), dst, level)
  take(dst)

proc decompress*(fmt: CompressionFormat; data: string): string =
  ## One-shot decompress to a fresh string.
  let dst = newOutput()
  decompressInto(fmt, openInputString(data), dst)
  take(dst)

proc compressFile*(fmt: CompressionFormat; srcPath, dstPath: string; level = 0) =
  ## Compress a file to a path (memory-mapped input, zero-copy reads).
  let inp = openInputFile(srcPath)
  try:
    let dst = newOutput()
    compressInto(fmt, inp, dst, level)
    writeFile(dstPath, take(dst))
  finally:
    close(inp)

proc decompressFile*(fmt: CompressionFormat; srcPath, dstPath: string) =
  ## Decompress a file to a path with bounded memory (fixed-size working
  ## buffers, never full contents) via registry dispatch. Brotli keeps
  ## the one-shot path (upstream nbrotli limitation).
  decompressFileInto(fmt, srcPath, dstPath)

# ---------- archives ----------

proc archiveData*(archival: ArchiveFormat; files: seq[FileInfo];
    ctx = ArchiveContext(); compression = none(CompressionFormat)): string =
  ## Archive a file list to a blob, optionally compressed
  ## (compression = some(cfGz)). For custom archive settings call
  ## archiveTar/archiveZip directly.
  let dst = newOutput()
  if compression.isSome:
    CompressedArchive(archival: archival,
      compression: compression.get).archiveTo(ctx, dst, files)
  else:
    archiveFormat(archival, ctx, dst, files)
  take(dst)

proc archiveToFile*(archival: ArchiveFormat; files: seq[FileInfo]; path: string;
    ctx = ArchiveContext(); compression = none(CompressionFormat)) =
  ## Archive a file list straight to a path.
  writeFile(path, archiveData(archival, files, ctx, compression))

proc archiveDir*(archival: ArchiveFormat; srcDir, dstPath: string;
    rootInArchive = ""; ctx = ArchiveContext();
    compression = none(CompressionFormat); followSymlinks = false) =
  ## Archive a directory from disk in one call (files are memory-mapped
  ## lazily; nothing is read up front).
  let files = filesFromDisk(ctx,
    FromDiskOptions(followSymlinks: followSymlinks), [(srcDir, rootInArchive)])
  archiveToFile(archival, files, dstPath, ctx, compression)

proc archivePaths*(archival: ArchiveFormat;
    paths: openArray[(string, string)];
    ctx = ArchiveContext(); compression = none(CompressionFormat);
    followSymlinks = false): string =
  ## Archive explicit (disk path, archive path) pairs to a blob, e.g.
  ## `[("run.sh", "bin/run")]`. Counterpart to `archiveDir` when entries
  ## come from scattered locations rather than one root.
  let files = filesFromDisk(ctx,
    FromDiskOptions(followSymlinks: followSymlinks), paths)
  archiveData(archival, files, ctx, compression)

proc archivePaths*(archival: ArchiveFormat; paths: openArray[string];
    ctx = ArchiveContext(); compression = none(CompressionFormat);
    followSymlinks = false): string =
  ## Archive disk paths under their own names: `archivePaths(afTar,
  ## @["a.txt", "sub/b.txt"])` stores exactly those names. For custom
  ## in-archive names use the pairs overload above.
  var pairs = newSeq[(string, string)](paths.len)
  for i, p in paths:
    pairs[i] = (p, p)
  archivePaths(archival, pairs, ctx, compression, followSymlinks)

# ---------- extraction ----------

proc extractIdentified*(res: IdentifyResult; ctx: ArchiveContext;
    inp: Input; handle: FileHandler) =
  ## Dispatch an identify() result to the right extractor. Raises
  ## ArchiveError for compression-only results (use decompressFile).
  if res.archival.isSome:
    if res.compression.isSome:
      CompressedArchive(archival: res.archival.get,
        compression: res.compression.get).extractFrom(ctx, inp, handle)
    else:
      extractFormat(res.archival.get, ctx, inp, handle)
  elif res.compression.isSome:
    raise newException(ArchiveError,
      "compression-only format, use decompressFile: " & $res.compression.get)
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
    ctx: ArchiveContext) =
  ## Extract an archive by path with auto-identify. Opens the file twice
  ## (once to identify, once to extract) because identify may advance
  ## the cursor while probing the compression layer.
  let res = identifyPath(path)
  let inp = openInputFile(path)
  try:
    extractIdentified(res, ctx, inp, handle)
  finally:
    close(inp)

proc extractFile*(path: string; handle: FileHandler) =
  ## Same, with an internal context: the two-arg call most callers want.
  var ctx: ArchiveContext
  extractFile(path, handle, ctx)

proc safeDestPath*(outPath, name: string): string =
  ## Joins an archive entry name onto the destination, rejecting zip-slip
  ## entries (absolute paths or `..` components) with ArchiveError.
  ## Exported so custom extract loops can share the same guard.
  let rel = name.replace('\\', '/')
  if rel.isAbsolute:
    raise newException(ArchiveError,
      "entry escapes destination (absolute path): " & name)
  for part in rel.split('/'):
    if part == "..":
      raise newException(ArchiveError,
        "entry escapes destination (..): " & name)
  joinPath(outPath, rel.replace('/', DirSep))

proc extractZipToDirStreaming(path, outPath: string; ctx: ArchiveContext) =
  ## Bounded-memory zip extraction: entries stream incrementally,
  ## never holding a full compressed entry or extracted file in RAM.
  ## Bulk bytes never touch the mmap: central directory parses from a
  ## small mapped tail, then each entry streams via file reads (64KB
  ## input + ~96KB window, both reused with a 1MB cap). Stored entries
  ## copy chunked, deflated entries inflate windowed straight to disk.
  ## Peak is fixed buffers + metadata, not archive or uncompressed size.
  let inp = openInputFile(path)
  try:
    var reader: ZipReader
    try:
      reader = openZip(inp)
    except CatchableError as e:
      raise newException(ArchiveError, "zip open: " & e.msg)
    # Mmap base for offset arithmetic only (no dereference = no fault).
    let baseAddr = cast[int](basePointer(inp))
    # Separate read handle for bulk bytes: page cache, not process RSS.
    var rf: File
    if not open(rf, path, fmRead):
      raise newException(ArchiveError, "zip open: cannot reopen for streaming")
    try:
      # Bounded pool: one 96KB window + one 64KB input chunk, reused.
      let scratch = newOutput(StreamBufCap)
      var inBuf = newString(0)
      var entryIdx = 0
      for e in reader.files:
        ctx.checkCancelled()
        if e.name == "" or e.name == ".":
          continue
        let dest =
          try: safeDestPath(outPath, e.name)
          except ArchiveError as err:
            raise newException(ArchiveError,
              "handling file: " & e.name & ": " & err.msg)
        ctx.reportProgress(e.name, entryIdx, -1, e.expectLen.int64)
        inc entryIdx
        try:
          if e.isDir:
            createDir(dest)
          elif e.isSymlink and not e.isDir:
            # Symlink targets are tiny path strings; materializing is
            # bounded by path length, not archive size.
            let lt =
              try: readAll(entryContent(e))
              except CatchableError as err:
                raise newException(ArchiveError,
                  "handling file: " & e.name & ": " & err.msg)
            createDir(parentDir(dest))
            createSymlink(lt, dest)
          elif not e.isDir and not e.isSymlink:
            createDir(parentDir(dest))
            var f: File
            if not open(f, dest, fmWrite):
              raise newException(ArchiveError,
                "handling file: " & e.name & ": cannot open for writing")
            var ok = false
            try:
              if e.raw.len == 0:
                # Empty file: nothing to stream; verify expectations.
                if e.expectLen != 0:
                  raise newException(ArchiveError,
                    "handling file: " & e.name & ": size mismatch")
                if e.expectCrc != 0:
                  raise newException(ArchiveError,
                    "handling file: " & e.name & ": checksum mismatch")
                ok = true
              else:
                # Offset arithmetic only: no mmap dereference, no fault.
                let dataOff = cast[int](e.raw.p) - baseAddr
                setFilePos(rf, dataOff.int64)
                if e.meth == 0: # stored
                  streamStoredRangeToFile(rf, f, inBuf, e.raw.len,
                    e.expectLen, e.expectCrc, e.name)
                elif e.meth == 8: # deflate
                  streamDeflatedRangeToFile(rf, e.raw.len, f, scratch,
                    inBuf, e.expectLen, e.expectCrc, e.name)
                else:
                  raise newException(ArchiveError,
                    "handling file: " & e.name & ": unsupported method")
                ok = true
            finally:
              close(f)
              resetBounded(scratch)
              if inBuf.len > MaxScratchCap:
                inBuf = newString(0)
              if not ok:
                try: removeFile(dest)
                except CatchableError: discard
          # else: skip other kinds (should not occur for zip)
        except ArchiveError:
          raise
        except CatchableError as err:
          raise newException(ArchiveError,
            "handling file: " & e.name & ": " & err.msg)
    finally:
      close(rf)
  finally:
    close(inp)

proc extractFile*(path, outPath: string; ctx: ArchiveContext) =
  ## Extracts an entire archive to a directory tree on disk, creating it
  ## (including parents) as needed. Regular files and directories are
  ## written; symlinks are recreated; other entry kinds (hardlinks,
  ## devices) are skipped. Entry names are validated with safeDestPath,
  ## so a malicious archive cannot write outside `outPath`.
  ## Plain zip uses a bounded streaming fast path (no full-entry
  ## buffering); all other formats use the generic handler (tar is
  ## already zero-copy bounded via borrowed spans).
  createDir(outPath)
  let res =
    try: identifyPath(path)
    except CatchableError:
      # Fall through to generic path for consistent error reporting.
      extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
        if info.nameInArchive == "" or info.nameInArchive == ".":
          return
        let dest = safeDestPath(outPath, info.nameInArchive)
        if info.isDir():
          createDir(dest)
        elif info.isSymlink():
          createDir(parentDir(dest))
          createSymlink(info.linkTarget, dest)
        elif info.isRegular():
          createDir(parentDir(dest))
          copyStreamToFile(info.open(), dest)
      , ctx)
      return
  if res.archival == some(afZip) and res.compression.isNone:
    extractZipToDirStreaming(path, outPath, ctx)
    return
  extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
    if info.nameInArchive == "" or info.nameInArchive == ".":
      return
    let dest = safeDestPath(outPath, info.nameInArchive)
    if info.isDir():
      createDir(dest)
    elif info.isSymlink():
      createDir(parentDir(dest))
      createSymlink(info.linkTarget, dest)
    elif info.isRegular():
      createDir(parentDir(dest))
      copyStreamToFile(info.open(), dest)
    # else: skip hardlinks, fifos, and other special entries
  , ctx)

proc extractFile*(path, outPath: string) =
  ## Same, with an internal context.
  var ctx: ArchiveContext
  extractFile(path, outPath, ctx)

iterator extractAll*(path: string;
    ctx: ArchiveContext): ArchiveEntry =
  ## Iterate all regular files as (archive path, content) pairs:
  ## `for e in extractAll("b.tar.gz"): ...`.
  ## Collects first, then yields: the core is callback-driven, so true
  ## lazy streaming is not possible; memory use matches the old seq form.
  var acc: seq[ArchiveEntry] = @[]
  extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
    if info.isRegular():
      acc.add((info.nameInArchive, readAll(info.open()))), ctx)
  for e in acc:
    yield e

iterator extractAll*(path: string): ArchiveEntry =
  ## Same, with an internal context.
  var ctx: ArchiveContext
  for e in extractAll(path, ctx):
    yield e

proc listEntries*(path: string; ctx: ArchiveContext): seq[string] =
  ## List every entry path in an archive without reading contents.
  var acc: seq[string] = @[]
  extractFile(path, proc(c: ArchiveContext; info: FileInfo) =
    acc.add(info.nameInArchive), ctx)
  acc

proc listEntries*(path: string): seq[string] =
  ## Same, with an internal context.
  var ctx: ArchiveContext
  listEntries(path, ctx)
