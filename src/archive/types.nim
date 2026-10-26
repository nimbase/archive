## Core types ported from mholt/archives (archives.go + interfaces.go).
##
## Go uses io/fs.FileInfo and io.Reader/Writer abstractions. In Nim we use
## our own io core (Input/Output over memfiles) and model file metadata
## explicitly.

import std/[times]
import ./io

export io

type
  ArchiveError* = object of CatchableError
  NoMatchError* = object of ArchiveError
  SkipDir* = object of ArchiveError
  SkipAll* = object of ArchiveError

  FileMode* = distinct int
    ## Minimal mode bits. We preserve Unix permission bits plus
    ## dir/symlink markers; mirrors the subset of fs.FileMode we need.

  FileMeta* = object
    ## Virtualized file metadata, replaces fs.FileInfo.
    name*: string       ## base name (not full archive path)
    size*: int64
    mode*: int          ## raw Unix mode bits (permissions + file type)
    modTime*: Time
    isDir*: bool
    isSymlink*: bool
    isRegular*: bool

  FileInfo* = object
    ## A virtualized file abstraction for interacting with archives.
    ## Port of Go's archives.FileInfo.
    meta*: FileMeta
    ## The file header as used/provided by the archive format.
    ## Kept as a string dump or format-specific ref; nil when creating.
    header*: RootRef
    ## Path of the file as it appears in the archive (slash separated).
    nameInArchive*: string
    ## For symbolic and hard links, the target of the link.
    linkTarget*: string
    ## Opens the file content for reading. Zero-copy when the entry is
    ## backed by mapped memory: no read syscalls, no buffer copies.
    open*: proc(): Input {.closure.}

  MatchResult* = object
    byName*: bool
    byStream*: bool

  ArchiveContext* = object
    ## Minimal cancellation token replacing Go's context.Context.
    cancelled*: ptr bool

  FileHandler* = proc(ctx: ArchiveContext; info: FileInfo) {.closure.}
    ## Called for each entry while extracting/walking. Raise SkipDir to
    ## skip a directory, SkipAll to stop the walk.

  FromDiskOptions* = object
    followSymlinks*: bool
    clearAttributes*: bool

  FromFSOptions* = object
    followSymlinks*: bool
    clearAttributes*: bool

  ArchiveAsyncJob* = object
    file*: FileInfo
    ## Result channel replacement: caller-supplied proc receiving the error
    ## (nil as empty string means success).
    result*: proc(err: string) {.closure.}

const
  ModeDir* = 0o040000
  ModeSymlink* = 0o120000
  ModePermMask* = 0o7777

proc matched*(mr: MatchResult): bool {.inline.} =
  mr.byName or mr.byStream

proc isDir*(f: FileInfo): bool {.inline.} = f.meta.isDir
proc isSymlink*(f: FileInfo): bool {.inline.} = f.meta.isSymlink
proc isRegular*(f: FileInfo): bool {.inline.} = f.meta.isRegular
proc size*(f: FileInfo): int64 {.inline.} = f.meta.size
proc name*(f: FileInfo): string {.inline.} = f.meta.name
proc mode*(f: FileInfo): int {.inline.} = f.meta.mode
proc modTime*(f: FileInfo): Time {.inline.} = f.meta.modTime

proc cancelled*(ctx: ArchiveContext): bool {.inline.} =
  ctx.cancelled != nil and ctx.cancelled[]

proc checkCancelled*(ctx: ArchiveContext) =
  if ctx.cancelled():
    raise newException(ArchiveError, "context cancelled")

proc stringOpener*(data: string): proc(): Input {.closure.} =
  ## Factory returning an opener closure over its own copy of data.
  ## Must be used instead of inline closures in loops: Nim closures
  ## created in a loop body share the captured variable slot, so an
  ## inline opener would serve the LAST file's data to every entry.
  ## A proc parameter is fresh per call. Zero-copy: the string is
  ## shared by reference, never copied.
  let d = data
  result = proc(): Input {.closure.} = openInputString(d)

proc fileOpener*(path: string): proc(): Input {.closure.} =
  ## Same as stringOpener but memory-maps the file from disk on each
  ## call: zero-copy reads, no read syscalls.
  let p = path
  result = proc(): Input {.closure.} = openInputFile(p)

proc viewOpener*(s: Span; keep: RootRef): proc(): Input {.closure.} =
  ## Opener over a borrowed span (e.g. an entry inside a mapped archive).
  ## `keep` retains the parent mapping/string.
  result = proc(): Input {.closure.} = openInputView(s, keep)

proc fileMetaFromStat*(path: string; info: FileInfo): FileMeta =
  ## Helper placeholder; real stat mapping lives in files.nim.
  info.meta

proc noAttrMeta*(m: FileMeta): FileMeta =
  ## Zero dst attributes except name/size/type/permissions (port of noAttrFileInfo).
  result = m
  result.modTime = fromUnix(0)
  result.mode = m.mode and (ModeDir or ModeSymlink or ModePermMask)
