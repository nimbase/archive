## Unified archive library, ported from mholt/archives (Go).
##
## Single entry point re-exporting the public API.
## Call registerDefaults() once before Identify/archive/extract.

when not defined(build_docs):
  {.error: "Import the specific module you need".}
else:
  import ./archive/types
  import ./archive/io
  import ./archive/simd
  import ./archive/registry
  import ./archive/files
  import ./archive/vfs
  import ./archive/crc32
  import ./archive/flate
  import ./archive/gzipf
  import ./archive/zlibf
  import ./archive/lz4f
  import ./archive/zipfile
  import ./archive/formats/tar
  import ./archive/formats/zip
  import ./archive/formats/gz
  import ./archive/formats/zlib
  import ./archive/formats/lz4
  import ./archive/formats/brotli

  export types
  export io
  export simd
  export registry
  export files
  export vfs
  export crc32
  export flate
  export gzipf
  export zlibf
  export lz4f
  export zipfile
  export tar
  export zip
  export gz
  export zlib
  export lz4
  export brotli

  proc registerDefaults*() =
    ## Register the v1 format set. Safe to call once (duplicates raise).
    registerTar()
    registerZip()
    registerGz()
    registerZlib()
    registerLz4()
    registerBrotli()
