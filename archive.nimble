# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "Unified Nim library for archives and compression, ported from mholt/archives"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.10"
requires "nbrotli >= 0.1.0"

feature "nimsimd":
  requires "nimsimd >= 1.3.2"
