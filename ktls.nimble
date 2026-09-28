# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "Linux kernel TLS (kTLS) offload: low-level C-style wrapper plus high-level API"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.10"
requires "nimcypher >= 0.2.5"

task test, "Run the test suite":
  for t in ["t_raw", "t_session", "t_tls13", "t_keylog", "t_integration"]:
    exec "nim c -r --hints:off tests/" & t & ".nim"
  # t_openssl uses std/openssl and needs -d:ssl.
  exec "nim c -r --hints:off -d:ssl tests/t_openssl.nim"
