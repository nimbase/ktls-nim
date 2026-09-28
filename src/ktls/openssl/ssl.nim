# OpenSSL extras for tests and advanced use: handshake + keylog capture.
#
# Everything already in `std/openssl` is reused as-is (context and
# connection setup, I/O, error codes, and its robust multi-version
# `libssl` loader). This module adds only the pieces stdlib lacks:
# the keylog callback, version/cipher introspection, and TLS 1.3
# pinning. It is deliberately *not* re-exported by `ktls.nim`, so the
# core package never requires `-d:ssl` — only importers of this
# module need it.
#
# Compile with `-d:ssl`.
when not defined(ssl):
  {.error: "ktls/openssl/ssl requires -d:ssl (it builds on std/openssl)".}

import std/openssl

export openssl.SslCtx
export openssl.SslPtr

const
  Tls13VersionNum* = 0x0304
  SslCtrlSetMinProtoVersion* = 123.cint
  SslCtrlSetMaxProtoVersion* = 124.cint
  SslErrorWantRead* = 2.cint
  SslErrorWantWrite* = 3.cint
  # `SSL_VERIFY_NONE`, `SSL_FILETYPE_PEM` and `SSL_CTX_ctrl` come from
  # `std/openssl` — reused, not redefined.

type
  SslKeylogCb* = proc (ssl: SslPtr, line: cstring) {.cdecl.}
    ## `SSL_CTX_keylog_cb_func`. Runs on the handshaking thread; keep
    ## it short (append the line, nothing more).

# NOTE: the push carries `dynlib` but deliberately *not* bare
# `importc` — with a bare `importc` in the push, Nim looks up the
# Nim-side proc name instead of the `importc` rename and every call
# dies with `could not import`. `DLLSSLName` is std/openssl's loader
# with multi-version fallback, reused here.
{.push cdecl, dynlib: DLLSSLName.}
proc sslCtxSetKeylogCallback*(ctx: SslCtx,
    cb: SslKeylogCb) {.importc: "SSL_CTX_set_keylog_callback".}
proc sslGetVersionStr*(ssl: SslPtr): cstring {.importc: "SSL_get_version".}
proc sslGetCurrentCipher*(ssl: SslPtr): pointer {.
    importc: "SSL_get_current_cipher".}
proc sslCipherGetName*(cipher: pointer): cstring {.
    importc: "SSL_CIPHER_get_name".}
proc sslCtxSetNumTickets*(ctx: SslCtx, n: cint): cint {.
    importc: "SSL_CTX_set_num_tickets".}
  ## How many post-handshake session tickets the server sends.
  ## Pin to `0` before a manual kTLS handoff: every ticket is an
  ## application-epoch record that would advance the sequence number
  ## out from under the `recSeq` you install.
{.pop.}

proc pinTls13*(ctx: SslCtx) =
  ## Restrict a context to TLS 1.3 only (min = max = 1.3).
  discard SSL_CTX_ctrl(ctx, SslCtrlSetMinProtoVersion, clong(Tls13VersionNum),
    nil)
  discard SSL_CTX_ctrl(ctx, SslCtrlSetMaxProtoVersion, clong(Tls13VersionNum),
    nil)

proc cipherName*(ssl: SslPtr): string =
  ## Negotiated suite name (e.g. `"TLS_AES_128_GCM_SHA256"`).
  $sslCipherGetName(sslGetCurrentCipher(ssl))

proc negotiatedVersion*(ssl: SslPtr): string =
  ## Negotiated version string (e.g. `"TLSv1.3"`).
  $sslGetVersionStr(ssl)
