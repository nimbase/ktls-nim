# OpenSSL interop: let OpenSSL drive kTLS itself.
#
# OpenSSL ≥ 3.0 built with `enable-ktls` can install the kernel record
# layer internally — no key extraction needed. Enable it with
# `enableKtlsOnCtx`/`enableKtlsOnConn` right after creating the `SSL_CTX`
#/`SSL`, before the handshake:
#
#   discard enableKtlsOnCtx(ctx)
#   # ... SSL_connect/SSL_accept as usual; the kernel then handles
#   # the record layer ...
#
# Notes:
# - `SSL_CTX_set_options`/`SSL_set_options` are C macros over
#   `SSL_CTX_ctrl`/`SSL_ctrl` (`SSL_CTRL_OPTIONS = 32`); this module
#   binds the real symbols. The loader tries versioned runtimes first
#   (`libssl.so.3`, 1.1) and falls back to the unversioned dev symlink.
# - Whether offload actually engages depends on the OpenSSL build, the
#   negotiated suite, and kernel support. The option only *permits* it.
# - Manual offload (handshake elsewhere, install keys yourself) is the
#   `session` + `tls13` + `openssl/keylog` path instead.

const
  SslCtrlOptions* = 32
    ## `SSL_CTRL_OPTIONS` control code for `SSL_CTX_ctrl`/`SSL_ctrl`.
  SslOpEnableKtls* = 8'u64
    ## `SSL_OP_ENABLE_KTLS` = `SSL_OP_BIT(3)`.
  SslOpEnableKtlsTxZerocopySendfile* = 17179869184'u64
    ## `SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE` = `SSL_OP_BIT(34)`.
    ## Boosts `sendfile` with hardware offload; the file must not change
    ## while being sent.

# NOTE: the push carries `dynlib` but deliberately *not* bare
# `importc` — with a bare `importc` in the push, Nim looks up the
# Nim-side proc name instead of the `importc` rename and every call
# dies with `could not import` (see `openssl/ssl.nim`).
{.push dynlib: "libssl.so(.3|.1.1|)".}
proc sslCtxCtrl(ctx: pointer, cmd: cint, larg: clong,
    parg: pointer): clong {.importc: "SSL_CTX_ctrl".}
proc sslCtrl(ssl: pointer, cmd: cint, larg: clong,
    parg: pointer): clong {.importc: "SSL_ctrl".}
{.pop.}

proc enableKtlsOnCtx*(ctx: pointer,
    extraOps: uint64 = 0): uint64 {.discardable.} =
  ## Set `SSL_OP_ENABLE_KTLS` (plus `extraOps`, e.g.
  ## `SslOpEnableKtlsTxZerocopySendfile`) on an `SSL_CTX*`.
  ## Returns the resulting options mask.
  uint64(sslCtxCtrl(ctx, cint(SslCtrlOptions),
    clong(SslOpEnableKtls or extraOps), nil))

proc enableKtlsOnConn*(ssl: pointer,
    extraOps: uint64 = 0): uint64 {.discardable.} =
  ## Set `SSL_OP_ENABLE_KTLS` (plus `extraOps`) on a per-connection `SSL*`.
  ## Returns the resulting options mask.
  uint64(sslCtrl(ssl, cint(SslCtrlOptions),
    clong(SslOpEnableKtls or extraOps), nil))
