# Error types and errno-mapping helpers for `ktls`.

import std/os
import ./raw

export raw.EKeyExpired

type
  KtlsError* = object of OSError
    ## Raised for any kTLS setup or usage failure. Inherits `OSError`,
    ## so `errorCode` holds the errno and `msg` is human-readable.
  KtlsKeyUpdateNeeded* = object of KtlsError
    ## A TLS 1.3 `KeyUpdate` arrived and the kernel paused decryption.
    ## Reads fail with `EKEYEXPIRED` until the new RX key is installed
    ## via `session.updateRxKey`; `poll` reports no read events meanwhile.

proc raiseKtls*(msg: string, code = OSErrorCode(-1)) =
  ## Raise `KtlsError`, defaulting the code to the last OS error.
  let c = if int32(code) == -1: osLastError() else: code
  var e = newException(KtlsError, msg & ": " & osErrorMsg(c))
  e.errorCode = int32(c)
  raise e

proc checkKtls*(rc: cint, what: string) =
  ## Raise `KtlsError` when a raw syscall returned `-1`.
  ## Maps `EKEYEXPIRED` to `KtlsKeyUpdateNeeded`.
  if rc == 0:
    return
  let code = osLastError()
  if int32(code) == EKeyExpired:
    var e = newException(KtlsKeyUpdateNeeded,
      what & ": peer sent KeyUpdate, install the new RX key: " & osErrorMsg(code))
    e.errorCode = int32(code)
    raise e
  raiseKtls(what, code)
