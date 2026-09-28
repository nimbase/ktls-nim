# Low-level 1:1 mapping of the Linux kernel TLS (kTLS) ABI (`linux/tls.h`).
#
# This module is deliberately C-style: constants mirror the header values,
# structs match the kernel layout byte-for-byte, and every proc returns the
# raw `setsockopt`/`getsockopt` result (`0` on success, `-1` on error with
# `errno` set). No validation, no exceptions — see `session.nim` for the
# safe wrapper.

import std/posix

export SocketHandle

const
  SolTls* = 282
    ## `SOL_TLS` socket level for `setsockopt`/`getsockopt`.
  IpProtoTcp* = 6
    ## `IPPROTO_TCP`: level used to attach the TLS ULP (`TCP_ULP`).
  TcpUlp* = 31
    ## `TCP_ULP`: attach a Upper Layer Protocol to a TCP socket.

  TlsTx* = 1
    ## Move the transmit (encrypt) path into the kernel.
  TlsRx* = 2
    ## Move the receive (decrypt) path into the kernel.
  TlsTxZerocopyRo* = 3
    ## TX zerocopy, read-only (sendfile only).
  TlsRxExpectNoPad* = 4
    ## Attempt opportunistic zero-copy on receive.
  TlsTxMaxPayloadLen* = 5
    ## Cap the maximum plaintext size per record.

  Tls12Version* = 0x0303
  Tls13Version* = 0x0304

  TlsCipherAesGcm128* = 51
  TlsCipherAesGcm256* = 52
  TlsCipherAesCcm128* = 53
  TlsCipherChacha20Poly1305* = 54
  TlsCipherSm4Gcm* = 55
  TlsCipherSm4Ccm* = 56
  TlsCipherAriaGcm128* = 57
  TlsCipherAriaGcm256* = 58

  # `TLS_INFO_*` (`linux/tls.h` enum) are *netlink diag* attributes
  # (`INET_ULP_INFO_TLS`, see `ss -t -o`), not `getsockopt` option names.
  # State read-back uses `rawGetTx`/`rawGetRx` below.

  EKeyExpired* = 127
    ## `EKEYEXPIRED`: read-after-KeyUpdate until the new RX key is installed
    ## (TLS 1.3). Not in Nim's `posix`, defined here for convenience.

type
  TlsCryptoInfo* {.packed.} = object
    ## Corresponds to `struct tls_crypto_info`.
    version*: uint16
    cipherType*: uint16

  Tls12CryptoInfoAesGcm128* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[16, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoAesGcm256* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[32, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoAesCcm128* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[16, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoChacha20Poly1305* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[12, uint8]
    key*: array[32, uint8]
    # `salt` is zero-length in C; kept as a zero-size field so generic
    # code can still refer to it uniformly.
    salt*: array[0, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoSm4Gcm* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[16, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoSm4Ccm* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[16, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoAriaGcm128* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[16, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

  Tls12CryptoInfoAriaGcm256* {.packed.} = object
    info*: TlsCryptoInfo
    iv*: array[8, uint8]
    key*: array[32, uint8]
    salt*: array[4, uint8]
    recSeq*: array[8, uint8]

static:
  # Kernel ABI sizes: 4-byte header + iv + key + salt + 8-byte record seq.
  assert sizeof(TlsCryptoInfo) == 4
  assert sizeof(Tls12CryptoInfoAesGcm128) == 40
  assert sizeof(Tls12CryptoInfoAesGcm256) == 56
  assert sizeof(Tls12CryptoInfoAesCcm128) == 40
  assert sizeof(Tls12CryptoInfoChacha20Poly1305) == 56
  assert sizeof(Tls12CryptoInfoSm4Gcm) == 40
  assert sizeof(Tls12CryptoInfoSm4Ccm) == 40
  assert sizeof(Tls12CryptoInfoAriaGcm128) == 40
  assert sizeof(Tls12CryptoInfoAriaGcm256) == 56

proc rawEnableUlp*(fd: SocketHandle): cint =
  ## Attach the `"tls"` ULP: `setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls")`.
  ## Must be called on an established TCP socket before `rawSetTx`/`rawSetRx`.
  ## Returns `0` on success, `-1` on error.
  var ulpName: array[4, char] = ['t', 'l', 's', '\0']
  posix.setsockopt(fd, cint(IpProtoTcp), cint(TcpUlp),
    addr ulpName[0], SockLen(ulpName.len))

proc rawSetTx*(fd: SocketHandle, cryptoInfo: pointer, infoLen: SockLen): cint =
  ## Install transmit crypto state: `setsockopt(fd, SOL_TLS, TLS_TX, ...)`.
  ## `cryptoInfo` must point at one of the `Tls12CryptoInfo*` structs and
  ## `infoLen` must be its size. Returns `0` on success, `-1` on error.
  posix.setsockopt(fd, cint(SolTls), cint(TlsTx), cryptoInfo, infoLen)

proc rawSetRx*(fd: SocketHandle, cryptoInfo: pointer, infoLen: SockLen): cint =
  ## Install receive crypto state: `setsockopt(fd, SOL_TLS, TLS_RX, ...)`.
  ## Same buffer contract as `rawSetTx`. Returns `0` on success, `-1` on error.
  posix.setsockopt(fd, cint(SolTls), cint(TlsRx), cryptoInfo, infoLen)

proc rawSetTxZerocopyRo*(fd: SocketHandle, enable: bool): cint =
  ## Toggle TX zerocopy (sendfile) mode. The kernel takes a 4-byte
  ## `unsigned int` flag (`0`/`1`). Returns `0` on success, `-1` on error.
  var v: uint32 = if enable: 1 else: 0
  posix.setsockopt(fd, cint(SolTls), cint(TlsTxZerocopyRo),
    addr v, SockLen(sizeof(v)))

proc rawSetRxExpectNoPad*(fd: SocketHandle, enable: bool): cint =
  ## Hint the kernel to attempt opportunistic zero-copy on receive.
  ## The kernel takes a 4-byte flag (`0`/`1`) and requires TLS 1.3 with
  ## RX already configured — call after `rawSetRx`. Returns `0`/`-1`.
  var v: uint32 = if enable: 1 else: 0
  posix.setsockopt(fd, cint(SolTls), cint(TlsRxExpectNoPad),
    addr v, SockLen(sizeof(v)))

proc rawSetTxMaxPayloadLen*(fd: SocketHandle, maxLen: uint16): cint =
  ## Cap the maximum plaintext payload per TLS record (2-byte value,
  ## kernel-validated range, at most 16384). Fails with `EBUSY` while a
  ## record is open. Returns `0` on success, `-1` on error.
  var v = maxLen
  posix.setsockopt(fd, cint(SolTls), cint(TlsTxMaxPayloadLen),
    addr v, SockLen(sizeof(v)))

proc rawGetTx*(fd: SocketHandle, buf: pointer, len: var SockLen): cint =
  ## Read back the installed TX crypto state (`getsockopt(SOL_TLS, TLS_TX)`).
  ## Fails (non-zero return) when no TX state is installed.
  posix.getsockopt(fd, cint(SolTls), cint(TlsTx), buf, addr len)

proc rawGetRx*(fd: SocketHandle, buf: pointer, len: var SockLen): cint =
  ## Read back the installed RX crypto state (`getsockopt(SOL_TLS, TLS_RX)`).
  ## Fails (non-zero return) when no RX state is installed.
  posix.getsockopt(fd, cint(SolTls), cint(TlsRx), buf, addr len)
