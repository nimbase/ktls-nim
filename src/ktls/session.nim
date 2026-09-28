# Safe high-level kTLS session API over a raw socket fd.
#
# Typical flow (handshake already completed in userspace, e.g. OpenSSL):
#
#   enableKtls(fd)          # attach the "tls" ULP (needs ESTABLISHED TCP)
#   setTx(fd, txKeys)       # kernel encrypts everything `send`n afterwards
#   setRx(fd, rxKeys)       # kernel decrypts everything `recv` returns
#
# After offload, `send`/`recv` on the fd carry plaintext; the kernel
# frames records. TX and RX are independent — enable either or both.
# For TLS 1.3 `KeyUpdate`, re-install with `updateTxKey`/`updateRxKey`
# (version and cipher must stay the same).

import std/posix
import ./raw
import ./errors
import ./types

export raw.SocketHandle
export types
export errors

proc enableKtls*(fd: SocketHandle) =
  ## Attach the `"tls"` ULP to an established TCP socket. Must precede
  ## `setTx`/`setRx`.
  ##
  ## Raises `KtlsError`: `ENOPROTOOPT`/`ENOENT` means the kernel lacks
  ## kTLS; `ENOTCONN` means the socket is not an established TCP socket.
  checkKtls(rawEnableUlp(fd), "enable kTLS ULP")

proc ensureKtls*(fd: SocketHandle) =
  ## Like `enableKtls`, but tolerates an already-attached `"tls"` ULP
  ## (`EEXIST`). This happens when the TLS library itself offloaded the
  ## connection first — e.g. distro OpenSSL builds with kTLS support
  ## engage it during the handshake without being asked. In that case
  ## the ULP is already what we want; just proceed to `setTx`/`setRx`
  ## (on TLS 1.3, re-installing keys is the normal KeyUpdate path).
  try:
    enableKtls(fd)
  except KtlsError as e:
    if e.errorCode != int32(EEXIST):
      raise

template withCrypto(km: KeyMaterial, name, body: untyped) =
  ## Serialize `km` into the matching packed struct, then run `body`
  ## with `name` bound to it.
  case km.cipher
  of csAesGcm128:
    var name = Tls12CryptoInfoAesGcm128(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 16: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csAesGcm256:
    var name = Tls12CryptoInfoAesGcm256(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 32: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csAesCcm128:
    var name = Tls12CryptoInfoAesCcm128(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 16: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csChacha20Poly1305:
    var name = Tls12CryptoInfoChacha20Poly1305(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 12: name.iv[i] = km.iv[i]
    for i in 0 ..< 32: name.key[i] = km.key[i]
    name.recSeq = km.recSeq
    body
  of csSm4Gcm:
    var name = Tls12CryptoInfoSm4Gcm(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 16: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csSm4Ccm:
    var name = Tls12CryptoInfoSm4Ccm(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 16: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csAriaGcm128:
    var name = Tls12CryptoInfoAriaGcm128(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 16: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body
  of csAriaGcm256:
    var name = Tls12CryptoInfoAriaGcm256(info: TlsCryptoInfo(
      version: km.versionNumber, cipherType: km.cipherType))
    for i in 0 ..< 8: name.iv[i] = km.iv[i]
    for i in 0 ..< 32: name.key[i] = km.key[i]
    for i in 0 ..< 4: name.salt[i] = km.salt[i]
    name.recSeq = km.recSeq
    body

proc setTx*(fd: SocketHandle, km: KeyMaterial) =
  ## Install transmit keys: subsequent `send`s are encrypted by the kernel.
  ## Raises `KtlsError` (`EBUSY` if TX is already installed and the
  ## version is not TLS 1.3 — use `updateTxKey` for 1.3 rekeying).
  withCrypto(km, ci):
    checkKtls(rawSetTx(fd, addr ci, SockLen(sizeof(ci))), "install kTLS TX")

proc setRx*(fd: SocketHandle, km: KeyMaterial) =
  ## Install receive keys: subsequent `recv`s return kernel-decrypted
  ## plaintext. Raises `KtlsError` (see `setTx` for rekeying).
  withCrypto(km, ci):
    checkKtls(rawSetRx(fd, addr ci, SockLen(sizeof(ci))), "install kTLS RX")

proc updateTxKey*(fd: SocketHandle, km: KeyMaterial) =
  ## TLS 1.3 KeyUpdate on the transmit path. Same syscall as `setTx`;
  ## the kernel rejects version/cipher changes with `EINVAL`.
  setTx(fd, km)

proc updateRxKey*(fd: SocketHandle, km: KeyMaterial) =
  ## TLS 1.3 KeyUpdate on the receive path: unblocks reads paused with
  ## `EKEYEXPIRED` (`KtlsKeyUpdateNeeded`). Same constraints as `setRx`.
  setRx(fd, km)

proc txConf*(fd: SocketHandle): tuple[version: TlsVersion, cipher: CipherSuite] =
  ## Read back the installed TX state (4-byte header `getsockopt`).
  ## Raises `KtlsError` when no TX state is installed.
  var hdr: TlsCryptoInfo
  var len = SockLen(sizeof(hdr))
  checkKtls(rawGetTx(fd, addr hdr, len), "read kTLS TX conf")
  (TlsVersion(hdr.version), CipherSuite(hdr.cipherType))

proc rxConf*(fd: SocketHandle): tuple[version: TlsVersion, cipher: CipherSuite] =
  ## Read back the installed RX state. Raises `KtlsError` when absent.
  var hdr: TlsCryptoInfo
  var len = SockLen(sizeof(hdr))
  checkKtls(rawGetRx(fd, addr hdr, len), "read kTLS RX conf")
  (TlsVersion(hdr.version), CipherSuite(hdr.cipherType))

proc isTxOffloaded*(fd: SocketHandle): bool =
  ## True when TX crypto state is installed.
  try:
    discard txConf(fd)
    true
  except KtlsError:
    false

proc isRxOffloaded*(fd: SocketHandle): bool =
  ## True when RX crypto state is installed.
  try:
    discard rxConf(fd)
    true
  except KtlsError:
    false

proc setTxZerocopy*(fd: SocketHandle, enable: bool) =
  ## Toggle TX zerocopy (sendfile) mode. Raises `KtlsError` on failure.
  checkKtls(rawSetTxZerocopyRo(fd, enable), "set kTLS TX zerocopy")

proc setRxExpectNoPad*(fd: SocketHandle, enable: bool) =
  ## Request opportunistic zero-copy on receive. Requires TLS 1.3 with
  ## RX already installed — call after `setRx`. Raises `KtlsError`.
  checkKtls(rawSetRxExpectNoPad(fd, enable), "set kTLS RX no-pad")

proc setTxMaxPayloadLen*(fd: SocketHandle, maxLen: uint16) =
  ## Cap plaintext bytes per record (kernel-validated, at most 16384).
  ## Raises `KtlsError` (`EBUSY` while a record is open).
  checkKtls(rawSetTxMaxPayloadLen(fd, maxLen), "set kTLS TX max payload")
