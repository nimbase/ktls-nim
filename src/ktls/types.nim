# Shared high-level types: versions, cipher suites, key material.
#
# Lengths mirror `linux/tls.h` (`*_IV_SIZE`, `*_KEY_SIZE`, `*_SALT_SIZE`).
# TLS 1.3 uses the same structs with the same field split: `salt` holds the
# implicit part of the nonce, `iv` the explicit part
# (`TLS_CIPHER_*_SALT_SIZE` + `TLS_CIPHER_*_IV_SIZE` = 12-byte nonce).

import std/os
import std/posix
import ./raw
import ./errors

type
  TlsVersion* = enum
    tv12 = Tls12Version
      ## TLS 1.2 (`0x0303`).
    tv13 = Tls13Version
      ## TLS 1.3 (`0x0304`).

  CipherSuite* = enum
    csAesGcm128 = TlsCipherAesGcm128
    csAesGcm256 = TlsCipherAesGcm256
    csAesCcm128 = TlsCipherAesCcm128
    csChacha20Poly1305 = TlsCipherChacha20Poly1305
    csSm4Gcm = TlsCipherSm4Gcm
    csSm4Ccm = TlsCipherSm4Ccm
    csAriaGcm128 = TlsCipherAriaGcm128
    csAriaGcm256 = TlsCipherAriaGcm256

  KeyMaterial* = object
    ## Validated key material for one direction. Build with
    ## `initKeyMaterial`, install with `session.setTx`/`session.setRx`.
    version*: TlsVersion
    cipher*: CipherSuite
    key*: seq[byte]
    iv*: seq[byte]
    salt*: seq[byte]
    recSeq*: array[8, byte]
      ## Record sequence number (big-endian on the wire). Starts at zero
      ## for a fresh epoch and increments per record; for TLS 1.3
      ## KeyUpdate re-arming, carry over the next expected sequence.

proc keyLen*(c: CipherSuite): Natural =
  case c
  of csAesGcm128, csAesCcm128, csSm4Gcm, csSm4Ccm, csAriaGcm128: 16
  of csAesGcm256, csChacha20Poly1305, csAriaGcm256: 32

proc ivLen*(c: CipherSuite): Natural =
  case c
  of csChacha20Poly1305: 12
  else: 8

proc saltLen*(c: CipherSuite): Natural =
  case c
  of csChacha20Poly1305: 0
  else: 4

proc initKeyMaterial*(cipher: CipherSuite, version: TlsVersion,
    key, iv, salt: openArray[byte],
    recSeq: array[8, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0]): KeyMaterial =
  ## Build validated `KeyMaterial`, raising `KtlsError` on length mismatch.
  ## The kernel additionally requires ARIA suites to use TLS 1.2
  ## (enforced here so the failure surfaces before any syscall).
  if key.len != cipher.keyLen:
    raiseKtls("key must be " & $cipher.keyLen & " bytes for " & $cipher &
      ", got " & $key.len, OSErrorCode(EINVAL))
  if iv.len != cipher.ivLen:
    raiseKtls("iv must be " & $cipher.ivLen & " bytes for " & $cipher &
      ", got " & $iv.len, OSErrorCode(EINVAL))
  if salt.len != cipher.saltLen:
    raiseKtls("salt must be " & $cipher.saltLen & " bytes for " & $cipher &
      ", got " & $salt.len, OSErrorCode(EINVAL))
  if cipher in {csAriaGcm128, csAriaGcm256} and version != tv12:
    raiseKtls("ARIA suites require TLS 1.2", OSErrorCode(EINVAL))
  KeyMaterial(version: version, cipher: cipher,
    key: @key, iv: @iv, salt: @salt, recSeq: recSeq)

proc cipherType*(km: KeyMaterial): uint16 = uint16(ord(km.cipher))
proc versionNumber*(km: KeyMaterial): uint16 = uint16(ord(km.version))
