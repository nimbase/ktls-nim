# TLS 1.3 key schedule helpers (RFC 8446 §7.1–7.2) for kTLS offload.
#
# After a userspace handshake, the traffic secrets (e.g. from an NSS
# keylog, see `openssl/keylog.nim`) are expanded into the key/IV the
# kernel needs:
#
#   key = HKDF-Expand-Label(secret, "key", "", keyLen)
#   iv  = HKDF-Expand-Label(secret, "iv", "", 12)
#
# KeyUpdate (§7.2): `nextTrafficSecret(secret) =
# HKDF-Expand-Label(secret, "traffic upd", "", HashLen)`, then re-arm
# the kernel with `session.updateTxKey`/`updateRxKey`.

import nimcypher/hash as nimHash
import ./types

type
  Tls13Suite* = enum
    tlsAes128GcmSha256
      ## `TLS_AES_128_GCM_SHA256` (HKDF-SHA-256).
    tlsAes256GcmSha384
      ## `TLS_AES_256_GCM_SHA384` (HKDF-SHA-384).
    tlsChacha20Poly1305Sha256
      ## `TLS_CHACHA20_POLY1305_SHA256` (HKDF-SHA-256).

proc suiteCipher*(s: Tls13Suite): CipherSuite =
  case s
  of tlsAes128GcmSha256: csAesGcm128
  of tlsAes256GcmSha384: csAesGcm256
  of tlsChacha20Poly1305Sha256: csChacha20Poly1305

proc suiteHashLen*(s: Tls13Suite): Natural =
  case s
  of tlsAes128GcmSha256, tlsChacha20Poly1305Sha256: 32
  of tlsAes256GcmSha384: 48

proc parseTls13Suite*(name: string): Tls13Suite =
  ## Parse an OpenSSL-style suite name (`TLS_AES_128_GCM_SHA256`, …).
  case name
  of "TLS_AES_128_GCM_SHA256": tlsAes128GcmSha256
  of "TLS_AES_256_GCM_SHA384": tlsAes256GcmSha384
  of "TLS_CHACHA20_POLY1305_SHA256": tlsChacha20Poly1305Sha256
  else: raise newException(ValueError, "unsupported TLS 1.3 suite: " & name)

proc hkdfExpandLabel*(secret: openArray[byte], label: string,
    context: openArray[byte], outLen: Natural, hashLen: Natural): seq[byte] =
  ## `HKDF-Expand-Label(Secret, Label, Context, Length)` with the
  ## `"tls13 "` prefix. `hashLen` selects SHA-256 (32) or SHA-384 (48).
  let fullLabel = "tls13 " & label
  var hkdfLabel = newSeq[byte](2 + 1 + fullLabel.len + 1 + context.len)
  hkdfLabel[0] = byte(outLen shr 8)
  hkdfLabel[1] = byte(outLen and 0xFF)
  hkdfLabel[2] = byte(fullLabel.len)
  for i, c in fullLabel:
    hkdfLabel[3 + i] = byte(c)
  hkdfLabel[3 + fullLabel.len] = byte(context.len)
  for i, b in context:
    hkdfLabel[4 + fullLabel.len + i] = b
  case hashLen
  of 32: nimHash.hkdfExpandSha256(secret, hkdfLabel, outLen)
  of 48: nimHash.hkdfExpandSha384(secret, hkdfLabel, outLen)
  else: raise newException(ValueError,
    "hashLen must be 32 (SHA-256) or 48 (SHA-384)")

proc trafficKey*(secret: openArray[byte], hashLen: Natural,
    keyLen: Natural): seq[byte] =
  ## Derive the `key` for a traffic secret.
  hkdfExpandLabel(secret, "key", [], keyLen, hashLen)

proc trafficIv*(secret: openArray[byte], hashLen: Natural): array[12, byte] =
  ## Derive the 12-byte `iv` for a traffic secret.
  let iv = hkdfExpandLabel(secret, "iv", [], 12, hashLen)
  for i in 0 ..< 12: result[i] = iv[i]

proc nextTrafficSecret*(secret: openArray[byte], hashLen: Natural): seq[byte] =
  ## Advance a traffic secret on `KeyUpdate` (RFC 8446 §7.2).
  hkdfExpandLabel(secret, "traffic upd", [], hashLen, hashLen)

proc toKeyMaterial*(suite: Tls13Suite, secret: openArray[byte],
    recSeq: array[8, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0]): KeyMaterial =
  ## Expand a TLS 1.3 traffic secret into kernel `KeyMaterial`, splitting
  ## the 12-byte IV into the kernel's `salt` + `iv` layout
  ## (ChaCha20-Poly1305 keeps the full 12-byte IV, empty salt).
  let cipher = suite.suiteCipher
  let hashLen = suite.suiteHashLen
  let key = trafficKey(secret, hashLen, cipher.keyLen)
  let iv12 = trafficIv(secret, hashLen)
  case cipher
  of csChacha20Poly1305:
    initKeyMaterial(cipher, tv13, key, iv12, [], recSeq)
  else:
    initKeyMaterial(cipher, tv13, key, iv12.toOpenArray(4, 11),
      iv12.toOpenArray(0, 3), recSeq)
