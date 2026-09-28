import std/unittest
import std/posix

import ktls/types
import ktls/errors
import ktls/session

test "cipher dimension table":
  check csAesGcm128.keyLen == 16
  check csAesGcm256.keyLen == 32
  check csChacha20Poly1305.keyLen == 32
  check csAesCcm128.ivLen == 8
  check csChacha20Poly1305.ivLen == 12
  check csChacha20Poly1305.saltLen == 0
  check csAesGcm128.saltLen == 4

test "initKeyMaterial accepts good material":
  let km = initKeyMaterial(csAesGcm128, tv12,
    newSeq[byte](16), newSeq[byte](8), newSeq[byte](4))
  check km.cipherType == 51
  check km.versionNumber == 0x0303
  let kc = initKeyMaterial(csChacha20Poly1305, tv13,
    newSeq[byte](32), newSeq[byte](12), newSeq[byte](0))
  check kc.cipherType == 54

test "initKeyMaterial rejects bad lengths":
  expect KtlsError:
    discard initKeyMaterial(csAesGcm128, tv12,
      newSeq[byte](32), newSeq[byte](8), newSeq[byte](4)) # wrong key
  expect KtlsError:
    discard initKeyMaterial(csAesGcm128, tv12,
      newSeq[byte](16), newSeq[byte](12), newSeq[byte](4)) # wrong iv
  expect KtlsError:
    discard initKeyMaterial(csAesGcm128, tv12,
      newSeq[byte](16), newSeq[byte](8), newSeq[byte](0)) # wrong salt
  expect KtlsError:
    discard initKeyMaterial(csChacha20Poly1305, tv13,
      newSeq[byte](32), newSeq[byte](12), newSeq[byte](4)) # salt must be empty

test "ARIA requires TLS 1.2":
  expect KtlsError:
    discard initKeyMaterial(csAriaGcm128, tv13,
      newSeq[byte](16), newSeq[byte](8), newSeq[byte](4))
  discard initKeyMaterial(csAriaGcm128, tv12,
    newSeq[byte](16), newSeq[byte](8), newSeq[byte](4))

test "session calls raise KtlsError on a bad fd":
  expect KtlsError:
    enableKtls(SocketHandle(-1))
  let km = initKeyMaterial(csAesGcm128, tv12,
    newSeq[byte](16), newSeq[byte](8), newSeq[byte](4))
  expect KtlsError:
    setTx(SocketHandle(-1), km)
  expect KtlsError:
    setRx(SocketHandle(-1), km)
  check isTxOffloaded(SocketHandle(-1)) == false
  check isRxOffloaded(SocketHandle(-1)) == false

test "ensureKtls re-raises anything but EEXIST":
  # Bad fd fails with EBADF, not EEXIST — must still raise, proving
  # ensureKtls only tolerates an already-attached ULP.
  expect KtlsError:
    ensureKtls(SocketHandle(-1))
