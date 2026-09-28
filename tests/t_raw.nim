import std/unittest
import std/posix

import ktls/raw

test "constants mirror linux/tls.h":
  check SolTls == 282
  check TcpUlp == 31
  check TlsTx == 1
  check TlsRx == 2
  check TlsTxZerocopyRo == 3
  check TlsRxExpectNoPad == 4
  check TlsTxMaxPayloadLen == 5
  check Tls12Version == 0x0303
  check Tls13Version == 0x0304
  check TlsCipherAesGcm128 == 51
  check TlsCipherAesGcm256 == 52
  check TlsCipherAesCcm128 == 53
  check TlsCipherChacha20Poly1305 == 54
  check TlsCipherSm4Gcm == 55
  check TlsCipherSm4Ccm == 56
  check TlsCipherAriaGcm128 == 57
  check TlsCipherAriaGcm256 == 58

test "struct sizes match the kernel ABI":
  check sizeof(TlsCryptoInfo) == 4
  check sizeof(Tls12CryptoInfoAesGcm128) == 40
  check sizeof(Tls12CryptoInfoAesGcm256) == 56
  check sizeof(Tls12CryptoInfoAesCcm128) == 40
  check sizeof(Tls12CryptoInfoChacha20Poly1305) == 56
  check sizeof(Tls12CryptoInfoSm4Gcm) == 40
  check sizeof(Tls12CryptoInfoSm4Ccm) == 40
  check sizeof(Tls12CryptoInfoAriaGcm128) == 40
  check sizeof(Tls12CryptoInfoAriaGcm256) == 56

test "field offsets match the C layout":
  check offsetof(Tls12CryptoInfoAesGcm128, info) == 0
  check offsetof(Tls12CryptoInfoAesGcm128, iv) == 4
  check offsetof(Tls12CryptoInfoAesGcm128, key) == 12
  check offsetof(Tls12CryptoInfoAesGcm128, salt) == 28
  check offsetof(Tls12CryptoInfoAesGcm128, recSeq) == 32
  check offsetof(Tls12CryptoInfoAesGcm256, key) == 12
  check offsetof(Tls12CryptoInfoAesGcm256, salt) == 44
  check offsetof(Tls12CryptoInfoAesGcm256, recSeq) == 48
  check offsetof(Tls12CryptoInfoChacha20Poly1305, iv) == 4
  check offsetof(Tls12CryptoInfoChacha20Poly1305, key) == 16
  check offsetof(Tls12CryptoInfoChacha20Poly1305, recSeq) == 48

test "rawEnableUlp fails cleanly on a bad fd":
  check rawEnableUlp(SocketHandle(-1)) == -1
