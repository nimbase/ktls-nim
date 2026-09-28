import std/unittest
import std/strutils

import ktls/tls13
import ktls/types

proc hexToBytes(s: string): seq[byte] =
  doAssert s.len mod 2 == 0, "odd-length hex vector"
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

test "RFC 8448 §3 server application traffic (AES-128-GCM-SHA256)":
  let secret = hexToBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
  check trafficKey(secret, 32, 16) ==
    hexToBytes("9f02283b6c9c07efc26bb9f2ac92e356")
  check trafficIv(secret, 32) ==
    hexToBytes("cf782b88dd83549aadf1e984")

test "RFC 8448 §3 client application traffic":
  let secret = hexToBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
  check trafficKey(secret, 32, 16) ==
    hexToBytes("17422dda596ed5d9acd890e3c63f5051")
  check trafficIv(secret, 32) ==
    hexToBytes("5b78923dee08579033e523d9")

test "RFC 8448 §3 server handshake traffic key/iv":
  let secret = hexToBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
  check trafficKey(secret, 32, 16) ==
    hexToBytes("3fce516009c21727d0f2e4e86ee403bc")
  check trafficIv(secret, 32) ==
    hexToBytes("5d313eb2671276ee13000b30")

test "KeyUpdate advances the secret (independent Python reference)":
  let serverAp = hexToBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
  check nextTrafficSecret(serverAp, 32) ==
    hexToBytes("51921b8aa3001976eb401d0a4319a8516416a6c56001a357e5d162031e84f916")
  let clientAp = hexToBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
  check nextTrafficSecret(clientAp, 32) ==
    hexToBytes("fcdfcc72725aaee48bf64e4fd8b749cdbdbab39d90da0b26e2245ca6ea167207")

test "toKeyMaterial splits the IV into salt + explicit part":
  let secret = hexToBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
  let km = toKeyMaterial(tlsAes128GcmSha256, secret)
  check km.version == tv13
  check km.cipher == csAesGcm128
  check km.key == hexToBytes("9f02283b6c9c07efc26bb9f2ac92e356")
  check km.salt == hexToBytes("cf782b88")
  check km.iv == hexToBytes("dd83549aadf1e984")

test "toKeyMaterial keeps the full IV for ChaCha20-Poly1305":
  let secret = hexToBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
  let km = toKeyMaterial(tlsChacha20Poly1305Sha256, secret)
  check km.iv.len == 12
  check km.salt.len == 0

test "suite parsing":
  check parseTls13Suite("TLS_AES_128_GCM_SHA256") == tlsAes128GcmSha256
  check parseTls13Suite("TLS_AES_256_GCM_SHA384") == tlsAes256GcmSha384
  check parseTls13Suite("TLS_CHACHA20_POLY1305_SHA256") ==
    tlsChacha20Poly1305Sha256
  expect ValueError:
    discard parseTls13Suite("TLS_RSA_WITH_RC4_128_MD5")
  expect ValueError:
    discard hkdfExpandLabel([byte 1], "key", [], 16, 20)
