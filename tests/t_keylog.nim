import std/unittest

import ktls/openssl/keylog
import ktls/tls13

test "keylog parsing picks out traffic secrets":
  var s: TrafficSecrets
  parseKeylogLine("# SSLKEYLOGFILE", s)
  parseKeylogLine("", s)
  parseKeylogLine("CLIENT_RANDOM 4b99d2cabd7e6c2dc95858f4718d264d4c5e14a8c8ec04397b08dcb8aa6f26d1 8d0f1e2d7b12583af4c1a06b5226c00b7bb90582f3c8b3f0a4e2bb4463633fbbd66", s)
  check s.haveClient == false
  check s.haveServer == false
  parseKeylogLine("CLIENT_TRAFFIC_SECRET_0 4b99d2cabd7e6c2dc95858f4718d264d4c5e14a8c8ec04397b08dcb8aa6f26d1 9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5", s)
  parseKeylogLine("SERVER_TRAFFIC_SECRET_0 4b99d2cabd7e6c2dc95858f4718d264d4c5e14a8c8ec04397b08dcb8aa6f26d1 a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643", s)
  check s.haveClient
  check s.haveServer
  check s.clientSecret.len == 32
  check s.serverSecret.len == 32

test "malformed traffic-secret lines raise":
  var s: TrafficSecrets
  expect ValueError:
    parseKeylogLine("CLIENT_TRAFFIC_SECRET_0 abcUsingOdd def", s)

test "role split assigns TX/RX by endpoint":
  var s = parseKeylog(
    "CLIENT_TRAFFIC_SECRET_0 00 9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5\n" &
    "SERVER_TRAFFIC_SECRET_0 00 a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643\n")
  s.suite = tlsAes128GcmSha256
  let asClient = roleKeyMaterial(s, amClient = true)
  let asServer = roleKeyMaterial(s, amClient = false)
  # Client TX == server RX and vice versa.
  check asClient.tx.key == asServer.rx.key
  check asClient.rx.key == asServer.tx.key
  # Spot-check against the RFC 8448 §3 application keys.
  check asServer.tx.key == @[0x9f'u8, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07,
    0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56]

test "missing secrets raise":
  var s: TrafficSecrets
  s.suite = tlsAes128GcmSha256
  expect ValueError:
    discard roleKeyMaterial(s, amClient = true)
