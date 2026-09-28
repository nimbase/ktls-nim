<p align="center">
  Linux kernel TLS (kTLS) offload for Nim — low-level C-style wrapper plus high-level API<br>
</p>

<p align="center">
  <code>nimble install ktls</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/ktls/">API reference</a><br>
  <img src="https://github.com/nimbase/ktls/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/ktls/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- **Two layers, one package.** `ktls/raw` is a 1:1 C-style mapping of
  `linux/tls.h` (constants, packed structs, raw `setsockopt` wrappers —
  no validation, no exceptions). Everything else builds on it with a
  safe, raising API.
- **High-level session API over raw socket fds.** `enableKtls`,
  `setTx` / `setRx`, TX/RX state read-back and `is*Offloaded` probes.
  Key lengths are validated before any syscall, and kernel errors map
  to `KtlsError` — including TLS 1.3 `KeyUpdate` pauses, which surface
  as the distinct `KtlsKeyUpdateNeeded` exception instead of a bare
  `EKEYEXPIRED`.
- **All 8 kernel ciphers, TLS 1.2 + 1.3.** AES-GCM 128/256, AES-CCM 128,
  ChaCha20-Poly1305, SM4-GCM, SM4-CCM, ARIA-GCM 128/256 — with the
  kernel's quirks (empty ChaCha salt, ARIA is 1.2-only, split
  salt/iv nonce layout) handled for you.
- **TLS 1.3 key schedule (RFC 8446 §7.1–7.2).** `HKDF-Expand-Label`,
  traffic key/IV derivation and `traffic upd` secret rotation, powered
  by pure-Nim `nimcypher` — no `libssl` needed for key derivation.
- **OpenSSL interop, two ways.** Let OpenSSL drive kTLS itself via
  `SSL_OP_ENABLE_KTLS`, or do the handshake anywhere and install
  keys manually from an NSS keylog (`CLIENT/SERVER_TRAFFIC_SECRET_0`
  parsing + client/server role split included).
- **Tested against reality.** RFC 8448 handshake vectors, an
  independent Python/OpenSSL cross-check of every derivation, and a
  live loopback test that encrypts through the real kernel (skips
  gracefully where kTLS is unavailable).

## Examples
Offload a connected TCP socket with manually supplied key material.
After `setTx` / `setRx`, plain `send` / `recv` on the fd carry
plaintext — the kernel frames the TLS records.

```nim
import std/net
import ktls/session

let sock = newSocket()
sock.connect("example.com", Port(443))
let fd = sock.getFd()

enableKtls(fd)  # attach the "tls" ULP (needs an established TCP socket)

let txKeys = initKeyMaterial(csAesGcm128, tv12, txKey, txIv, txSalt)
let rxKeys = initKeyMaterial(csAesGcm128, tv12, rxKey, rxIv, rxSalt)
setTx(fd, txKeys)  # kernel encrypts everything sent from here on
setRx(fd, rxKeys)  # kernel decrypts everything received
```

Derive TLS 1.3 keys from an NSS keylog and handle `KeyUpdate`
(`roleKeyMaterial` picks TX/RX secrets by endpoint — a client
transmits with the client secret, a server with the server secret):

```nim
import ktls/session
import ktls/tls13
import ktls/openssl/keylog

var secrets = parseKeylog(readFile("keylog.txt"))
secrets.suite = parseTls13Suite("TLS_AES_128_GCM_SHA256")  # from SSL_get_cipher_name
let (tx, rx) = roleKeyMaterial(secrets, amClient = true)
setTx(fd, tx)
setRx(fd, rx)

# ... on KtlsKeyUpdateNeeded (peer sent KeyUpdate):
let next = nextTrafficSecret(secrets.serverSecret, 32)  # 32 = SHA-256, 48 = SHA-384
updateRxKey(fd, trafficKeyMaterial(next, secrets.suite))
```

Or skip manual keys entirely and let an `enable-ktls` OpenSSL build
offload its own connections — just set the flag before the handshake:

```nim
import ktls/openssl

discard enableKtlsOnCtx(ctx)  # SSL_CTX*, optionally + SslOpEnableKtlsTxZerocopySendfile
# ... SSL_connect / SSL_accept as usual; the kernel takes the record layer
```

Run the suite with `clue test` (`t_integration` needs `sudo modprobe tls`
and skips otherwise).

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/ktls/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/ktls/fork)

### 🎩 License
MIT license | Nim Community.
