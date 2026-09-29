<p align="center">
  Linux kernel TLS (kTLS) offload for Nim<br>
  low-level C-style wrapper & high-level API
</p>

<p align="center">
  <code>nimble install ktls</code> | <code>clue install ktls</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/ktls-nim/">API reference</a><br>
  <img src="https://github.com/nimbase/ktls-nim/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/ktls-nim/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- Two layers in one package: a thin C-style mapping of the kernel
  interface, plus a safe high-level API on top.
- Simple session handling on plain socket descriptors, with clear
  errors — including dedicated handling of TLS 1.3 key updates.
- All kernel cipher suites, for both TLS 1.2 and TLS 1.3.
- Built-in TLS 1.3 key derivation, with no OpenSSL required for it.
- Works with OpenSSL two ways: let it offload by itself, or install
  handshake keys manually from a key log.
- Tested against official specification vectors and a live kernel
  round-trip.

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
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/ktls-nim/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/ktls-nim/fork)

### 🎩 License
MIT license | Nim Community.
