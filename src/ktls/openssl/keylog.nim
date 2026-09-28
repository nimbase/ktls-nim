# NSS keylog parsing for manual kTLS offload.
#
# Point OpenSSL at a keylog (`SSL_CTX_set_keylog_callback`) or set
# `SSLKEYLOGFILE`, complete the handshake, then feed the
# `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` lines here:
#
#   for line in lines(keylogPath):
#     let e = parseKeylogLine(line)   # raises on malformed lines
#     ...
#   let txm = trafficKeyMaterial(txSecret, suite, isClientTxSeq...)
#
# Which secret is TX depends on the endpoint role: a client transmits
# with `CLIENT_TRAFFIC_SECRET_0` and receives with
# `SERVER_TRAFFIC_SECRET_0`; a server does the opposite. Use `splitRole`
# to pick them out of a parsed log.

import std/strutils
import ../tls13
import ../types

export tls13
export types

type
  TrafficSecrets* = object
    ## TLS 1.3 traffic secrets captured from a keylog.
    ## Note: keylog lines carry no suite name — set `suite` yourself
    ## from the negotiated cipher (e.g. OpenSSL's
    ## `SSL_get_cipher_name`) before calling `roleKeyMaterial`.
    clientSecret*: seq[byte]
    serverSecret*: seq[byte]
    suite*: Tls13Suite
    haveClient*: bool
    haveServer*: bool

proc hexBytes(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newException(ValueError, "odd-length hex in keylog")
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc parseKeylogLine*(line: string, secrets: var TrafficSecrets) =
  ## Fold one NSS keylog line into `secrets`. Recognizes
  ## `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0` (each
  ## `<label> <client_random_hex> <secret_hex>`); ignores blanks,
  ## comments (`# ...`), and other labels (handshake/early/exporter).
  ## Raises `ValueError` on malformed traffic-secret lines.
  let l = line.strip
  if l.len == 0 or l.startsWith("#"):
    return
  let parts = l.splitWhitespace
  if parts.len != 3:
    return # not a secret line; ignore
  case parts[0]
  of "CLIENT_TRAFFIC_SECRET_0":
    secrets.clientSecret = hexBytes(parts[2])
    secrets.haveClient = true
  of "SERVER_TRAFFIC_SECRET_0":
    secrets.serverSecret = hexBytes(parts[2])
    secrets.haveServer = true
  else:
    discard # CLIENT_RANDOM, handshake secrets, exporter: not needed for kTLS data path

proc parseKeylog*(text: string): TrafficSecrets =
  ## Parse a whole keylog file's contents.
  for line in text.splitLines:
    parseKeylogLine(line, result)

proc trafficKeyMaterial*(secret: openArray[byte], suite: Tls13Suite,
    recSeq: array[8, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0]): KeyMaterial =
  ## Expand a traffic secret into kernel `KeyMaterial` (`tls13.toKeyMaterial`).
  toKeyMaterial(suite, secret, recSeq)

proc roleKeyMaterial*(secrets: TrafficSecrets, amClient: bool,
    txRecSeq: array[8, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0],
    rxRecSeq: array[8, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0]
    ): tuple[tx, rx: KeyMaterial] =
  ## Split captured secrets into TX/RX `KeyMaterial` by endpoint role.
  ## Raises `ValueError` when a required secret is missing.
  if amClient:
    if not secrets.haveClient:
      raise newException(ValueError, "keylog lacks CLIENT_TRAFFIC_SECRET_0")
    if not secrets.haveServer:
      raise newException(ValueError, "keylog lacks SERVER_TRAFFIC_SECRET_0")
    (trafficKeyMaterial(secrets.clientSecret, secrets.suite, txRecSeq),
     trafficKeyMaterial(secrets.serverSecret, secrets.suite, rxRecSeq))
  else:
    if not secrets.haveServer:
      raise newException(ValueError, "keylog lacks SERVER_TRAFFIC_SECRET_0")
    if not secrets.haveClient:
      raise newException(ValueError, "keylog lacks CLIENT_TRAFFIC_SECRET_0")
    (trafficKeyMaterial(secrets.serverSecret, secrets.suite, txRecSeq),
     trafficKeyMaterial(secrets.clientSecret, secrets.suite, rxRecSeq))
