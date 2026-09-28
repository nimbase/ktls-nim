# ktls — Linux kernel TLS (kTLS) offload for Nim.
#
# Layer 1 (`ktls/raw`): 1:1 C-style mapping of `linux/tls.h`, raw fds,
# no exceptions. Layer 2 (`ktls/session`, `ktls/tls13`, `ktls/openssl`):
# validated key material, TLS 1.3 key schedule (RFC 8446), OpenSSL
# interop — still over raw socket fds.

import ktls/raw
import ktls/types
import ktls/errors
import ktls/session
import ktls/tls13
import ktls/openssl
import ktls/openssl/keylog

export raw
export types
export errors
export session
export tls13
export openssl
export keylog
