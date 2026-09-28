# End-to-end: real OpenSSL 3 handshake -> NSS keylog -> manual kTLS
# offload -> plaintext round-trip through the kernel.
#
# Two tests: the handshake/keylog half needs only `libssl.so.3` and the
# `openssl` CLI (for a throwaway test certificate); the offload half
# additionally needs kernel kTLS. Each skips cleanly when its
# requirements are missing.
#
# Single-threaded by design: both handshake halves are interleaved over
# non-blocking sockets with poll, so no threads are needed.

import std/unittest
import std/net
import std/os
import std/osproc
import std/posix
import std/strutils
import std/dynlib
import std/openssl

import ktls/session
import ktls/errors
import ktls/tls13
import ktls/openssl/keylog
import ktls/openssl/ssl

var logLines: seq[string]

proc keylogCb(ssl: SslPtr, line: cstring) {.cdecl.} =
  logLines.add($line)

proc libsslPresent(): bool =
  ## Non-fatal probe: `loadLib` returns nil instead of dying, unlike a
  ## first call into a statically bound `{.dynlib.}` symbol.
  for name in ["libssl.so.3", "libssl.so.1.1"]:
    let h = loadLib(name)
    if not h.isNil:
      unloadLib(h)
      return true
  false

proc tryKtls(): bool =
  var srv = newSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(0), "127.0.0.1")
  srv.listen()
  let port = srv.getLocalAddr()[1]
  var cli = newSocket()
  cli.connect("127.0.0.1", port)
  var acc: Socket
  srv.accept(acc)
  defer:
    cli.close()
    acc.close()
    srv.close()
  try:
    enableKtls(cli.getFd())
    true
  except KtlsError:
    false

proc setNonblock(fd: SocketHandle, on: bool) =
  let fl = posix.fcntl(fd, F_GETFL, 0)
  let fl2 = if on: fl or O_NONBLOCK else: fl and not O_NONBLOCK
  assert posix.fcntl(fd, F_SETFL, fl2) != -1, "fcntl failed"

proc waitFd(fd: SocketHandle, forWrite: bool) =
  var pfd: TPollfd
  pfd.fd = fd.cint
  pfd.events = if forWrite: POLLOUT else: POLLIN
  discard posix.poll(addr pfd, 1, 5000)

proc sendAll(fd: SocketHandle, data: string) =
  var sent = 0
  while sent < data.len:
    let n = posix.send(fd, unsafeAddr data[sent], data.len - sent, 0)
    assert n > 0, "send failed"
    sent += n

proc recvExact(fd: SocketHandle, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let r = posix.recv(fd, addr result[got], n - got, 0)
    assert r > 0, "recv failed"
    got += r

type
  HandshakePair = object
    srvCtx, cliCtx: SslCtx
    cssl, sssl: SslPtr
    srv, cli, acc: Socket
    cipher: string

proc setupContexts(tmp: string): tuple[srvCtx, cliCtx: SslCtx] =
  ## Fresh TLS-1.3-only contexts with keylog capture. Throws on error.
  let srvCtx = SSL_CTX_new(TLS_server_method())
  assert not srvCtx.isNil, "SSL_CTX_new (server) failed"
  let certFile = tmp / "cert.pem"
  let keyFile = tmp / "key.pem"
  assert SSL_CTX_use_certificate_file(srvCtx, certFile.cstring,
    SSL_FILETYPE_PEM) == 1, "load test certificate failed"
  assert SSL_CTX_use_PrivateKey_file(srvCtx, keyFile.cstring,
    SSL_FILETYPE_PEM) == 1, "load test key failed"
  let cliCtx = SSL_CTX_new(TLS_client_method())
  assert not cliCtx.isNil, "SSL_CTX_new (client) failed"
  for ctx in [srvCtx, cliCtx]:
    assert SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") == 1
    pinTls13(ctx)
    sslCtxSetKeylogCallback(ctx, keylogCb)
  SSL_CTX_set_verify(cliCtx, SSL_VERIFY_NONE, nil)
  (srvCtx, cliCtx)

proc handshakePair(srvCtx, cliCtx: SslCtx): HandshakePair =
  ## Connected TCP pair with a completed handshake. Throws on error.
  result.srvCtx = srvCtx
  result.cliCtx = cliCtx
  result.srv = newSocket()
  result.srv.setSockOpt(OptReuseAddr, true)
  result.srv.bindAddr(Port(0), "127.0.0.1")
  result.srv.listen()
  let port = result.srv.getLocalAddr()[1]
  result.cli = newSocket()
  result.cli.connect("127.0.0.1", port)
  result.srv.accept(result.acc)
  let cfd = result.cli.getFd()
  let sfd = result.acc.getFd()

  result.cssl = SSL_new(cliCtx)
  result.sssl = SSL_new(srvCtx)
  assert SSL_set_fd(result.cssl, cfd) == 1
  assert SSL_set_fd(result.sssl, sfd) == 1

  setNonblock(cfd, true)
  setNonblock(sfd, true)
  var cDone, sDone = false
  var spins = 0
  var ok = true
  while not (cDone and sDone) and ok:
    inc spins
    if spins >= 100_000:
      checkpoint "TLS handshake stalled"
      fail()
      ok = false
      break
    if not cDone:
      let r = SSL_connect(result.cssl)
      if r == 1:
        cDone = true
      elif SSL_get_error(result.cssl, r) == SslErrorWantRead:
        waitFd(cfd, false)
      elif SSL_get_error(result.cssl, r) == SslErrorWantWrite:
        waitFd(cfd, true)
      else:
        checkpoint "client handshake failed"
        fail()
        ok = false
        break
    if not sDone:
      let r = SSL_accept(result.sssl)
      if r == 1:
        sDone = true
      elif SSL_get_error(result.sssl, r) == SslErrorWantRead:
        waitFd(sfd, false)
      elif SSL_get_error(result.sssl, r) == SslErrorWantWrite:
        waitFd(sfd, true)
      else:
        checkpoint "server handshake failed"
        fail()
        ok = false
        break
  assert ok, "handshake failed"
  setNonblock(cfd, false)
  setNonblock(sfd, false)
  result.cipher = cipherName(result.cssl)

proc closePair(p: var HandshakePair) =
  if not p.cssl.isNil:
    SSL_free(p.cssl)
    p.cssl = nil
  if not p.sssl.isNil:
    SSL_free(p.sssl)
    p.sssl = nil
  if not p.srvCtx.isNil:
    SSL_CTX_free(p.srvCtx)
    p.srvCtx = nil
  if not p.cliCtx.isNil:
    SSL_CTX_free(p.cliCtx)
    p.cliCtx = nil
  for s in [addr p.srv, addr p.cli, addr p.acc]:
    try:
      s[].close()
    except CatchableError:
      discard

proc withCert(body: proc (tmp: string)) =
  ## Mint a throwaway certificate with the openssl CLI, run `body`,
  ## clean up. Call `skip()` inside `body` is the caller's business —
  ## this just guarantees setup/teardown.
  let tmp = getTempDir() / ("ktls-ossl-" & $getCurrentProcessId())
  createDir(tmp)
  try:
    body(tmp)
  finally:
    removeDir(tmp)

suite "OpenSSL end-to-end":
  test "handshake yields TLS 1.3 and keylog secrets":
    if findExe("openssl") == "":
      skip()
    elif not libsslPresent():
      skip()
    else:
      withCert proc (tmp: string) =
        let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " &
          tmp / "key.pem" & " -out " & tmp / "cert.pem" &
          " -days 2 -nodes -subj /CN=127.0.0.1"
        let (_, code) = execCmdEx(cmd)
        if code != 0 or not fileExists(tmp / "cert.pem"):
          skip()
        else:
          let (srvCtx, cliCtx) = setupContexts(tmp)
          var pair = handshakePair(srvCtx, cliCtx)
          try:
            check negotiatedVersion(pair.cssl) == "TLSv1.3"
            check pair.cipher == "TLS_AES_128_GCM_SHA256"
            check cipherName(pair.sssl) == pair.cipher
            let secrets = parseKeylog(logLines.join("\n"))
            check secrets.haveClient
            check secrets.haveServer
            check secrets.clientSecret.len == 32
            check secrets.serverSecret.len == 32
          finally:
            closePair(pair)
  test "handshake -> keylog -> kTLS offload round-trip":
    if findExe("openssl") == "":
      skip()
    elif not libsslPresent():
      skip()
    else:
      withCert proc (tmp: string) =
        let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " &
          tmp / "key.pem" & " -out " & tmp / "cert.pem" &
          " -days 2 -nodes -subj /CN=127.0.0.1"
        let (_, code) = execCmdEx(cmd)
        if code != 0 or not fileExists(tmp / "cert.pem"):
          skip()
        elif not tryKtls():
          skip()
        else:
          let (srvCtx, cliCtx) = setupContexts(tmp)
          var pair = handshakePair(srvCtx, cliCtx)
          try:
            check pair.cipher == "TLS_AES_128_GCM_SHA256"

            # Hand the sockets to the kernel. dup first so the result
            # cannot depend on libssl's BIO close semantics.
            let cfd = pair.cli.getFd()
            let sfd = pair.acc.getFd()
            let kcfd = SocketHandle(posix.dup(cfd.cint))
            let ksfd = SocketHandle(posix.dup(sfd.cint))
            SSL_free(pair.cssl)
            SSL_free(pair.sssl)
            pair.cssl = nil
            pair.sssl = nil
            pair.cli.close()
            pair.acc.close()
            check kcfd != SocketHandle(-1) and ksfd != SocketHandle(-1)

            var secrets = parseKeylog(logLines.join("\n"))
            check secrets.haveClient and secrets.haveServer
            secrets.suite = parseTls13Suite(pair.cipher)

            let cKeys = roleKeyMaterial(secrets, amClient = true)
            let sKeys = roleKeyMaterial(secrets, amClient = false)
            enableKtls(kcfd)
            enableKtls(ksfd)
            setTx(kcfd, cKeys.tx)
            setRx(kcfd, cKeys.rx)
            setTx(ksfd, sKeys.tx)
            setRx(ksfd, sKeys.rx)
            check isTxOffloaded(kcfd)
            check isRxOffloaded(ksfd)
            check txConf(kcfd) == (tv13, csAesGcm128)

            const msg = "e2e plaintext via kernel TLS"
            sendAll(kcfd, msg)
            check recvExact(ksfd, msg.len) == msg
            const reply = "kernel says hi back"
            sendAll(ksfd, reply)
            check recvExact(kcfd, reply.len) == reply

            discard posix.close(kcfd)
            discard posix.close(ksfd)
          finally:
            closePair(pair)
