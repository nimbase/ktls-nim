# Live kernel round-trip: TX on one end, RX on the other, plaintext
# `send`/`recv`. Skips gracefully when the kernel lacks kTLS.
import std/unittest
import std/net
import std/posix

import ktls/session
import ktls/errors

proc tryKtls(): bool =
  ## Probe kernel support with a throwaway connected pair.
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

proc setupPair(): tuple[srv, cli, acc: Socket] =
  var srv = newSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(0), "127.0.0.1")
  srv.listen()
  let port = srv.getLocalAddr()[1]
  var cli = newSocket()
  cli.connect("127.0.0.1", port)
  var acc: Socket
  srv.accept(acc)
  (srv, cli, acc)

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

suite "kTLS loopback":
  test "plaintext round-trip through the kernel":
    if tryKtls():
      let (srv, cli, acc) = setupPair()
      defer:
        cli.close()
        acc.close()
        srv.close()
      let cliFd = cli.getFd()
      let accFd = acc.getFd()
      enableKtls(cliFd)
      enableKtls(accFd)
      check isTxOffloaded(cliFd) == false

      var key: array[16, byte]
      var iv: array[8, byte]
      var salt: array[4, byte]
      for i in 0 ..< 16: key[i] = byte(i + 1)
      for i in 0 ..< 8: iv[i] = byte(0xA0 + i)
      for i in 0 ..< 4: salt[i] = byte(0xC0 + i)
      let txKm = initKeyMaterial(csAesGcm128, tv12, key, iv, salt)
      let rxKm = initKeyMaterial(csAesGcm128, tv12, key, iv, salt)

      setTx(cliFd, txKm)
      setRx(accFd, rxKm)
      check isTxOffloaded(cliFd)
      check isRxOffloaded(accFd)
      check txConf(cliFd) == (tv12, csAesGcm128)
      check rxConf(accFd) == (tv12, csAesGcm128)

      const msg = "hello kTLS world, this is plaintext"
      sendAll(cliFd, msg)
      check recvExact(accFd, msg.len) == msg

      # And back the other way.
      setTx(accFd, txKm)
      setRx(cliFd, rxKm)
      const reply = "ack from the kernel side"
      sendAll(accFd, reply)
      check recvExact(cliFd, reply.len) == reply
    else:
      skip()
