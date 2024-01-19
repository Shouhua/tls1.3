from time import sleep

from tls13.tls13_session import TLS13Session


def main():
    # host = b"www.google.com"
    # host = b"www.facebook.com"
    # host = b"cloudflare.com"
    # port = 443

    host = b"127.0.0.1"
    port = 4433
    # port = 8888

    # msg = f"HEAD /img.jpg HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
    # msg = b"hello world again"
    msg = f"GET / HTTP/1.1\r\nHost: {host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()

    sess = TLS13Session(host, port)
    sess.connect()
    sess.send(msg)
    # sess.send(b"hello, world")
    res = sess.recv()
    print(
        f"应用数据: ################################################################################################"
    )
    print(res.decode())
    print(
        f"################################################################################################"
    )
    sess.close()
    # print(sess.session_tickets)
    # sleep(0.5)
    sess.resume(msg)
    sess.close()


if __name__ == "__main__":
    main()
