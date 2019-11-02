from tls13_session import TLS13Session


def main():
    host = b"www.google.com"
    # host = b"www.facebook.com"
    # host = b"cloudflare.com"
    port = 443

    sess = TLS13Session(host, port)
    sess.connect()
    sess.send(
        f"GET / HTTP/1.1\r\nHost: {host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
    )
    res = sess.recv()
    print(res.decode())
    sess.close()


if __name__ == "__main__":
    main()
