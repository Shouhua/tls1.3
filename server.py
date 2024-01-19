#!/usr/bin/env python3

import asyncio
import ssl
from asyncio import StreamReader
from os.path import abspath


async def handle_connection(reader: StreamReader, writer):
    addr = writer.get_extra_info("peername")
    print("Connection established with {}".format(addr))
    while True:
        # Read the marker
        try:
            content = await reader.read(1024)
            if not content:
                print("Connection terminated with {}".format(addr))
                break
        except asyncio.IncompleteReadError:
            print("Connection terminated with {}".format(addr))
            break
        print("Read {} bytes from  the client: {}".format(len(content), addr))
        # Reverse the string
        echo_data = "".join(reversed(content.decode()))
        # Send the marker
        writer.write(len(echo_data).to_bytes(4, byteorder="big"))
        # Send the data itself
        writer.write(echo_data.encode())
        # Wait for the data to be written back
        await writer.drain()
        print(
            "Finished sending {} bytes to the client: {}".format(len(echo_data), addr)
        )


def setup_server():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ssl_ctx.options |= ssl.OP_NO_TLSv1
    # ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    # ssl_ctx.options |= ssl.PROTOCOL_TLSv1

    ssl_ctx.keylog_filename = "server_keylogfile"

    ssl_ctx.load_cert_chain(
        certfile=abspath("./test_server/nginx/certs/cert.pem"),
        keyfile=abspath("./test_server/nginx/certs/key.pem"),
    )
    # ssl_ctx.load_verify_locations(cafile='server_ca.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
    # ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    loop = asyncio.get_event_loop()
    coroutine = asyncio.start_server(handle_connection, "127.0.0.1", 8888, ssl=ssl_ctx)
    server = loop.run_until_complete(coroutine)
    print("Serving on {}".format(server.sockets[0].getsockname()))
    loop.run_forever()


if __name__ == "__main__":
    setup_server()
