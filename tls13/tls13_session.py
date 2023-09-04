"""
Usage:
s = TLS13Session()
s.connect((host, port))

s.send(b"hello world")
data = s.recv(4096)

s.close()
"""
from socket import socket, timeout
from tls13.client_hello import ClientHello, ExtensionKeyShare, ExtensionPreSharedKey, ExtensionEarlyData, ExtensionServerName
from tls13.server_hello import ServerHello, RecordHeader
from tls13.handshake_headers import (
    HandshakeHeader,
    HANDSHAKE_HEADER_TYPES,
    HandshakeFinishedHandshakePayload,
    NewSessionTicketHandshakePayload,
)
from tls13.change_cipher_suite import ChangeCipherSuite
from tls13.wrapper import Wrapper
import hashlib
from tls13.crypto import KeyPair, xor_iv, HandshakeKeys
from binascii import hexlify
from io import BytesIO, BufferedReader
from Crypto.Cipher import AES
import struct
from tls13.crypto import HKDF_Expand_Label
import hmac


class TLS13Session:
    def __init__(self, host, port, timeout=2.0):
        self.host = host
        self.port = port
        self.socket = socket()
        self.socket.settimeout(timeout)
        self.session_tickets = []
        self._initialize()
    
    def _initialize(self):
        self.client_random = bytes(32)
        self.key_pair = KeyPair.generate()
        self.hello_hash_bytes = bytearray()
        self.handshake_send_counter = 0
        self.handshake_recv_counter = 0
        self.application_send_counter = 0
        self.application_recv_counter = 0
        self.resumption_keys = None

    def connect(self) -> None:
        self.socket.connect((self.host, self.port))

        # Send ClientHello
        self.send_client_hello()

        # Recv ServerHello
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))
        sh = self.recv_server_hello(bytes_buffer)
        key_share_ex = [ex for ex in sh.extensions if type(ex) is ExtensionKeyShare][0]
        self.handshake_keys = self.calc_handshake_keys(key_share_ex.public_key_bytes)

        # Recv ServerChangeCipherSuite
        sccs = ChangeCipherSuite.deserialize(bytes_buffer)

        # Server Encrypted Extensions
        plaintext = self.recv_server_encrypted_extensions(bytes_buffer)

        # 这里的hash = client_hello + server_hello + server_encrypted_extension + server_certificate + server_certificate_verify + server_finish
        self.hello_hash_bytes += plaintext

        # Calculate Application Keys
        handshake_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        self.application_keys = self.key_pair.derive_application_keys(
            self.handshake_keys.handshake_secret, handshake_hash
        )

        with open("keylogfile", "w") as f:
            f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.client_handshake_traffic_secret)}\n")
            f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.server_handshake_traffic_secret)}\n")
            f.write(f"CLIENT_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.client_application_traffic_secret)}\n")
            f.write(f"SERVER_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.server_application_traffic_secret)}\n")

        # Client change cipher suite
        self.socket.send(sccs.serialize())

        # Client Handshake Finished
        # NOTICE: handshake_hash += client_finish
        self.send_handshake_finished(self.handshake_keys, handshake_hash)

    def resume(self) -> None:
        if self.application_keys is None:
            raise Exception("Can't Resume TLS1.3 Session")

        session_ticket = self.session_tickets[0]
        
        # print("keys", self.application_keys)
        resumption_master_secret = self.application_keys.resumption_master_secret(hashlib.sha256(self.hello_hash_bytes).digest())
        print("resumption_master_secret", hexlify(resumption_master_secret))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), b"")
        print("binder_key", hexlify(self.resumption_keys.binder_key))

        # binder = aead(key = binder_key, hash = client_hello_without_binder)
        # finished_key = HKDF_expand(key = binder_key, label="finished", hash=b"")
        # binder_key = HKDF_expand(key = early_secret, "res binder", "")
        # early_secret = HKDF_extract(key = psk, salt = 0)
        # psk = HKDF_expand(key = resumption_master_secret, label = "resumption", hash = ticket_nonce)
        # 最终用来生成binder的key
        finished_key = HKDF_Expand_Label(
            key=self.resumption_keys.binder_key,
            label="finished",
            context=b"",
            length=32,
        )
        verify_data = hmac.new(
            finished_key, msg=b"", digestmod=hashlib.sha256
        ).digest()
        psk_binders = verify_data # 这个时候是空的，只是占位，后面填充，因为要计算binder的offset， 后面hash不带上binder, 但是长度还是要带上
        # print("finished_key", hexlify(finished_key))

        offset = len(ExtensionPreSharedKey.serialize_binders(psk_binders))

        pre_share_key_ext = ExtensionPreSharedKey(
            identity=session_ticket.session_ticket, 
            obfuscated_ticket_age=session_ticket.obfuscated_ticket_age, 
            binders=psk_binders)

        # TODO 需要重新生成key pair，重点是在哪儿点生成，这里会干扰后面的密钥生成？
        self.key_pair = KeyPair.generate()
        self.handshake_keys = None
        self.application_keys = None
        # self.hello_hash_bytes = bytearray()
        self.handshake_send_counter = 0
        self.handshake_recv_counter = 0
        self.application_send_counter = 0
        self.application_recv_counter = 0

        ch = ClientHello(self.host, self.key_pair.public)
        self.client_random = ch.client_random
        # ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionServerName]
        ch.add_extension(ExtensionEarlyData())
        ch.add_extension(pre_share_key_ext)

        ch_bytes = ch.serialize()
        my_hello_hash = hashlib.sha256(ch_bytes[5:-offset]).digest()
        print("my_hash", hexlify(my_hello_hash))
        print("my_hash_offset", hexlify(ch_bytes[5:-offset]))


        finished_key = HKDF_Expand_Label(
            key=self.resumption_keys.binder_key,
            label="finished",
            context=b"",
            length=32,
        )
        # 根据hello_hash_without_binder算出真正的binder
        verify_data = hmac.new(
            finished_key, msg=my_hello_hash, digestmod=hashlib.sha256
        ).digest()
        print("finished_key", hexlify(finished_key))
        psk_binders = verify_data
        
        print("psk_binders", hexlify(psk_binders))

        
        # client_hello hash
        # final_hash = hashlib.sha256(ch_bytes[5:]).digest()
        # print("early data client hello hash:", hexlify(final_hash))
        # self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), final_hash)

        pre_share_key_ext = ExtensionPreSharedKey(
            identity=session_ticket.session_ticket, 
            obfuscated_ticket_age=session_ticket.obfuscated_ticket_age, 
            binders=psk_binders)

        # TODO: 这里删除之前PreSharedKey extension, 添加新的, 能不能更新原有的
        ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionPreSharedKey]
        # ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionServerName]
        ch.add_extension(pre_share_key_ext)

        ch_bytes_final = ch.serialize()
        # print(len(ch_bytes_final), ch_bytes_final)

        final_hash = hashlib.sha256(ch_bytes_final[5:]).digest()
        print("final_hash", hexlify(final_hash))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), final_hash)

        # 新的hash开始
        self.hello_hash_bytes = ch_bytes_final[5:]

        with open("keylogfile", "a") as f:
            f.write(f"CLIENT_EARLY_TRAFFIC_SECRET {ch.client_random.hex()} {self.resumption_keys.client_early_traffic_secret.hex()}\n")

        self.socket = socket()
        self.socket.connect((self.host, self.port))

        # data = f"HEAD /img.jpg HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
        data = f"GET / HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
        send_data = data + b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)
        print("client_early_traffic_secret", hexlify(self.resumption_keys.client_early_traffic_secret))
        print("client_early_key", hexlify(self.resumption_keys.client_early_key))
        print("client_early_iv", hexlify(self.resumption_keys.client_early_iv))
        encryptor = AES.new(
            self.resumption_keys.client_early_key,
            AES.MODE_GCM,
            xor_iv(self.resumption_keys.client_early_iv, 0),
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        # client hello, change cipher spec(140303000101), application data 一起发送
        self.socket.send(ch_bytes_final + bytes.fromhex("140303000101") + w.serialize())
        
        # TODO 续写接受过程，验证是否可以继续通信
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))
        # print("res", bytes_buffer)
        
        # NOTICE: 里面已经添加server hello到hello_hash_bytes
        sh = self.recv_server_hello(bytes_buffer)
        key_share_ex = [ex for ex in sh.extensions if type(ex) is ExtensionKeyShare][0]
        print(f"server key share -> public key bytes: {key_share_ex.public_key_bytes.hex()}")
        self.handshake_keys = self.calc_handshake_keys(key_share_ex.public_key_bytes)
        with open("keylogfile", "a") as f:
            f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.client_handshake_traffic_secret)}\n")
            f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.server_handshake_traffic_secret)}\n")

        # Recv ServerChangeCipherSuite
        sccs = ChangeCipherSuite.deserialize(bytes_buffer)

        # Server Encrypted Extensions
        plaintext = self.recv_server_encrypted_extensions(bytes_buffer)

        # 这里的hash = client_hello + server_hello + server_encrypted_extension + server_finish
        self.hello_hash_bytes += plaintext

        # 发送 end of early data和client finished
        # early data 05000000 and application data type 0x16
        send_data = bytes.fromhex("0500000016")
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)
        encryptor = AES.new(
            self.resumption_keys.client_early_key,
            AES.MODE_GCM,
            xor_iv(self.resumption_keys.client_early_iv, 1),
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        # hash添加end of early data
        # self.hello_hash_bytes += send_data

        finished_data = self.send_handshake_finished(self.handshake_keys, self.hello_hash_bytes, True)
        self.socket.send(w.serialize() + finished_data)

        # Calculate Application Keys
        handshake_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        self.application_keys = self.key_pair.derive_application_keys(
            self.handshake_keys.handshake_secret, handshake_hash
        )
        with open("keylogfile", "a") as f:
            f.write(f"CLIENT_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.client_application_traffic_secret)}\n")
            f.write(f"SERVER_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.server_application_traffic_secret)}\n")

        # 接收server application data, 也有可能alter数据
        while raw_data := self.socket.recv(4096):
            # print(f"received {len(raw_data)} bytes data: {raw_data.hex()}")
            while len(raw_data) > 5:
                if raw_data[0] == 0x17: # application data
                    assert raw_data[1:3] == b"\x03\x03" # check version tls1.2 
                    record_len = int.from_bytes(raw_data[3:5], byteorder="big")
                    application_data = raw_data[5:record_len+5]
                    print(f"application raw data: {application_data.hex()}")
                    # 解密
                    decryptor = AES.new(
                        self.application_keys.server_key,
                        AES.MODE_GCM,
                        xor_iv(self.application_keys.server_iv, self.application_recv_counter),
                    )
                    self.application_recv_counter += 1
                    # NOTICE: handshake加解密的associated data是相对应的record header data
                    decryptor.update(raw_data[0:5]) # associated data

                    plaintext = decryptor.decrypt(application_data[0: -16])
                    if plaintext[-1] == 0x17: # 如果是真正的application data，打印decode后的asscii
                        print(f"decryptor application data: {plaintext[0: -1].decode()}")
                    else:
                        print(f"decryptor raw data: {plaintext[0: -1].hex()}")
                    raw_data = raw_data[record_len+5:]
                else:
                    break;

    def send_client_hello(self):
        ch = ClientHello(self.host, self.key_pair.public)
        self.client_random = ch.client_random
        ch_bytes = ch.serialize()
        self.hello_hash_bytes += ch_bytes[5:]
        self.socket.send(ch_bytes)

    def recv_server_hello(self, bytes_buffer) -> ServerHello:
        original_buffer = bytes_buffer.peek()
        sh = ServerHello.deserialize(bytes_buffer)
        self.hello_hash_bytes += original_buffer[5 : sh.record_header.size + 5]
        return sh

    def calc_handshake_keys(self, peer_pub_key: bytes) -> HandshakeKeys:
        shared_secret = self.key_pair.exchange(peer_pub_key)
        print("shared secret", shared_secret)
        hello_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        return self.key_pair.derive(shared_secret, hello_hash, self.resumption_keys)

    def recv_server_encrypted_extensions(self, bytes_buffer) -> bytes:
        def parse_wrapper(bytes_buffer):
            wrapper = Wrapper.deserialize(bytes_buffer)
            while wrapper.record_header.size > len(wrapper.payload):
                wrapper.payload += self.socket.recv(
                    wrapper.record_header.size - len(wrapper.payload)
                )

            recdata = wrapper.record_header.serialize()
            authtag = wrapper.auth_tag

            ciphertext = wrapper.encrypted_data

            decryptor = AES.new(
                self.handshake_keys.server_key,
                AES.MODE_GCM,
                xor_iv(self.handshake_keys.server_iv, self.handshake_recv_counter),
            )
            # NOTICE: handshake加解密的associated data是相对应的record header data
            decryptor.update(recdata) # associated data

            plaintext = decryptor.decrypt(bytes(ciphertext))
            self.handshake_recv_counter += 1

            decryptor.verify(authtag)
            return plaintext[:-1]

        plaintext = bytearray()
        plaintext += parse_wrapper(bytes_buffer)
        plaintext_buffer = BufferedReader(BytesIO(plaintext))
        # TODO: change this to walrus operator
        while True:
            if len(plaintext_buffer.peek()) < 4:
                res = parse_wrapper(bytes_buffer)
                plaintext += res
                plaintext_buffer = BufferedReader(
                    BytesIO(plaintext_buffer.peek() + res)
                )

            hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
        
            hh_payload_buffer = plaintext_buffer.read(hh.size)
            while len(hh_payload_buffer) < hh.size:
                res = parse_wrapper(bytes_buffer)
                plaintext += res
                plaintext_buffer = BufferedReader(
                    BytesIO(plaintext_buffer.peek() + res)
                )

                prev_len = len(hh_payload_buffer)
                hh_payload_buffer = hh_payload_buffer + plaintext_buffer.read(
                    hh.size - prev_len
                )

            # TODO: 这里解析了不止EncryptedExtension，还包括Certificate，CertificateVerify， Finish
            # 这些都是就使用handshake secret解密的，最终得到的plaintext包括以上的除record header之外内容的集合
            hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
                hh_payload_buffer
            )
    
            if type(hh_payload) is HandshakeFinishedHandshakePayload:
                break

        return plaintext

    def send_handshake_finished(
        self, handshake_keys: HandshakeKeys, handshake_hash: bytes, not_send = False
    ):
        hh_payload = HandshakeFinishedHandshakePayload.generate(
            handshake_keys.client_handshake_traffic_secret, handshake_hash
        )
        hh_header = HandshakeHeader(
            HandshakeFinishedHandshakePayload.default_htype(),
            len(hh_payload.verify_data),
        )
        # NOTICE: 这里最后加了后缀0x16(content type), 总体来说，这个内容会伪装成0x17application data, 但是使用后缀表示真正的类型
        #     enum {
        #       invalid(0),
        #       change_cipher_spec(20),
        #       alert(21),
        #       handshake(22),
        #       application_data(23),
        #       (255)
        #   } ContentType;
        # record payload protection https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
        plaintext_payload = b"".join(
            [hh_header.serialize(), hh_payload.verify_data, b"\x16"]
        )

        # NOTICE: 添加的hash包括header+payload+0x16
        if not_send is False:
            self.hello_hash_bytes += plaintext_payload[:-1]

        # type都为0x17(23), 表示application data type
        record_header = RecordHeader(rtype=0x17, size=len(plaintext_payload) + 16)

        encryptor = AES.new(
            handshake_keys.client_key, AES.MODE_GCM, handshake_keys.client_iv
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(plaintext_payload)

        # record payload protection https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
        # 文档里面说的比较模糊，tag属于AEAD范畴，tag已经包含到encrypted_record里面了
        tag = encryptor.digest()

        # 可以在wireshark中查看
        print(f"client finish record AEAD tag: {tag.hex()}")

        # recorder header + handshake header + handshake payload + 0x16 + tag(16 bytes)
        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        if not_send is True:
            return w.serialize()
        else:
            self.socket.send(w.serialize())

    def send(self, data: bytes):
        send_data = data + b"\x17" # 要发送的payload, 0x17表示真正的content type(application data)
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16) # 加上的16表示AEAD auth tag
        encryptor = AES.new(
            self.application_keys.client_key,
            AES.MODE_GCM,
            xor_iv(self.application_keys.client_iv, self.application_send_counter),
        )
        encryptor.update(record_header.serialize())
        ciphertext_payload = encryptor.encrypt(send_data)
        tag = encryptor.digest()

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        self.socket.send(w.serialize())
        self.application_send_counter += 1

    def __recv(self, bytes_buffer):

        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += self.socket.recv(
                wrapper.record_header.size - len(wrapper.payload)
            )

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        decryptor = AES.new(
            self.application_keys.server_key,
            AES.MODE_GCM,
            xor_iv(self.application_keys.server_iv, self.application_recv_counter),
        )
        decryptor.update(recdata)

        plaintext = decryptor.decrypt(bytes(ciphertext))

        decryptor.verify(authtag)
        self.application_recv_counter += 1

        return plaintext

    def _recv(self):
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))

        if len(bytes_buffer.peek()) < 4:
            bytes_buffer = BufferedReader(
                BytesIO(bytes_buffer.read() + self.socket.recv(4096))
            )
        res = self.__recv(bytes_buffer)
        # while res[-1] != 0x17:
        # count =1
        while True:
            if res[-1] == 0x17: # 23 application data
                yield res[:-1]
            if res[-1] == 0x16: # 22 handshak data
                plaintext_buffer = BufferedReader(BytesIO(res[:-1]))
                while plaintext_buffer.peek():
                    hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
                    hh_payload_buffer = plaintext_buffer.read(hh.size)
                    hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
                        hh_payload_buffer
                    )
                    if type(hh_payload) is NewSessionTicketHandshakePayload:
                        self.session_tickets.append(hh_payload)

            if len(bytes_buffer.peek()) < 4:
                bytes_buffer = BufferedReader(
                    BytesIO(bytes_buffer.read() + self.socket.recv(4096))
                )

                if len(bytes_buffer.peek()) < 4:
                    break

            res = self.__recv(bytes_buffer)

    # 接受server的session ticket, application data
    def recv(self):
        res = bytearray()
        try:
            for data in self._recv():
                res += data
        except timeout:
            pass

        return res

    def close(self):
        self.socket.close()
