from socket import socket, timeout
from tls13.client_hello import ClientHello, ExtensionKeyShare, ExtensionPreSharedKey, ExtensionEarlyData, supported_signatures
from tls13.server_hello import ServerHello, RecordHeader
from tls13.handshake_headers import (
    HandshakeHeader,
    HANDSHAKE_HEADER_TYPES,
    CertificateHandshakePayload,
    HandshakeFinishedHandshakePayload,
    CertificateVerifyHandshakePayload,
    NewSessionTicketHandshakePayload,
)
from tls13.change_cipher_suite import ChangeCipherSuite
from tls13.wrapper import Wrapper
import hashlib
from tls13.crypto import KeyPair, xor_iv, HandshakeKeys, calc_verify_data
from binascii import hexlify
from io import BytesIO, BufferedReader
from tls13.crypto import HKDF_Expand_Label
import hmac
from typing import Tuple, Dict, Optional
from enum import IntEnum
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
import ipaddress
import service_identity
from OpenSSL import crypto
import certifi
import os

class SignatureAlgorithm(IntEnum):
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    # EdDSA自己内部集成了hash，这个在DSA中need notable
    # Demystifying cryptography with openssl 3.0(page 135)
    ED25519 = 0x0807
    ED448 = 0x0808
    # RSA使用PKCS1标准的padding
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # legacy
    RSA_PKCS1_SHA1 = 0x0201
    SHA1_DSA = 0x0202
    ECDSA_SHA1 = 0x0203

SIGNATURE_ALGORITHMS: Dict = {
    SignatureAlgorithm.ECDSA_SECP256R1_SHA256: (None, hashes.SHA256),
    SignatureAlgorithm.ECDSA_SECP384R1_SHA384: (None, hashes.SHA384),
    SignatureAlgorithm.ECDSA_SECP521R1_SHA512: (None, hashes.SHA512),
    SignatureAlgorithm.RSA_PKCS1_SHA1: (padding.PKCS1v15, hashes.SHA1),
    SignatureAlgorithm.RSA_PKCS1_SHA256: (padding.PKCS1v15, hashes.SHA256),
    SignatureAlgorithm.RSA_PKCS1_SHA384: (padding.PKCS1v15, hashes.SHA384),
    SignatureAlgorithm.RSA_PKCS1_SHA512: (padding.PKCS1v15, hashes.SHA512),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA256: (padding.PSS, hashes.SHA256),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA384: (padding.PSS, hashes.SHA384),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA512: (padding.PSS, hashes.SHA512),
}

class TLS13Session:
    def __init__(self, host, port, timeout=2.0):
        self.host = host
        self.port = port
        self.socket = socket()
        self.socket.settimeout(timeout)
        self.session_tickets = []
        self.client_random = bytes(32)
        self.key_pair = KeyPair.generate()
        self.hello_hash_bytes = bytearray()
        self.handshake_send_counter = 0
        self.handshake_recv_counter = 0
        self.application_send_counter = 0
        self.application_recv_counter = 0
        self.resumption_keys = None
        self.peer_cert: Optional[x509.Certificate] = None

        self.client_hello = b""
        self.server_hello = b""
        self.encrypted_extension = b""
        self.certificate = b""
        self.certificate_verify = b""
        self.server_finished = b""
    
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

        # 处理服务端的encrypted_extension, certificate, certificate_verify, server_finished
        self.parse_enc_cert_verify_finished(bytes_buffer)

        # Calculate Application Keys, 使用client_hello...server_finished
        handshake_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        self.application_keys = self.key_pair.derive_application_keys(
            self.handshake_keys.handshake_secret, handshake_hash
        )

        # 写入keylogfile
        with open("keylogfile", "w") as f:
            f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.client_handshake_traffic_secret)}\n")
            f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.server_handshake_traffic_secret)}\n")
            f.write(f"CLIENT_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.client_application_traffic_secret)}\n")
            f.write(f"SERVER_TRAFFIC_SECRET_0 {bytes.hex(self.client_random)} {bytes.hex(self.application_keys.server_application_traffic_secret)}\n")

        # 兼容性考虑 Client change cipher suite
        self.socket.send(sccs.serialize())

        # Client Handshake Finished
        self.send_handshake_finished(self.handshake_keys, handshake_hash)

    def encrypt(self, key, iv, content, associated_data): 
        algorithm = algorithms.AES(key)
        mode = modes.GCM(iv)
        encryptor = Cipher(algorithm, mode).encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(content) + encryptor.finalize()
        return ciphertext, encryptor.tag

    def decrypt(self, key, iv, ciphertext, associated_data, tag):
        algorithm = algorithms.AES(key)
        mode = modes.GCM(iv, bytes(tag))
        decryptor = Cipher(algorithm, mode).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def resume(self) -> None:
        if self.application_keys is None:
            raise Exception("Can't Resume TLS1.3 Session")

        session_ticket = self.session_tickets[0]
        
        # print("keys", self.application_keys)
        resumption_master_secret = self.application_keys.resumption_master_secret(hashlib.sha256(self.hello_hash_bytes).digest())
        # print("resumption_master_secret", hexlify(resumption_master_secret))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), b"")
        # print("binder_key", hexlify(self.resumption_keys.binder_key))

        # binder = AEAD_encrypt(key = binder_key, content = client_hello_without_binder)
        # finished_key = HKDF_expand(key = binder_key, label="finished", hash=b"")
        # binder_key = HKDF_expand(key = early_secret, "res binder", "")
        # early_secret = HKDF_extract(key = psk, salt = 0)
        # psk = HKDF_expand(key = resumption_master_secret, label = "resumption", hash = ticket_nonce)
        # resumption_master_key = HKDF_expand(key=application_master_key, label="res master", hash=clientHello...clientFinished)
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

        self.key_pair = KeyPair.generate()
        self.handshake_keys = None
        self.application_keys = None
        self.handshake_send_counter = 0
        self.handshake_recv_counter = 0
        self.application_send_counter = 0
        self.application_recv_counter = 0

        ch = ClientHello(self.host, self.key_pair.public)
        self.client_random = ch.client_random
        # ch.extensions = [ex for ex in ch.extensions if type(ex) is not ExtensionServerName]
        ch.add_extension(ExtensionEarlyData())
        ch.add_extension(pre_share_key_ext) # 注意presharedkey extension位于最后

        ch_bytes = ch.serialize()
        my_hello_hash = hashlib.sha256(ch_bytes[5:-offset]).digest()
        # print("my_hash", hexlify(my_hello_hash))
        # print("my_hash_offset", hexlify(ch_bytes[5:-offset]))


        # TODO 这一段跟上面算占位代码重复了
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
        # print("finished_key", hexlify(finished_key))
        psk_binders = verify_data
        
        # print("psk_binders", hexlify(psk_binders))

        
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
        # print("final_hash", hexlify(final_hash))
        self.resumption_keys = self.key_pair.derive_early_keys(session_ticket.psk(resumption_master_secret), final_hash)

        # 新的hash开始
        self.hello_hash_bytes = ch_bytes_final[5:]

        with open("keylogfile", "a") as f:
            f.write(f"CLIENT_EARLY_TRAFFIC_SECRET {ch.client_random.hex()} {self.resumption_keys.client_early_traffic_secret.hex()}\n")

        self.socket = socket()
        self.socket.connect((self.host, self.port))

        # data = f"HEAD /img.jpg HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
        # data = f"GET / HTTP/1.1\r\nHost: {self.host.decode()}\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".encode()
        data = b"hello world again"
        send_data = data + b"\x17"
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)

        # encryptor = AES.new(
        #     self.resumption_keys.client_early_key,
        #     AES.MODE_GCM,
        #     xor_iv(self.resumption_keys.client_early_iv, 0),
        # )
        # ciphertext_payload = encryptor.encrypt(send_data) + encryptor.finalize()
        # tag = encryptor.tag
        ciphertext_payload, tag = self.encrypt(
            self.resumption_keys.client_early_key, 
            xor_iv(self.resumption_keys.client_early_iv, 0),
            send_data,
            record_header.serialize()
        )

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        # client hello, change cipher spec(140303000101), application data 一起发送
        self.socket.send(ch_bytes_final + bytes.fromhex("140303000101") + w.serialize())
        
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(4096)))
        # print("res", bytes_buffer)
        
        # NOTICE: 里面已经添加server hello到hello_hash_bytes
        sh = self.recv_server_hello(bytes_buffer)
        key_share_ex = [ex for ex in sh.extensions if type(ex) is ExtensionKeyShare][0]
        # print(f"server key share -> public key bytes: {key_share_ex.public_key_bytes.hex()}")
        self.handshake_keys = self.calc_handshake_keys(key_share_ex.public_key_bytes)
        with open("keylogfile", "a") as f:
            f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.client_handshake_traffic_secret)}\n")
            f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {bytes.hex(self.client_random)} {bytes.hex(self.handshake_keys.server_handshake_traffic_secret)}\n")

        # Recv ServerChangeCipherSuite
        sccs = ChangeCipherSuite.deserialize(bytes_buffer)

        # Server Encrypted Extensions
        # plaintext = self.recv_server_encrypted_extensions(bytes_buffer)

        # 这里的hash = client_hello + server_hello + server_encrypted_extension + server_finish
        # self.hello_hash_bytes += plaintext
        self.parse_enc_cert_verify_finished(bytes_buffer, True)

        # 发送 end of early data和client finished
        # early data 05000000 and application data type 0x16
        send_data = bytes.fromhex("0500000016")
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16)

        ciphertext_payload, tag = self.encrypt(
            self.resumption_keys.client_early_key,
            xor_iv(self.resumption_keys.client_early_iv, 1),
            send_data,
            record_header.serialize()
        )

        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)

        handshake_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        finished_data = self.send_handshake_finished(self.handshake_keys, handshake_hash, True)
        self.socket.send(w.serialize() + finished_data)

        # Calculate Application Keys
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
                    # print(f"application raw data: {application_data.hex()}")

                    # NOTICE: handshake加解密的associated data是相对应的record header data
                    plaintext = self.decrypt(
                        self.application_keys.server_key,
                        xor_iv(self.application_keys.server_iv, self.application_recv_counter),
                        application_data[0: -16],
                        raw_data[0:5],
                        application_data[-16:]
                    )
                    self.application_recv_counter += 1
                    if plaintext[-1] == 0x17: # 如果是真正的application data，打印decode后的asscii
                        print(f'应用数据: ################################################################################################')
                        print(f'{plaintext[0: -1].decode()}')
                        print('###########################################################################################################')
                    elif plaintext[-1] == 0x15: # alert
                        print(f"Alert数据: alert level {plaintext[0:1].hex()}, alert desc {plaintext[1:2].hex()}")
                    else:
                        print(f"未知类型数据: 类型 {plaintext[-1:].hex()} raw data: {plaintext[0: -1].hex()}")
                    raw_data = raw_data[record_len+5:]
                else:
                    break;

    def send_client_hello(self):
        ch = ClientHello(self.host, self.key_pair.public)
        self.client_random = ch.client_random
        ch_bytes = ch.serialize()
        self.hello_hash_bytes += ch_bytes[5:]
        self.client_hello = ch_bytes[5:]
        self.socket.send(ch_bytes)

    def recv_server_hello(self, bytes_buffer) -> ServerHello:
        original_buffer = bytes_buffer.peek()
        sh = ServerHello.deserialize(bytes_buffer)
        self.hello_hash_bytes += original_buffer[5 : sh.record_header.size + 5]
        self.server_hello = original_buffer[5 : sh.record_header.size + 5]
        return sh

    def calc_handshake_keys(self, peer_pub_key: bytes) -> HandshakeKeys:
        shared_secret = self.key_pair.exchange(peer_pub_key)
        # print("shared secret", shared_secret)
        hello_hash = hashlib.sha256(self.hello_hash_bytes).digest()
        return self.key_pair.derive(shared_secret, hello_hash, self.resumption_keys)

    def parse_wrapper(self, bytes_buffer):
        wrapper = Wrapper.deserialize(bytes_buffer)
        while wrapper.record_header.size > len(wrapper.payload):
            wrapper.payload += self.socket.recv(
                wrapper.record_header.size - len(wrapper.payload)
            )

        recdata = wrapper.record_header.serialize()
        authtag = wrapper.auth_tag

        ciphertext = wrapper.encrypted_data

        # NOTICE: handshake加解密的associated data是相对应的record header data, 已经自动验证tag了
        plaintext = self.decrypt(
            self.handshake_keys.server_key,
            xor_iv(self.handshake_keys.server_iv, self.handshake_recv_counter),
            bytes(ciphertext),
            recdata,
            authtag
        )
        self.handshake_recv_counter += 1

        # 去掉最后一位的真实类型，此方法用于解析EE, CT, CV, FINISHED
        return plaintext[:-1]

    def parse_encrypted_extensions(self, plaintext):
        # TODO self.encrypted_extensions = ...
        self.hello_hash_bytes += plaintext
        self.encrypted_extension = plaintext

    def parse_certificate(self, plaintext):
        plaintext_buffer = BufferedReader(BytesIO(plaintext))
        hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
        hh_payload_buffer = plaintext_buffer.read(hh.size)
        hh_payload = CertificateHandshakePayload.deserialize(
            hh_payload_buffer
        )
        self.peer_cert = x509.load_der_x509_certificate(hh_payload.certificate) 

        self.hello_hash_bytes += plaintext
        self.certificate = plaintext
    
    def signature_algorithm_params(self, signature_algorithm: int) -> Tuple:
        if signature_algorithm in (SignatureAlgorithm.ED25519, SignatureAlgorithm.ED448):
            return tuple()

        padding_cls, algorithm_cls = SIGNATURE_ALGORITHMS[signature_algorithm]
        algorithm = algorithm_cls()
        if padding_cls is None:
            return (ec.ECDSA(algorithm),)
        elif padding_cls == padding.PSS:
            padding_obj = padding_cls(
                mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size
            )
        else:
            padding_obj = padding_cls()
        return padding_obj, algorithm

    def verify_certificate(self, certificate: x509.Certificate, cafile, server_name: Optional[str] = None):
        # 1. 检查时间
        now = datetime.utcnow()
        if now < certificate.not_valid_before:
            print(f"证书还没有生效 {certificate.not_valid_before}")
        if now > certificate.not_valid_after:
            print(f"证书已经过期 {certificate.not_valid_after}")

        # 2. 验证subject
        if server_name is not None:
            try:
                ipaddress.ip_address(server_name)
            except ValueError:
                is_ip = False
            else:
                is_ip = True

            try:
                if is_ip:
                    service_identity.cryptography.verify_certificate_ip_address(
                        certificate, server_name
                    )
                else:
                    service_identity.cryptography.verify_certificate_hostname(
                        certificate, server_name
                    )

            except service_identity.VerificationError as exc:
                patterns = service_identity.cryptography.extract_patterns(certificate)
                if len(patterns) == 0:
                    errmsg = "subject alternative name not found in the certificate"
                elif len(patterns) == 1:
                    errmsg = f"hostname {server_name!r} doesn't match {patterns[0]!r}"
                else:
                    patterns_repr = ", ".join(repr(pattern) for pattern in patterns)
                    errmsg = (
                        f"hostname {server_name!r} doesn't match "
                        f"either of {patterns_repr}"
                    )
                print(f"证书校验失败，各种subject对不上 {errmsg}")
        
        # 3. 加载根证书，验证是否是真货
        store = crypto.X509Store()
        store.load_locations(certifi.where())
        store.load_locations(cafile)
        store_ctx = crypto.X509StoreContext(
            store, 
            crypto.X509.from_cryptography(certificate))
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError:
            print(f"证书校验失败，根证书校验不了")

    def parse_certificate_verify(self, plaintext):
        plaintext_buffer = BufferedReader(BytesIO(plaintext))
        hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
        hh_payload_buffer = plaintext_buffer.read(hh.size)
        hh_payload = CertificateVerifyHandshakePayload.deserialize(
            hh_payload_buffer
        )
        if hh_payload.signature_algorithm not in supported_signatures: # 此处进行handshake header中的signature_algorithm比较
            print(f"NOT SUPPORT SIGNATURE ALGORITHM {self.signature_algorithm}")
                
        # https://datatracker.ietf.org/doc/html/rfc8446#autoid-51
        context_string = b"TLS 1.3, server CertificateVerify"
        hash = hashes.Hash(hashes.SHA256())
        hash.update(self.hello_hash_bytes)
        verify_data = b" " * 64 + context_string + b"\x00" + hash.finalize()
        
        # 检验certificate verify
        try:
            self.peer_cert.public_key().verify(
                hh_payload.signature,
                verify_data,
                *self.signature_algorithm_params(hh_payload.signature_algorithm)
            )
        except InvalidSignature:
            print(f"CertificateVerify失败")

        # 检验certificate
        self.verify_certificate(
            self.peer_cert, 
            os.path.abspath("./test_server/nginx/certs/cert.pem"), 
            "localhost"
        )

        self.hello_hash_bytes += plaintext
        self.certificate_verify = plaintext

    def parse_finished(self, plaintext):
        finished_key = HKDF_Expand_Label(
            key=self.handshake_keys.server_handshake_traffic_secret,
            label="finished",
            context=b"",
            length=32,
        )
        # NOTICE 这里的msg是经过hash后的
        verify_data = hmac.new(
            key = finished_key, 
            msg = hashlib.sha256(self.hello_hash_bytes).digest(), 
            digestmod = hashlib.sha256
        ).digest()

        print(hexlify(self.handshake_keys.server_handshake_traffic_secret))
        print(hexlify(calc_verify_data(self.handshake_keys.server_handshake_traffic_secret, self.hello_hash_bytes)))
        print(hexlify(verify_data))
        print(hexlify(plaintext[4:]))
        
        self.hello_hash_bytes += plaintext
        self.server_finished = plaintext

    # 解析server的encrypted_extension, certificate(*), certificate_verify(*), finished
    # resume情况下没有certificate, certificate_verifiy
    def parse_enc_cert_verify_finished(self, bytes_buffer, is_resume = False) -> bytes:
        parse_funcs = [self.parse_encrypted_extensions]
        if is_resume is False:
           parse_funcs.append(self.parse_certificate)
           parse_funcs.append(self.parse_certificate_verify)
        parse_funcs.append(self.parse_finished)
        for parse_func in parse_funcs:
            # plaintext 包含handshake header(4 bytes)
            plaintext = self.parse_wrapper(bytes_buffer)
            parse_func(plaintext)

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
        # NOTICE: 为了compatibility，这里最后加了真正的类型后缀0x16(handshake)，但是header上伪装成0x17(application data)
        # record payload protection https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
        plaintext_payload = b"".join(
            [hh_header.serialize(), hh_payload.verify_data, b"\x16"]
        )

        # NOTICE: 添加的hash包括handshake header(4 bytes)+payload, 不包括最后的真实类型(1 byte)
        if not_send is False:
            self.hello_hash_bytes += plaintext_payload[:-1]

        # type都为0x17(23), 表示application data type
        record_header = RecordHeader(rtype=0x17, size=len(plaintext_payload) + 16)

        # record payload protection https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
        # 文档里面说的比较模糊，tag属于AEAD范畴，tag放到加密内容后面，而且计算到长度里面

        ciphertext_payload, tag = self.encrypt(
            handshake_keys.client_key,
            handshake_keys.client_iv,
            plaintext_payload,
            record_header.serialize()
        )

        # 可以在wireshark中查看
        # print(f"client finish record AEAD tag: {tag.hex()}")

        # recorder header + handshake header + handshake payload + 0x16 + tag(16 bytes)
        w = Wrapper(record_header=record_header, payload=ciphertext_payload + tag)
        if not_send is True:
            return w.serialize()
        else:
            self.socket.send(w.serialize())

    def send(self, data: bytes):
        send_data = data + b"\x17" # 要发送的payload, 0x17表示真正的content type(application data)
        record_header = RecordHeader(rtype=0x17, size=len(send_data) + 16) # 加上的16表示AEAD auth tag

        ciphertext_payload, tag = self.encrypt(
            self.application_keys.client_key,
            xor_iv(self.application_keys.client_iv, self.application_send_counter),
            send_data,
            record_header.serialize()
        )

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

        plaintext = self.decrypt(
            self.application_keys.server_key,
            xor_iv(self.application_keys.server_iv, self.application_recv_counter),
            bytes(ciphertext),
            recdata,
            authtag
        )
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
