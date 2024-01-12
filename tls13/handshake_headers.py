from dataclasses import dataclass
import struct
from io import BytesIO, BufferedReader
from tls13.crypto import HKDF_Expand_Label
import hmac
import hashlib
from binascii import hexlify
import datetime
from enum import IntEnum

class HandshakeType(IntEnum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254

# 每一个TLS握手消息4个字节，1字节类型和3字节长度开始, 类型有比如：client hello, server hello等
# https://datatracker.ietf.org/doc/html/rfc8446#autoid-18
@dataclass
class HandshakeHeader:
    message_type: int
    size: int

    @classmethod
    def deserialize(klass, data: bytes):
        message_type = data[0]
        size, = struct.unpack(">i", b"\x00" + data[1:])
        return HandshakeHeader(message_type, size)

    def serialize(self):
        return b"".join(
            [struct.pack("b", self.message_type), struct.pack(">i", self.size)[1:]]
        )


@dataclass
class HandshakePayload:
    data: bytes

    @classmethod
    def default_htype(klass) -> int:
        raise NotImplementedError

    @classmethod
    def deserialize(klass, data: bytes):
        return klass(data=data)


@dataclass
class EncryptedExtensionHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return HandshakeType.encrypted_extensions

# 服务器会发送一个或多个证书：
# 该主机的证书，包含主机名、公钥和第三方的签名(签名证明该证书主机名的所有者持有该证书的私钥)。
# 其他证书的可选列表，从主机证书一直到预先安装在客户端上的可信证书。其中每一个都对前一个证书进行签名，形成一个信任链。
@dataclass
class CertificateHandshakePayload(HandshakePayload):
    certificate: bytes

    @classmethod
    def default_htype(klass) -> int:
        return HandshakeType.certificate

    @classmethod
    def deserialize(klass, data: bytes):
        bytes_buffer = BytesIO(data)
        _request_context, = struct.unpack("b", bytes_buffer.read(1)) # 1字节的请求上下文，来源于CertificateRequest
        _certificate_length, = struct.unpack(">i", b"\x00" + bytes_buffer.read(3)) # 3字节的所有证书长度
        certificate_length_follows, = struct.unpack( # 接下来的证书长度，这里只解析一个证书
            ">i", b"\x00" + bytes_buffer.read(3)
        )
        certificate = bytes_buffer.read(certificate_length_follows)
        _certificate_extensions_follow, = struct.unpack(">h", bytes_buffer.read(2)) # 这里不处理证书的扩展
        return CertificateHandshakePayload(data=data, certificate=certificate)

@dataclass
class CertificateVerifyHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return HandshakeType.certificate_verify

    @property
    def signature(self) -> bytes:
        return self.data

    # TODO: we need to varify the signature

@dataclass
class HandshakeFinishedHandshakePayload(HandshakePayload):
    @classmethod
    def default_htype(klass) -> int:
        return HandshakeType.finished

    @property
    def verify_data(self) -> bytes:
        return self.data

    @classmethod
    def generate(klass, client_handshake_traffic_secret: bytes, hello_hash: bytes):
        finished_key = HKDF_Expand_Label(
            key=client_handshake_traffic_secret,
            label="finished",
            context=b"",
            length=32,
        )
        verify_data = hmac.new(
            finished_key, msg=hello_hash, digestmod=hashlib.sha256
        ).digest()
        return HandshakeFinishedHandshakePayload(data=verify_data)

    # TODO: there maybe some more checks we want to do with the verify data as well...


utcnow = datetime.datetime.utcnow
@dataclass
class NewSessionTicketHandshakePayload(HandshakePayload):
    ticket_lifetime_seconds: int
    ticket_age_add: int
    ticket_nonce: int
    session_ticket: bytes
    received_time: datetime.datetime

    @classmethod
    def default_htype(klass) -> int:
        return HandshakeType.new_session_ticket

    @property
    def obfuscated_ticket_age(self):
        # see https://tools.ietf.org/html/rfc8446#section-4.2.11.1 for explanation
        # TODO: 这里为什么不是 self.ticket_lifetime_seconds * 1000
        # print("ticket lifetime", self.ticket_lifetime_seconds // 1000)
        # print("ticket add", self.ticket_age_add)
        # return ((self.ticket_lifetime_seconds // 1000) + self.ticket_age_add) % (2 ** 32)
        return (((utcnow() - self.received_time).seconds * 1000) + self.ticket_age_add) % ( 1 << 32 )

    # https://datatracker.ietf.org/doc/html/rfc8446#autoid-55
    def psk(self, resumption_master_secret: bytes):
        tmp_psk = HKDF_Expand_Label(
            key=resumption_master_secret,
            label="resumption", 
            context=self.ticket_nonce, 
            length=32
        )
        print("psk", hexlify(tmp_psk))
        return tmp_psk

    @classmethod
    def deserialize(klass, data: bytes):
        bytes_buffer = BufferedReader(BytesIO(data))
        ticket_lifetime_seconds, = struct.unpack(">I", bytes_buffer.read(4))
        ticket_age_add, = struct.unpack(">I", bytes_buffer.read(4))
        bytes_of_nonce_value_followed, = struct.unpack("b", bytes_buffer.read(1))
        ticket_nonce = bytes_buffer.read(
            bytes_of_nonce_value_followed
        )  # , = #struct.unpack(">H", bytes_buffer.read(2))
        session_ticket_length, = struct.unpack(">H", bytes_buffer.read(2))
        session_ticket = bytes_buffer.read(session_ticket_length)
        if len(session_ticket) < session_ticket_length:
            raise Exception("Need more data!", session_ticket_length)
        if len(bytes_buffer.peek()) > 2:
            extension_data_length, = struct.unpack(">h", bytes_buffer.read(2))
            _extension_data = bytes_buffer.read(extension_data_length)

        return NewSessionTicketHandshakePayload(
            data=data,
            ticket_lifetime_seconds=ticket_lifetime_seconds,
            ticket_age_add=ticket_age_add,
            ticket_nonce=ticket_nonce,
            session_ticket=session_ticket,
            received_time=utcnow()
        )


HANDSHAKE_HEADER_TYPES = {
    EncryptedExtensionHandshakePayload.default_htype(): EncryptedExtensionHandshakePayload,
    CertificateHandshakePayload.default_htype(): CertificateHandshakePayload,
    CertificateVerifyHandshakePayload.default_htype(): CertificateVerifyHandshakePayload,
    HandshakeFinishedHandshakePayload.default_htype(): HandshakeFinishedHandshakePayload,
    NewSessionTicketHandshakePayload.default_htype(): NewSessionTicketHandshakePayload,
}
