import struct
from dataclasses import dataclass
from enum import IntEnum

class ContentType(IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23

TLS_VERSION_1_0 = 0x0301
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304

# record header 5个字节
# type 1 byte, 比如handshake protocol：22， change cipher spec protocol: 20, application data: 23
# legacy protocol version: 0x0303(tls1.2)
# size 2 bytes
@dataclass
class RecordHeader:
    rtype: int
    size: int
    legacy_proto_version: int = 0x0303

    @classmethod
    def deserialize(klass, data: bytes):
        record_type = data[0]
        legacy_proto_version, size = struct.unpack(">2H", data[1:])
        return RecordHeader(
            rtype=record_type, legacy_proto_version=legacy_proto_version, size=size
        )

    # 1 byte DTLS记录类型(0x16 22 handshake)
    # 2 bytes 协议版本(03 01 3.1 即tls1.0)
    # 2 bytes payload length(00 f8 248个字节)
    def serialize(self) -> bytes:
        return b"".join(
            [
                struct.pack("b", self.rtype),
                struct.pack(">H", self.legacy_proto_version),
                struct.pack(">H", self.size),
            ]
        )
