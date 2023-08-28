import struct
from dataclasses import dataclass


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
