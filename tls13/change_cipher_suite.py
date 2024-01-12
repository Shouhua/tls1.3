from tls13.record_header import RecordHeader, ContentType
from io import BytesIO
from dataclasses import dataclass

@dataclass
class ChangeCipherSuite:
    record_header: RecordHeader
    payload: bytes

    @classmethod
    def deserialize(klass, byte_stream: BytesIO):
        rh = RecordHeader.deserialize(byte_stream.read(5))
        # https://datatracker.ietf.org/doc/html/rfc8446#autoid-58 change cipher spec仅仅是为了兼容
        assert rh.rtype == ContentType.change_cipher_spec # 0x14
        assert rh.size == 1
        payload = byte_stream.read(rh.size)
        assert payload == b"\x01"
        return klass(rh, payload)

    def serialize(self):
        return b"".join([self.record_header.serialize(), self.payload])
