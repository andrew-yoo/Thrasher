import struct


class KDF:
    def __init__(self, salt=None, password=None):
        self.salt = salt
        self.password = password


class Cipher:
    def __init__(self, nonce=None, key=None, ptext=None, ctext=None, ad=None):
        self.nonce = nonce
        self.key = key
        self.ptext = ptext
        self.ctext = ctext
        self.ad = ad


class Header:
    MAGIC = b"CODE"
    VERSION = 0x04
    SIZE = 45
    SALT_SIZE = 32
    CHUNK_SIZE = 1_048_576

    def __init__(self, salt: bytes, length: int) -> None:
        if len(salt) != self.SALT_SIZE:
            raise ValueError("Wrong salt size")
        if length < 0:
            raise ValueError("Invalid length")
        self.salt = salt
        self.length = length

    def to_bytes(self) -> bytes:
        return struct.pack("<4sBQ", self.MAGIC, self.VERSION, self.length) + self.salt

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        if len(data) < cls.SIZE:
            raise ValueError("Wrong header size")
        magic, version, length = struct.unpack_from("<4sBQ", data, 0)
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        if version != cls.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        return cls(salt=data[13:45], length=length)
