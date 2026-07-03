import struct


class KDF:
    def __init__(self, salt=None, mode=None, password=None):
        self.salt = salt
        self.mode = mode
        self.password = password


class Cipher:
    def __init__(self, nonce=None, key=None, mode=None, ptext=None, ctext=None):
        self.nonce = nonce
        self.key = key
        self.mode = mode
        self.ptext = ptext
        self.ctext = ctext


class Header:
    MAGIC = b"BLWK"
    VERSION = 0x02
    SIZE = 38
    SALT_SIZE = 32
    NORMAL, OVERKILL = 0, 1

    def __init__(self, mode: int, salt: bytes) -> None:
        if mode not in (self.NORMAL, self.OVERKILL):
            raise ValueError(f"Invalid mode: {mode}")
        if len(salt) != self.SALT_SIZE:
            raise ValueError("Wrong salt size")
        self.mode = mode
        self.salt = salt

    def to_bytes(self) -> bytes:
        return struct.pack("<4sBB", self.MAGIC, self.VERSION, self.mode) + self.salt

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        if len(data) < cls.SIZE:
            raise ValueError("Wrong header size")
        magic, version, mode = struct.unpack_from("<4sBB", data, 0)
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        if version != cls.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        return cls(mode=mode, salt=data[6:38])
