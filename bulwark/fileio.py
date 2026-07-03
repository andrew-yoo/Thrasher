import os

from .shared import Header


def write(path: str, mode: int, ciphertext: bytes) -> None:
    salt = os.urandom(Header.SALT_SIZE)
    header = Header(mode=mode, salt=salt)
    with open(path, "wb") as f:
        f.write(header.to_bytes())
        f.write(ciphertext)


def read(path: str) -> tuple[Header, bytes]:
    with open(path, "rb") as f:
        raw_header = f.read(Header.SIZE)
        if len(raw_header) < Header.SIZE:
            raise ValueError("File too short to contain a valid header")
        header = Header.from_bytes(raw_header)
        ciphertext = f.read()
    return header, ciphertext
