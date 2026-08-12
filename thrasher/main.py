import os

from .encryption import decrypt as _decrypt
from .encryption import encrypt as _encrypt
from .fileio import atomic_write, read_chunks, read_exact
from .kdf import derive_key
from .shared import Cipher, Header, KDF


def chunk_nonce(index: int) -> bytes:
    return index.to_bytes(8, "big") + bytes(24)


def _record_count(length: int) -> int:
    return max(1, (length + Header.CHUNK_SIZE - 1) // Header.CHUNK_SIZE)


def encrypt(path: str, password: bytes, overwrite: bool = False) -> None:
    plaintext_size = os.path.getsize(path)
    salt = os.urandom(Header.SALT_SIZE)

    key = derive_key(KDF(salt=salt, password=password))

    header = Header(salt=salt, length=plaintext_size)
    header_bytes = header.to_bytes()

    chunks = read_chunks(path, Header.CHUNK_SIZE)
    out_path = path + ".thrash"
    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(f"A file at {out_path} already exists but can be overwritten with -w")
    with atomic_write(out_path, overwrite=overwrite) as out:
        out.write(header_bytes)
        for i in range(_record_count(plaintext_size)):
            chunk = next(chunks, b"")
            nonce = chunk_nonce(i)
            cipher = Cipher(nonce=nonce, key=key, ptext=chunk, ad=header_bytes if i == 0 else b"")
            out.write(_encrypt(cipher))


def decrypt(path: str, password: bytes, overwrite: bool = False) -> None:
    if not path.endswith(".thrash"):
        raise ValueError("Wrong extension")

    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        header_bytes = read_exact(f, Header.SIZE)
        header = Header.from_bytes(header_bytes)

        records = _record_count(header.length)
        if file_size != Header.SIZE + header.length + records * 32:
            raise ValueError("Corrupt file: unexpected size")

        key = derive_key(KDF(salt=header.salt, password=password))

        out_path = path.removesuffix(".thrash")
        if not out_path or (os.path.exists(out_path) and not overwrite):
            raise FileExistsError(f"{out_path} already exists; use -w/--overwrite to overwrite")
        with atomic_write(out_path, overwrite=overwrite) as out:
            recovered = 0
            for i in range(records):
                remaining = header.length - recovered
                chunk_len = min(Header.CHUNK_SIZE, remaining) if remaining > 0 else 0
                record = read_exact(f, chunk_len + 32)
                nonce = chunk_nonce(i)
                cipher = Cipher(nonce=nonce, key=key, ctext=record, ad=header_bytes if i == 0 else b"")
                plaintext = _decrypt(cipher)
                out.write(plaintext)
                recovered += len(plaintext)

            if f.read(1) != b"":
                raise ValueError("Corrupt file: trailing data")
            f.close()
