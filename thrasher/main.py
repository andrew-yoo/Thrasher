import os

from .encryption import decrypt as _decrypt
from .encryption import verify as _verify
from .encryption import encrypt as _encrypt
from .fileio import read, write
from .kdf import derive_aegis_key, derive_aegis_nonce, derive_master
from .shared import Cipher, Header, KDF


def encrypt(path: str, password: bytes, overwrite: bool = False) -> None:
    plaintext = read(path)
    salt = os.urandom(Header.SALT_SIZE)

    master_key = derive_master(KDF(salt=salt, password=password))

    aegis_key = derive_aegis_key(master_key)
    aegis_nonce = derive_aegis_nonce(master_key)

    header = Header(salt=salt)
    header_bytes = header.to_bytes()
    aegis = Cipher(nonce=aegis_nonce, key=aegis_key, ptext=plaintext, ad=header_bytes)

    ciphertext = _encrypt(aegis)

    out = header.to_bytes() + ciphertext
    out_path = path if overwrite else path + ".thrash"
    write(out_path, out)


def decrypt(path: str, password: bytes, verify: bool = False, overwrite: bool = False) -> None:
    if not path.endswith(".thrash"):
        raise ValueError("Wrong extension")

    data = read(path)
    header_bytes = data[: Header.SIZE]
    header = Header.from_bytes(header_bytes)
    ciphertext = data[Header.SIZE :]

    master_key = derive_master(KDF(salt=header.salt, password=password))

    aegis_key = derive_aegis_key(master_key)
    aegis_nonce = derive_aegis_nonce(master_key)
    aegis = Cipher(nonce=aegis_nonce, key=aegis_key, ctext=ciphertext, ad=header_bytes)

    if verify:
        _verify(aegis)

    plaintext = _decrypt(aegis)

    out_path = path if overwrite else path.removesuffix(".thrash")
    write(out_path, plaintext)
