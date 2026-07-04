import os

from .encryption import decrypt as _decrypt
from .encryption import verify as _verify
from .encryption import encrypt as _encrypt
from .fileio import read, write
from .kdf import (
    derive_aegis_key,
    derive_aegis_nonce,
    derive_master,
    derive_xchacha_key,
    derive_xchacha_nonce,
)
from .shared import Cipher, Header, KDF


def encrypt(path: str, password: bytes, mode: int, overwrite: bool = False) -> None:
    plaintext = read(path)
    salt = os.urandom(Header.SALT_SIZE)

    master_key = derive_master(KDF(salt=salt, mode=mode, password=password))

    aegis_key = derive_aegis_key(master_key)
    aegis_nonce = derive_aegis_nonce(master_key)

    header = Header(mode=mode, salt=salt)
    header_bytes = header.to_bytes()
    aegis = Cipher(nonce=aegis_nonce, key=aegis_key, mode=mode, ptext=plaintext, ad=header_bytes)

    if mode == Header.OVERKILL:
        xchacha_key = derive_xchacha_key(master_key)
        xchacha_nonce = derive_xchacha_nonce(master_key)
        xchacha = Cipher(nonce=xchacha_nonce, key=xchacha_key, mode=mode, ptext=plaintext)
        ciphertext = _encrypt(aegis, xchacha)
    else:
        ciphertext = _encrypt(aegis)

    out = header.to_bytes() + ciphertext
    out_path = path if overwrite else path + ".blwk"
    write(out_path, out)


def decrypt(path: str, password: bytes, verify: bool = False, overwrite: bool = False) -> None:
    if not path.endswith(".blwk"):
        raise ValueError("Wrong extension")

    data = read(path)
    header_bytes = data[: Header.SIZE]
    header = Header.from_bytes(header_bytes)
    ciphertext = data[Header.SIZE :]

    master_key = derive_master(KDF(salt=header.salt, mode=header.mode, password=password))

    aegis_key = derive_aegis_key(master_key)
    aegis_nonce = derive_aegis_nonce(master_key)
    aegis = Cipher(nonce=aegis_nonce, key=aegis_key, mode=header.mode, ctext=ciphertext, ad=header_bytes)

    if header.mode == Header.OVERKILL:
        xchacha_key = derive_xchacha_key(master_key)
        xchacha_nonce = derive_xchacha_nonce(master_key)
        xchacha = Cipher(nonce=xchacha_nonce, key=xchacha_key, mode=header.mode)
    else:
        xchacha = None

    if verify:
        _verify(aegis)

    plaintext = _decrypt(aegis, xchacha)

    out_path = path if overwrite else path.removesuffix(".blwk")
    write(out_path, plaintext)
