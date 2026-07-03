from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from nacl.hash import blake2b

from .shared import Header

NORMAL_SETTINGS = {
    "m": 1_048_576,
    "t": 4,
    "p": 4,
}
OVERKILL_SETTINGS = {
    "m": 2_097_152,
    "t": 8,
    "p": 8,
}


def derive_master(kdf_class):
    if kdf_class.mode == Header.OVERKILL:
        settings = OVERKILL_SETTINGS
    else:
        settings = NORMAL_SETTINGS
    kdf = Argon2id(
        salt=kdf_class.salt,
        length=64,
        iterations=settings["t"],
        lanes=settings["p"],
        memory_cost=settings["m"],
        ad=None,
        secret=None,
    )
    return kdf.derive(kdf_class.password)


def _blake2b(key, digest_size, person):
    return bytes.fromhex(blake2b(person, digest_size, key).decode())


def derive_aegis_key(master_key):
    return _blake2b(master_key, 32, b"\x01")


def derive_xchacha_key(master_key):
    return _blake2b(master_key, 32, b"\x02")


def derive_aegis_nonce(master_key):
    return _blake2b(master_key, 32, b"\x03")


def derive_xchacha_nonce(master_key):
    return _blake2b(master_key, 24, b"\x04")
