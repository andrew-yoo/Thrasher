from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import nacl.hash
import nacl.encoding

SETTINGS = {
    "m": 2_097_152,
    "t": 8,
    "p": 4,
}


def derive_master(kdf_class):
    kdf = Argon2id(
        salt=kdf_class.salt,
        length=32,
        iterations=SETTINGS["t"],
        lanes=SETTINGS["p"],
        memory_cost=SETTINGS["m"],
        ad=None,
        secret=None,
    )
    return kdf.derive(kdf_class.password)


def _blake2b(key, digest_size, person):
    return nacl.hash.blake2b(b"", digest_size, key, person=person, encoder=nacl.encoding.RawEncoder)


def _person(value: int) -> bytes:
    return value.to_bytes(16, "big")


def derive_aegis_key(master_key):
    return _blake2b(master_key, 32, _person(0))


def derive_chunk_nonce(master_key, index: int) -> bytes:
    return _blake2b(master_key, 32, _person(index + 1))
