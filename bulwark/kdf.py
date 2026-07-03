from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from nacl.hash import blake2b
from .shared import KDF

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


def derive_master(master_class):
    if master_class.overkill:
        kdf = Argon2id(
            salt=master_class.salt,
            length=32,
            iterations=OVERKILL_SETTINGS["t"],
            lanes=OVERKILL_SETTINGS["p"],
            memory_cost=OVERKILL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    else:
        kdf = Argon2id(
            salt=master_class.salt,
            length=32,
            iterations=NORMAL_SETTINGS["t"],
            lanes=NORMAL_SETTINGS["p"],
            memory_cost=NORMAL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    return kdf.derive(master_class.password)


def verify_master(master_class):
    if master_class.overkill:
        kdf = Argon2id(
            salt=master_class.salt,
            length=32,
            iterations=OVERKILL_SETTINGS["t"],
            lanes=OVERKILL_SETTINGS["p"],
            memory_cost=OVERKILL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    else:
        kdf = Argon2id(
            salt=master_class.salt,
            length=32,
            iterations=NORMAL_SETTINGS["t"],
            lanes=NORMAL_SETTINGS["p"],
            memory_cost=NORMAL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    return kdf.verify(master_class.password, master_class.key)


def derive_subkey(subkey_class, num):
    return blake2b(subkey_class.key, 64, num, subkey_class.salt)
