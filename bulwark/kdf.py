from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from shared import Argon

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


def derive(argon_class):
    if argon_class.overkill:
        kdf = Argon2id(
            salt=argon_class.salt,
            length=32,
            iterations=OVERKILL_SETTINGS["t"],
            lanes=OVERKILL_SETTINGS["p"],
            memory_cost=OVERKILL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    else:
        kdf = Argon2id(
            salt=argon_class.salt,
            length=32,
            iterations=NORMAL_SETTINGS["t"],
            lanes=NORMAL_SETTINGS["p"],
            memory_cost=NORMAL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    return kdf.derive(argon_class.password)

def verify(argon_class):
    if argon_class.overkill:
        kdf = Argon2id(
            salt=argon_class.salt,
            length=32,
            iterations=OVERKILL_SETTINGS["t"],
            lanes=OVERKILL_SETTINGS["p"],
            memory_cost=OVERKILL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    else:
        kdf = Argon2id(
            salt=argon_class.salt,
            length=32,
            iterations=NORMAL_SETTINGS["t"],
            lanes=NORMAL_SETTINGS["p"],
            memory_cost=NORMAL_SETTINGS["m"],
            ad=None,
            secret=None,
        )
    return kdf.verify(argon_class.password, argon_class.key)