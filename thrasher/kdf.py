from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

SETTINGS = {
    "m": 2_097_152,
    "t": 8,
    "p": 4,
}


def derive_key(kdf_class):
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
