from thrasher import kdf
from thrasher.shared import KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"

MASTER_KEY = bytes.fromhex(
    "9c1edba509aadbc6195bffe6ab7f1672952d671a19e63cedbf9513a0eb64aa2ab03ac88fd38070109676c7e08450c54152aebd3d9e726de7a165e04f9f1d6878"
)

AEGIS_KEY = bytes.fromhex("aa08ed542cef8c8e833e9a818d9b44ed0999146e3e720f8151bdd1088479324d")

AEGIS_NONCE = bytes.fromhex("4d3d9522fe58149b1c41c5815fef10ab33b15bb92fad41bd08b862c004e0473e")


def test_derive_master():
    kdf_obj = KDF(salt=SALT, password=PASSWORD)
    assert kdf.derive_master(kdf_obj) == MASTER_KEY


def test_derive_aegis_key():
    assert kdf.derive_aegis_key(MASTER_KEY) == AEGIS_KEY


def test_derive_aegis_nonce():
    assert kdf.derive_aegis_nonce(MASTER_KEY) == AEGIS_NONCE
