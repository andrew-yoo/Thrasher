from thrasher import kdf
from thrasher.shared import KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"

MASTER_KEY = bytes.fromhex("ba8305a5d4306ec3527b6ac2c13eecb34ea5f9a209b766c9e7afa7627ee67703")


def test_derive_key():
    kdf_obj = KDF(salt=SALT, password=PASSWORD)
    assert kdf.derive_key(kdf_obj) == MASTER_KEY
