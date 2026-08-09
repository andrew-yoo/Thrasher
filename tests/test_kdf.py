from thrasher import kdf
from thrasher.shared import KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"

MASTER_KEY = bytes.fromhex("ba8305a5d4306ec3527b6ac2c13eecb34ea5f9a209b766c9e7afa7627ee67703")

AEGIS_KEY = bytes.fromhex("510ac00ff2f452adadf8b33561508f6526b40cfb20c2a2b42af432688f8bb56c")

CHUNK_NONCES = {
    0: bytes.fromhex("cb6f51c6ff3c4b730de7ec857dfecd040b9a92f718c1c4074b3aeacc7ae5198f"),
    1: bytes.fromhex("c107fca01e20dbc7c255ab8957a63f0094fa05832846282519221fcc8c896ae6"),
    2: bytes.fromhex("cf9d8bb94746f4c6952febe124d8d5aea19d093c5b892247882cee7e38045aae"),
}


def test_derive_master():
    kdf_obj = KDF(salt=SALT, password=PASSWORD)
    assert kdf.derive_master(kdf_obj) == MASTER_KEY


def test_derive_aegis_key():
    assert kdf.derive_aegis_key(MASTER_KEY) == AEGIS_KEY


def test_derive_chunk_nonce_vectors():
    for index, expected in CHUNK_NONCES.items():
        assert kdf.derive_chunk_nonce(MASTER_KEY, index) == expected


def test_derive_chunk_nonce_unique():
    nonces = [kdf.derive_chunk_nonce(MASTER_KEY, i) for i in range(32)]
    assert len(set(nonces)) == len(nonces)


def test_derive_chunk_nonce_distinct_from_key():
    for i in range(8):
        assert kdf.derive_chunk_nonce(MASTER_KEY, i) != AEGIS_KEY
    assert kdf.derive_aegis_key(MASTER_KEY) != kdf.derive_aegis_key(bytes(32))
