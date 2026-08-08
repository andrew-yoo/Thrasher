from thrasher import kdf
from thrasher.shared import KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"

MASTER_KEY = bytes.fromhex(
    "9c1edba509aadbc6195bffe6ab7f1672952d671a19e63cedbf9513a0eb64aa2ab03ac88fd38070109676c7e08450c54152aebd3d9e726de7a165e04f9f1d6878"
)

AEGIS_KEY = bytes.fromhex("73d1d40b72ebc52d8595ca2ee4e502c27cb9d23cba00bec480ec700607bc5924")

CHUNK_NONCES = {
    0: bytes.fromhex("b70f787d99b0ca94dedb6f9d5e3118beda5b7b83ae23c12031db219b29ffeb11"),
    1: bytes.fromhex("91b86b8bf0e2502864b8cf1f9b213832045b9166eb95caa64c07248c7e7ea965"),
    2: bytes.fromhex("2b88bec4587a2414e99e30e00eb652a2bb9fdaa547416d8f4febe2e668914a04"),
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
    assert kdf.derive_aegis_key(MASTER_KEY) != kdf.derive_aegis_key(bytes(64))
