import pytest
from bulwark import kdf
from bulwark.shared import Header, KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"
WRONG_PASSWORD = b"wrong"

NORMAL_MASTER_KEY = bytes.fromhex(
    "707d0a0a6e2489c5a6b9d2745af274b23e380176033fcfa8194913b08b1fa97268430a884e84a597f6105c089335aa18fe162b2880084df74996d6d39a78be53"
)
OVERKILL_MASTER_KEY = bytes.fromhex(
    "99bd5d8f1d3bfc25f31d8728f4d62bbb8a60ff21cf0bcec4933e597c7d7109f6f4fbf3d7b21ceb292c472db29ea53417c143c6e79bcf93556d9307c07aee1a3d"
)

NORMAL_AEGIS_KEY = bytes.fromhex("a5b487b76ddf05ab5e8aed28e1f4c913b37da8da772a538561359b2475f0dbd6")
OVERKILL_AEGIS_KEY = bytes.fromhex("b73f55456656c00a3227b2552a858b4363b7f912949760a1d5547b6191dcb460")
OVERKILL_XCHACHA_KEY = bytes.fromhex("d99528047109877af44996fa8a2b20a26e15be31facd8e6f4caceab57d17a77a")

NORMAL_AEGIS_NONCE = bytes.fromhex("5f0a14b79fda1448e3cd159494e03c7422812f992c1926f6ecdb803cbfb7a7ff")
OVERKILL_AEGIS_NONCE = bytes.fromhex("3b0d830a70537a9f34c74eb5876466bff46d4455b7e7128af80d829bfe8904e3")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("b7f6ccfa007509032258a7becce5e618f01b41cfc3a2ba0a")


def test_derive_master():
    norm_obj = KDF(salt=SALT, mode=Header.NORMAL, password=PASSWORD)
    over_obj = KDF(salt=SALT, mode=Header.OVERKILL, password=PASSWORD)
    assert kdf.derive_master(norm_obj) == NORMAL_MASTER_KEY
    assert kdf.derive_master(over_obj) == OVERKILL_MASTER_KEY


def test_verify_master():
    norm_obj = KDF(salt=SALT, mode=Header.NORMAL, password=PASSWORD, key=NORMAL_MASTER_KEY)
    over_obj = KDF(salt=SALT, mode=Header.OVERKILL, password=PASSWORD, key=OVERKILL_MASTER_KEY)
    assert kdf.verify_master(norm_obj) is None
    assert kdf.verify_master(over_obj) is None

    wrong_norm = KDF(salt=SALT, mode=Header.NORMAL, password=WRONG_PASSWORD, key=NORMAL_MASTER_KEY)
    wrong_over = KDF(salt=SALT, mode=Header.OVERKILL, password=WRONG_PASSWORD, key=OVERKILL_MASTER_KEY)
    with pytest.raises(Exception, match="Keys do not match"):
        kdf.verify_master(wrong_norm)
    with pytest.raises(Exception, match="Keys do not match"):
        kdf.verify_master(wrong_over)


def test_derive_aegis_key():
    assert kdf.derive_aegis_key(NORMAL_MASTER_KEY) == NORMAL_AEGIS_KEY
    assert kdf.derive_aegis_key(OVERKILL_MASTER_KEY) == OVERKILL_AEGIS_KEY


def test_derive_xchacha_key():
    assert kdf.derive_xchacha_key(OVERKILL_MASTER_KEY) == OVERKILL_XCHACHA_KEY


def test_derive_aegis_nonce():
    assert kdf.derive_aegis_nonce(NORMAL_MASTER_KEY) == NORMAL_AEGIS_NONCE
    assert kdf.derive_aegis_nonce(OVERKILL_MASTER_KEY) == OVERKILL_AEGIS_NONCE


def test_derive_xchacha_nonce():
    assert kdf.derive_xchacha_nonce(OVERKILL_MASTER_KEY) == OVERKILL_XCHACHA_NONCE
