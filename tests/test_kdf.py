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

NORMAL_AEGIS_KEY = bytes.fromhex("f9f2394551df773270f7178b589b25ed28150c04b3e584e6591a8f0048ac86c5")
OVERKILL_AEGIS_KEY = bytes.fromhex("e0b00eb53a54136a0caaddba9b0f430a428bf4c29fbfefef1a82489ece6a3fc2")
OVERKILL_XCHACHA_KEY = bytes.fromhex("c928e1ad5c7371f140364672ff0c4995cb01a891b0dfd0e8d91eb34859dff88b")

NORMAL_AEGIS_NONCE = bytes.fromhex("e9bd72b478c8801df62c3d3c1e4ad2f08664ab687aeb2f8aa85a80973f93114b")
OVERKILL_AEGIS_NONCE = bytes.fromhex("08c276a2314ca02f32541eef3d2585b0094b035556a1e08233e0faa40f11a307")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("31ae81fbc702f32d79e4266d6eb3a8bb01de476649c7349c")


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
