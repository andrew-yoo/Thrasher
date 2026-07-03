import pytest
from bulwark import kdf
from bulwark.shared import KDF

SALT = b"0123456789abcdef"
PASSWORD = b"password"
WRONG_PASSWORD = b"wrong"

NORMAL_KEY = bytes.fromhex("24cd7d4013432dc68a04d5806ce387f9f8a42ae464f7c99b2da157e92a5b0a2f")
OVERKILL_KEY = bytes.fromhex("22495d9083756044b2277e5619382b425be2d0fa92a1d5b47cb16d0c5ee97cee")


def test_derive_master():
    norm_obj = KDF(salt=SALT, overkill=False, password=PASSWORD)
    over_obj = KDF(salt=SALT, overkill=True, password=PASSWORD)

    assert NORMAL_KEY != OVERKILL_KEY
    assert kdf.derive_master(norm_obj) == NORMAL_KEY
    assert kdf.derive_master(over_obj) == OVERKILL_KEY


def test_verify_master():
    norm_obj = KDF(salt=SALT, overkill=False, password=PASSWORD, key=NORMAL_KEY)
    over_obj = KDF(salt=SALT, overkill=True, password=PASSWORD, key=OVERKILL_KEY)

    assert kdf.verify_master(norm_obj) == None
    assert kdf.verify_master(over_obj) == None

    wrong_norm_obj = KDF(salt=SALT, overkill=False, password=WRONG_PASSWORD, key=NORMAL_KEY)
    wrong_over_obj = KDF(salt=SALT, overkill=True, password=WRONG_PASSWORD, key=OVERKILL_KEY)

    with pytest.raises(Exception, match="Keys do not match"):
        kdf.verify_master(wrong_norm_obj)

    with pytest.raises(Exception, match="Keys do not match"):
        kdf.verify_master(wrong_over_obj)
