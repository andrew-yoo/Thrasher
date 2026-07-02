import pytest
from cryptography.exceptions import InvalidKey
from bulwark import kdf
from bulwark.shared import KDF

SALT = b"0123456789abcdef"
PASSWORD = b"password"
WRONG_PASSWORD = b"wrong"

NORMAL_KEY = bytes.fromhex("24cd7d4013432dc68a04d5806ce387f9f8a42ae464f7c99b2da157e92a5b0a2f")
OVERKILL_KEY = bytes.fromhex("22495d9083756044b2277e5619382b425be2d0fa92a1d5b47cb16d0c5ee97cee")


def test_derive():
    norm_obj = KDF(salt=SALT, overkill=False, password=PASSWORD)
    over_obj = KDF(salt=SALT, overkill=True, password=PASSWORD)

    assert NORMAL_KEY != OVERKILL_KEY
    assert kdf.derive(norm_obj) == NORMAL_KEY
    assert kdf.derive(over_obj) == OVERKILL_KEY


def test_verify():
    norm_obj = KDF(salt=SALT, overkill=False, password=PASSWORD, key=NORMAL_KEY)
    over_obj = KDF(salt=SALT, overkill=True, password=PASSWORD, key=OVERKILL_KEY)

    assert kdf.verify(norm_obj) == None
    assert kdf.verify(over_obj) == None

    wrong_norm_obj = KDF(salt=SALT, overkill=False, password=WRONG_PASSWORD, key=NORMAL_KEY)
    wrong_over_obj = KDF(salt=SALT, overkill=False, password=WRONG_PASSWORD, key=NORMAL_KEY)

    with pytest.raises(Exception):
        kdf.verify(wrong_norm_obj)

    with pytest.raises(Exception):
        kdf.verify(wrong_over_obj)
