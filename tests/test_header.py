import pytest
from thrasher.shared import Header

SALT = bytes(range(32))
LENGTH = 1_000


def test_roundtrip():
    h = Header(salt=SALT, length=LENGTH)
    h2 = Header.from_bytes(h.to_bytes())
    assert h2.salt == SALT
    assert h2.length == LENGTH


def test_from_bytes_errors():
    with pytest.raises(ValueError, match="Wrong header size"):
        Header.from_bytes(b"CODE\x03" + bytes(39))
    with pytest.raises(ValueError, match="Invalid magic"):
        Header.from_bytes(b"NOPE" + bytes(41))
    with pytest.raises(ValueError, match="Unsupported version"):
        Header.from_bytes(b"CODE" + bytes([0xFF]) + bytes(8) + bytes(32))


def test_init_errors():
    with pytest.raises(ValueError, match="Wrong salt size"):
        Header(salt=b"tooshort", length=LENGTH)
    with pytest.raises(ValueError, match="Invalid length"):
        Header(salt=SALT, length=-1)
