import pytest
from thrasher.shared import Header

SALT = bytes(range(32))


def test_roundtrip():
    h = Header(salt=SALT)
    h2 = Header.from_bytes(h.to_bytes())
    assert h2.salt == SALT


def test_from_bytes_errors():
    with pytest.raises(ValueError, match="Wrong header size"):
        Header.from_bytes(b"CODE\x01")
    with pytest.raises(ValueError, match="Invalid magic"):
        Header.from_bytes(b"NOPE" + bytes(33))
    with pytest.raises(ValueError, match="Unsupported version"):
        Header.from_bytes(b"CODE" + bytes([0xFF]) + bytes(32))


def test_init_errors():
    with pytest.raises(ValueError, match="Wrong salt size"):
        Header(salt=b"tooshort")
