import pytest
from bulwark.shared import Header

SALT = bytes(range(32))


def test_roundtrip():
    for mode in (Header.NORMAL, Header.OVERKILL):
        h = Header(mode=mode, salt=SALT)
        h2 = Header.from_bytes(h.to_bytes())
        assert h2.mode == mode
        assert h2.salt == SALT


def test_from_bytes_errors():
    with pytest.raises(ValueError, match="Wrong header size"):
        Header.from_bytes(b"BLWK\x01\x00")
    with pytest.raises(ValueError, match="Invalid magic"):
        Header.from_bytes(b"NOPE" + bytes(34))
    with pytest.raises(ValueError, match="Unsupported version"):
        Header.from_bytes(b"BLWK" + bytes([0xFF, 0x00]) + bytes(32))


def test_init_errors():
    with pytest.raises(ValueError, match="Invalid mode"):
        Header(mode=5, salt=SALT)
    with pytest.raises(ValueError, match="Wrong salt size"):
        Header(mode=Header.NORMAL, salt=b"tooshort")
