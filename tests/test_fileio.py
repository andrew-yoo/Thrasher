import os

import pytest
from bulwark.fileio import read, write
from bulwark.shared import Header

PAYLOAD = b"hello world"


def test_write_creates_file_with_header(tmp_path):
    path = str(tmp_path / "test.blwk")
    write(path, mode=Header.NORMAL, ciphertext=PAYLOAD)
    assert os.path.exists(path)
    with open(path, "rb") as f:
        data = f.read()
    assert len(data) == Header.SIZE + len(PAYLOAD)
    assert data[:4] == Header.MAGIC


def test_write_random_salt(tmp_path):
    p1 = str(tmp_path / "a.blwk")
    p2 = str(tmp_path / "b.blwk")
    write(p1, mode=Header.NORMAL, ciphertext=PAYLOAD)
    write(p2, mode=Header.NORMAL, ciphertext=PAYLOAD)
    with open(p1, "rb") as f:
        salt1 = f.read()[6:38]
    with open(p2, "rb") as f:
        salt2 = f.read()[6:38]
    assert salt1 != salt2


def test_read_roundtrip(tmp_path):
    for mode in (Header.NORMAL, Header.OVERKILL):
        path = str(tmp_path / f"test_{mode}.blwk")
        write(path, mode=mode, ciphertext=PAYLOAD)
        header, ciphertext = read(path)
        assert isinstance(header, Header)
        assert header.mode == mode
        assert ciphertext == PAYLOAD


def test_read_invalid(tmp_path):
    for data in (b"BLWK\x01", b""):
        path = str(tmp_path / "test.blwk")
        with open(path, "wb") as f:
            f.write(data)
        with pytest.raises(ValueError):
            read(path)
