import os

from bulwark.fileio import read, write


def test_write_and_read(tmp_path):
    path = str(tmp_path / "test.bin")
    data = b"hello world"
    write(path, data)
    assert read(path) == data


def test_write_creates_file(tmp_path):
    path = str(tmp_path / "test.bin")
    write(path, b"data")
    assert os.path.exists(path)


def test_read_empty_file(tmp_path):
    path = str(tmp_path / "test.bin")
    write(path, b"")
    assert read(path) == b""
