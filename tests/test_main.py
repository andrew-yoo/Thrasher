import pytest
from thrasher.main import decrypt


def test_decrypt_non_thrash_extension(tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(b"data")
    with pytest.raises(ValueError):
        decrypt(str(path), b"password")
