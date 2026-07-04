import pytest
from bulwark.main import decrypt


def test_decrypt_non_blwk_extension(tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(b"data")
    with pytest.raises(ValueError, match="Expected .blwk file extension"):
        decrypt(str(path), b"password")
