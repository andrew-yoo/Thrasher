import pytest

from thrasher import kdf as kdf_module
from thrasher.main import chunk_nonce, decrypt, encrypt
from thrasher.shared import Header

PASSWORD = b"pw"
CHUNK = Header.CHUNK_SIZE
REC = CHUNK + 32


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(kdf_module, "SETTINGS", {"m": 65_536, "t": 1, "p": 1})


def data(n):
    return bytes(range(256)) * (n // 256) + bytes(range(n % 256))


def test_chunk_nonce():
    assert len(chunk_nonce(0)) == 32
    assert chunk_nonce(0) == b"\x00" * 8 + b"\x00" * 24
    assert chunk_nonce(5)[:8] == (5).to_bytes(8, "big")
    assert chunk_nonce(5)[8:] == bytes(24)
    assert len({chunk_nonce(i) for i in range(1024)}) == 1024


def encrypt_to(tmp_path, size):
    src = tmp_path / "in.bin"
    src.write_bytes(data(size))
    encrypt(str(src), PASSWORD)
    return str(src) + ".thrash"


@pytest.mark.parametrize("size", [0, 1, 12345, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 777])
def test_roundtrip(tmp_path, size):
    enc = encrypt_to(tmp_path, size)
    decrypt(enc, PASSWORD, overwrite=True)
    assert open(enc, "rb").read() == data(size)


def read_bytes(enc):
    with open(enc, "rb") as f:
        return bytearray(f.read())


def write_bytes(enc, payload):
    with open(enc, "wb") as f:
        f.write(payload)


def _flip(d):
    d[Header.SIZE + 100] ^= 0x01


def _truncate_tail(d):
    del d[Header.SIZE :]


def _truncate_mid(d):
    del d[Header.SIZE + 100 :]


def _reorder(d):
    first = bytes(d[Header.SIZE : Header.SIZE + REC])
    second = bytes(d[Header.SIZE + REC : Header.SIZE + 2 * REC])
    d[Header.SIZE : Header.SIZE + 2 * REC] = second + first


def _duplicate(d):
    first = bytes(d[Header.SIZE : Header.SIZE + REC])
    d[Header.SIZE + REC : Header.SIZE + 2 * REC] = first


def _length_field(d):
    d[8] ^= 0x80


def _salt(d):
    d[13] ^= 0x80


def _append(d):
    d += b"extra"


ATTACKS = [
    pytest.param(12345, _flip, id="flip-payload-byte"),
    pytest.param(2 * CHUNK, _truncate_tail, id="truncate-at-boundary"),
    pytest.param(CHUNK + 100, _truncate_mid, id="truncate-mid-record"),
    pytest.param(2 * CHUNK, _reorder, id="reorder-chunks"),
    pytest.param(2 * CHUNK, _duplicate, id="duplicate-chunk"),
    pytest.param(100, _length_field, id="tamper-length"),
    pytest.param(100, _salt, id="tamper-salt"),
    pytest.param(1000, _append, id="append-trailing-data"),
]


@pytest.mark.parametrize("size,mutate", ATTACKS)
def test_attacks_rejected(tmp_path, size, mutate):
    enc = encrypt_to(tmp_path, size)
    payload = read_bytes(enc)
    mutate(payload)
    write_bytes(enc, payload)
    with pytest.raises(Exception):
        decrypt(enc, PASSWORD, overwrite=True)


def test_wrong_password(tmp_path):
    enc = encrypt_to(tmp_path, 100)
    with pytest.raises(Exception):
        decrypt(enc, b"nope", overwrite=True)


def test_wrong_extension(tmp_path):
    f = tmp_path / "in.bin"
    f.write_bytes(b"data")
    with pytest.raises(ValueError):
        decrypt(str(f), PASSWORD)


def test_empty_file_header_authenticated(tmp_path):
    enc = encrypt_to(tmp_path, 0)
    assert len(read_bytes(enc)) == Header.SIZE + 32
    payload = read_bytes(enc)
    _salt(payload)
    write_bytes(enc, payload)
    with pytest.raises(Exception):
        decrypt(enc, PASSWORD, overwrite=True)
