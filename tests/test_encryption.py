import pytest
from thrasher.encryption import encrypt, decrypt, verify
from thrasher.shared import Cipher

PT = b"hello world"

AEGIS_KEY = bytes.fromhex("16cfd6720ab4cddcb992d16798978c5e5fab4ee71e06be1172d2bcc4e83b8b99")
AEGIS_NONCE = bytes.fromhex("8c25bb161126592c0ac384541c4655277f94b71bcbd4961e322f674678501fbd")

CT = bytes.fromhex("00ef8f4a637c3c15098778e7cbd7753dac335634554dab91c120e5a38b622ca306039c023d1eacc1596183")


def test_encrypt():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, ptext=PT)
    assert encrypt(cipher) == CT


def test_decrypt():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, ctext=CT)
    assert decrypt(cipher) == PT


def test_wrong_key_raises():
    cipher = Cipher(nonce=AEGIS_NONCE, key=bytes(32), ctext=CT)
    with pytest.raises(Exception):
        decrypt(cipher)


def test_tampered_ciphertext_raises():
    tampered = bytearray(CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, ctext=bytes(tampered))
    with pytest.raises(Exception):
        decrypt(cipher)


def test_verify_valid():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, ctext=CT)
    verify(cipher)


def test_verify_wrong_key():
    cipher = Cipher(nonce=AEGIS_NONCE, key=bytes(32), ctext=CT)
    with pytest.raises(Exception):
        verify(cipher)


def test_verify_tampered():
    tampered = bytearray(CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, ctext=bytes(tampered))
    with pytest.raises(Exception):
        verify(cipher)
