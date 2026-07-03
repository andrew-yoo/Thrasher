import pytest
from bulwark.encryption import encrypt, decrypt, verify
from bulwark.shared import Cipher

PT = b"hello world"

AEGIS_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
AEGIS_NONCE = bytes(32)

XCHACHA_KEY = bytes.fromhex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
XCHACHA_NONCE = bytes([9] * 24)

NORMAL_CT = bytes.fromhex("df78a5ce3cb31d32a43684e511f95c2a58770a926e4fcb5d3efd3b003ddcd87a29183dc4b913e01cf9a4dd")
OVERKILL_CT = bytes.fromhex("0f061c3509bd3899e5308ef7b8f236012fe23432d301eedc2ab7cf0f94ca2f0970006a46661b7f664e586b2bddf125f9f3baa8947c198281224a25")


def test_normal_encrypt():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=False, ptext=PT)
    assert encrypt(cipher) == NORMAL_CT


def test_normal_decrypt():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=False, ctext=NORMAL_CT)
    assert decrypt(cipher) == PT


def test_overkill_encrypt():
    aegis = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=True, ptext=PT)
    xchacha = Cipher(nonce=XCHACHA_NONCE, key=XCHACHA_KEY, overkill=True, ptext=PT)
    assert encrypt(aegis, xchacha) == OVERKILL_CT


def test_overkill_decrypt():
    aegis = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=True, ctext=OVERKILL_CT)
    xchacha = Cipher(nonce=XCHACHA_NONCE, key=XCHACHA_KEY, overkill=True)
    assert decrypt(aegis, xchacha) == PT


def test_wrong_key_raises():
    cipher = Cipher(nonce=AEGIS_NONCE, key=bytes(32), overkill=False, ctext=NORMAL_CT)
    with pytest.raises(Exception):
        decrypt(cipher)


def test_tampered_ciphertext_raises():
    # Flip a single bit in the ciphertext
    tampered = bytearray(NORMAL_CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=False, ctext=bytes(tampered))
    with pytest.raises(Exception):
        decrypt(cipher)


def test_verify_valid():
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=False, ctext=NORMAL_CT)
    verify(cipher)


def test_verify_wrong_key():
    cipher = Cipher(nonce=AEGIS_NONCE, key=bytes(32), overkill=False, ctext=NORMAL_CT)
    with pytest.raises(Exception):
        verify(cipher)


def test_verify_tampered():
    tampered = bytearray(NORMAL_CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=AEGIS_NONCE, key=AEGIS_KEY, overkill=False, ctext=bytes(tampered))
    with pytest.raises(Exception):
        verify(cipher)
