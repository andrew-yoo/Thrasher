import pytest
from bulwark.encryption import encrypt, decrypt, verify
from bulwark.shared import Cipher, Header

PT = b"hello world"

NORMAL_AEGIS_KEY = bytes.fromhex("a5b487b76ddf05ab5e8aed28e1f4c913b37da8da772a538561359b2475f0dbd6")
NORMAL_AEGIS_NONCE = bytes.fromhex("5f0a14b79fda1448e3cd159494e03c7422812f992c1926f6ecdb803cbfb7a7ff")

OVERKILL_AEGIS_KEY = bytes.fromhex("b73f55456656c00a3227b2552a858b4363b7f912949760a1d5547b6191dcb460")
OVERKILL_AEGIS_NONCE = bytes.fromhex("3b0d830a70537a9f34c74eb5876466bff46d4455b7e7128af80d829bfe8904e3")
OVERKILL_XCHACHA_KEY = bytes.fromhex("d99528047109877af44996fa8a2b20a26e15be31facd8e6f4caceab57d17a77a")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("b7f6ccfa007509032258a7becce5e618f01b41cfc3a2ba0a")

NORMAL_CT = bytes.fromhex("a312334eb2fb864fe7b74c03c041a3063e71bf6d4651b5537d233a9f53000904eec1b6723b594ff452b3ca")
OVERKILL_CT = bytes.fromhex("9144e00781054b65894dd491301d0994bbb1e495bc46161a923d7d189b8f4662ec2dbc4ef22838ac521ba9d8eb497af391725076e84ff9b31c005f")


def test_normal_encrypt():
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=NORMAL_AEGIS_KEY, mode=Header.NORMAL, ptext=PT)
    assert encrypt(cipher) == NORMAL_CT


def test_normal_decrypt():
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=NORMAL_AEGIS_KEY, mode=Header.NORMAL, ctext=NORMAL_CT)
    assert decrypt(cipher) == PT


def test_overkill_encrypt():
    aegis = Cipher(nonce=OVERKILL_AEGIS_NONCE, key=OVERKILL_AEGIS_KEY, mode=Header.OVERKILL, ptext=PT)
    xchacha = Cipher(nonce=OVERKILL_XCHACHA_NONCE, key=OVERKILL_XCHACHA_KEY, mode=Header.OVERKILL, ptext=PT)
    assert encrypt(aegis, xchacha) == OVERKILL_CT


def test_overkill_decrypt():
    aegis = Cipher(nonce=OVERKILL_AEGIS_NONCE, key=OVERKILL_AEGIS_KEY, mode=Header.OVERKILL, ctext=OVERKILL_CT)
    xchacha = Cipher(nonce=OVERKILL_XCHACHA_NONCE, key=OVERKILL_XCHACHA_KEY, mode=Header.OVERKILL)
    assert decrypt(aegis, xchacha) == PT


def test_wrong_key_raises():
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=bytes(32), mode=Header.NORMAL, ctext=NORMAL_CT)
    with pytest.raises(Exception):
        decrypt(cipher)


def test_tampered_ciphertext_raises():
    tampered = bytearray(NORMAL_CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=NORMAL_AEGIS_KEY, mode=Header.NORMAL, ctext=bytes(tampered))
    with pytest.raises(Exception):
        decrypt(cipher)


def test_verify_valid():
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=NORMAL_AEGIS_KEY, mode=Header.NORMAL, ctext=NORMAL_CT)
    verify(cipher)


def test_verify_wrong_key():
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=bytes(32), mode=Header.NORMAL, ctext=NORMAL_CT)
    with pytest.raises(Exception):
        verify(cipher)


def test_verify_tampered():
    tampered = bytearray(NORMAL_CT)
    tampered[0] ^= 0x01
    cipher = Cipher(nonce=NORMAL_AEGIS_NONCE, key=NORMAL_AEGIS_KEY, mode=Header.NORMAL, ctext=bytes(tampered))
    with pytest.raises(Exception):
        verify(cipher)
