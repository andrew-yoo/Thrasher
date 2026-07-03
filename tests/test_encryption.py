import pytest
from bulwark.encryption import encrypt, decrypt, verify
from bulwark.shared import Cipher, Header

PT = b"hello world"

NORMAL_AEGIS_KEY = bytes.fromhex("f9f2394551df773270f7178b589b25ed28150c04b3e584e6591a8f0048ac86c5")
NORMAL_AEGIS_NONCE = bytes.fromhex("e9bd72b478c8801df62c3d3c1e4ad2f08664ab687aeb2f8aa85a80973f93114b")

OVERKILL_AEGIS_KEY = bytes.fromhex("e0b00eb53a54136a0caaddba9b0f430a428bf4c29fbfefef1a82489ece6a3fc2")
OVERKILL_AEGIS_NONCE = bytes.fromhex("08c276a2314ca02f32541eef3d2585b0094b035556a1e08233e0faa40f11a307")
OVERKILL_XCHACHA_KEY = bytes.fromhex("c928e1ad5c7371f140364672ff0c4995cb01a891b0dfd0e8d91eb34859dff88b")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("31ae81fbc702f32d79e4266d6eb3a8bb01de476649c7349c")

NORMAL_CT = bytes.fromhex("8addee6a3ca1fe1b6854713c5dff3dd1463733c9c4165d5e971673e2f90f3615f8c1057764b51771bfb474")
OVERKILL_CT = bytes.fromhex("caf15cd385c2dfa41cb0900fb4b26a39ef19a6e1c52703b7aa7b0d8728dd5112ed9a075b40ccfe5b10ca128e8960c2dc9f58dd5661b45615a3d4de")


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
