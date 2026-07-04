import pytest
from thrasher.encryption import encrypt, decrypt, verify
from thrasher.shared import Cipher, Header

PT = b"hello world"

NORMAL_AEGIS_KEY = bytes.fromhex("16cfd6720ab4cddcb992d16798978c5e5fab4ee71e06be1172d2bcc4e83b8b99")
NORMAL_AEGIS_NONCE = bytes.fromhex("8c25bb161126592c0ac384541c4655277f94b71bcbd4961e322f674678501fbd")

OVERKILL_AEGIS_KEY = bytes.fromhex("4db461711aa9d9a1808c129e5d88485750c226c5b47231c1f4ad83588fac71d4")
OVERKILL_AEGIS_NONCE = bytes.fromhex("d35b030c479fa165ca86676d2b81f8903cf04dcc744e51c15704059a1e252b57")
OVERKILL_XCHACHA_KEY = bytes.fromhex("3dc0d8c58c1e4ed786858c617f36831a1e5700e964af745ee2bdaf08624edc9d")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("6b5fdb6d5fd18cdcfb98b24fa3bbd9da076d9d9ab8a42e28")

NORMAL_CT = bytes.fromhex("00ef8f4a637c3c15098778e7cbd7753dac335634554dab91c120e5a38b622ca306039c023d1eacc1596183")
OVERKILL_CT = bytes.fromhex("d4b7e37cf6f83c09e0a7f9257bc20adf4d9c72bbcdc66e17e07b7a544f90dbabd7061f66062e908ab457be84adcfead31b3a7a9a84f594ea9e8d77")


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
