import nacl
from .shared import Cipher

AEGIS_NONCE = 256
XCHACHA_NONCE = 192

# PyNaCl has no high-level bindings for AEGIS


def encrypt(cipher_class):
    e = nacl.bindings.crypto_aead_aegis256_encrypt
    if cipher_class.overkill:
        pass

    else:
        pass


def decrypt(cipher_class):
    d = nacl.bindings.crypto_aead_aegis256_decrypt
    if cipher_class.overkill:
        pass

    else:
        pass
