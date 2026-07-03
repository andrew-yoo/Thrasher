from nacl.bindings import (
    crypto_aead_aegis256_decrypt,
    crypto_aead_aegis256_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from .shared import Cipher


def encrypt(aegis_class, xchacha_class=None):
    if not xchacha_class:
        aegis_class.ctext = crypto_aead_aegis256_encrypt(aegis_class.ptext, None, aegis_class.nonce, aegis_class.key)
        return aegis_class.ctext

    else:
        # Cascade: XChaCha20-Poly1305 (inner) then AEGIS-256 (outer)
        xchacha_class.ctext = crypto_aead_xchacha20poly1305_ietf_encrypt(xchacha_class.ptext, None, xchacha_class.nonce, xchacha_class.key)
        aegis_class.ctext = crypto_aead_aegis256_encrypt(xchacha_class.ctext, None, aegis_class.nonce, aegis_class.key)
        return aegis_class.ctext


def decrypt(aegis_class, xchacha_class=None):
    if not xchacha_class:
        aegis_class.ptext = crypto_aead_aegis256_decrypt(aegis_class.ctext, None, aegis_class.nonce, aegis_class.key)
        return aegis_class.ptext

    else:
        # Cascade: AEGIS-256 (outer) then XChaCha20-Poly1305 (inner)
        aegis_class.ptext = crypto_aead_aegis256_decrypt(aegis_class.ctext, None, aegis_class.nonce, aegis_class.key)
        xchacha_class.ptext = crypto_aead_xchacha20poly1305_ietf_decrypt(aegis_class.ptext, None, xchacha_class.nonce, xchacha_class.key)
        return xchacha_class.ptext
