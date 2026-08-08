from nacl.bindings import crypto_aead_aegis256_decrypt, crypto_aead_aegis256_encrypt


def encrypt(aegis_class):
    aegis_class.ctext = crypto_aead_aegis256_encrypt(aegis_class.ptext, aegis_class.ad, aegis_class.nonce, aegis_class.key)
    return aegis_class.ctext


def decrypt(aegis_class):
    aegis_class.ptext = crypto_aead_aegis256_decrypt(aegis_class.ctext, aegis_class.ad, aegis_class.nonce, aegis_class.key)
    return aegis_class.ptext
