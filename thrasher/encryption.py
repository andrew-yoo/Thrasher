from nacl.bindings import crypto_aead_aegis256_decrypt, crypto_aead_aegis256_encrypt


def encrypt(cipher_class):
    cipher_class.ctext = crypto_aead_aegis256_encrypt(cipher_class.ptext, cipher_class.ad, cipher_class.nonce, cipher_class.key)
    return cipher_class.ctext


def decrypt(cipher_class):
    cipher_class.ptext = crypto_aead_aegis256_decrypt(cipher_class.ctext, cipher_class.ad, cipher_class.nonce, cipher_class.key)
    return cipher_class.ptext
