class KDF:
    def __init__(self, salt, overkill, password, key=None):
        self.salt = salt
        self.overkill = overkill
        self.password = password
        self.key = key


class Cipher:
    def __init__(self, nonce, key, overkill, ptext=None, ctext=None):
        self.nonce = nonce
        self.key = key
        self.overkill = overkill
        self.ptext = ptext
        self.ctext = ctext
