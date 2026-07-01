class Argon:
    def __init__(self, salt, password, overkill, key=None):
        self.salt = salt
        self.password = password
        self.overkill = overkill
        self.key = key