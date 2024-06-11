class PrivateKey:
    def __init__(self, key, encryptedKey, password):
        self.key = key
        self.encryptedKey = encryptedKey
        self.password = password