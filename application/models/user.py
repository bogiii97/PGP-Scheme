from application.keys.private_key import PrivateKey
from application.keys.public_key import PublicKey
from application.keys.exported_key import ExportedKey

class User:

    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.private_keys = []
        self.public_keys = []
        self.exported_keys = []

    def add_private_key(self, private_key):
        if isinstance(private_key, PrivateKey):
            self.private_keys.append(private_key)
        else:
            raise ValueError("Invalid key type. Expected PrivateKey.")

    def add_public_key(self, public_key):
        if isinstance(public_key, PublicKey):
            self.public_keys.append(public_key)
        else:
            raise ValueError("Invalid key type. Expected PublicKey.")

    def add_exported_key(self, exported_key):
        if isinstance(exported_key, ExportedKey):
            self.exported_keys.append(exported_key)
        else:
            raise ValueError("Invalid key type. Expected ExportedKey.")

    def __repr__(self):
        return (f"User(name={self.name}, email={self.email}, "
                f"private_keys={self.private_keys}, "
                f"public_keys={self.public_keys}, "
                f"exported_keys={self.exported_keys})")

