from application.keys.private_key import PrivateKey
from application.keys.public_key import PublicKey

class User:

    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.private_ring = []
        self.public_ring = []


    def __repr__(self):
        return (f"User(name={self.name}, email={self.email}, "
                f"private_keys={self.private_ring}, "
                f"public_keys={self.public_ring}")

