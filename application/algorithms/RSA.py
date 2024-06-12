from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
def generate_keys(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(key_size),
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

