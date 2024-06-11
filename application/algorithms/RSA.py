from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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


def convertToPem(private, public, publicID):
    private_key_obj = serialization.load_der_private_key(
        private,
        password=None,
        backend=default_backend()
    )

    # Deserializacija javnog ključa iz DER formata
    public_key_obj = serialization.load_der_public_key(
        public,
        backend=default_backend()
    )

    # Serijalizacija privatnog ključa u PEM formatu
    private_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serijalizacija javnog ključa u PEM formatu
    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )



    print("Privatni ključ u PEM formatu:\n", private_pem.decode('utf-8'))
    print("Javni ključ u PEM formatu:\n", public_pem.decode('utf-8'))
