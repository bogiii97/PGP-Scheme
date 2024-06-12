from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def convertPublicToPEM(public_byte):
    public_key_obj = serialization.load_der_public_key(public_byte, backend=default_backend())

    # Serijalizacija javnog ključa u PEM formatu
    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Uklanjanje zaglavlja i završetaka
    public_pem_cleaned = public_pem.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----\n", "").replace("\n", "")
    return public_pem_cleaned

def convertPrivateToPEM(encrypted_private_byte):
    encrypted_private_key_b64 = base64.b64encode(encrypted_private_byte).decode('utf-8')
    encrypted_private_key_pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{encrypted_private_key_b64}\n-----END ENCRYPTED PRIVATE KEY-----\n"

    # Uklanjanje zaglavlja i završetaka
    private_pem_cleaned = encrypted_private_key_pem.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "").replace("-----END ENCRYPTED PRIVATE KEY-----\n", "").replace("\n", "")
    return private_pem_cleaned