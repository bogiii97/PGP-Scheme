from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def convertPublicToPEM(public_byte):
    public_key_obj = serialization.load_der_public_key(public_byte, backend=default_backend())

    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    public_pem_cleaned = public_pem.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----\n", "").replace("\n", "")
    return public_pem_cleaned

def convertPEMToPublic(public_pem_cleaned):
    public_pem = f"-----BEGIN PUBLIC KEY-----\n{public_pem_cleaned}\n-----END PUBLIC KEY-----\n"

    public_key_obj = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())

    public_byte = public_key_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_byte

def convertPrivateToPEM(encrypted_private_byte):
    encrypted_private_key_b64 = base64.b64encode(encrypted_private_byte).decode('utf-8')
    encrypted_private_key_pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{encrypted_private_key_b64}\n-----END ENCRYPTED PRIVATE KEY-----\n"

    private_pem_cleaned = encrypted_private_key_pem.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "").replace("-----END ENCRYPTED PRIVATE KEY-----\n", "").replace("\n", "")
    return private_pem_cleaned

def convertPEMToPrivate(private_pem_cleaned):
    encrypted_private_key_pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{private_pem_cleaned}\n-----END ENCRYPTED PRIVATE KEY-----\n"

    encrypted_private_key_b64 = encrypted_private_key_pem.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "").replace("\n-----END ENCRYPTED PRIVATE KEY-----\n", "").replace("\n", "")
    encrypted_private_byte = base64.b64decode(encrypted_private_key_b64)

    return encrypted_private_byte