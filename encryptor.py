from cryptography.fernet import Fernet
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str) -> bytes:
    salt = b'static_salt'  # You can replace this with os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_password(password: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()
