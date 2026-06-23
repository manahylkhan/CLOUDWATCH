import base64
import os
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from config import SECRET_SALT


def _derive_key() -> bytes:
    machine_id = str(uuid.getnode()).encode()
    salt = SECRET_SALT.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(machine_id))


def _fernet() -> Fernet:
    return Fernet(_derive_key())


def encrypt_credential(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_credential(encrypted: str) -> str:
    return _fernet().decrypt(encrypted.encode()).decode()
