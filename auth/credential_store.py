import os
import threading
from cryptography.fernet import Fernet
from config import SECRET_KEY_PATH

_fernet: "Fernet | None" = None
_fernet_lock = threading.Lock()


def _get_or_create_key():
    key_dir = os.path.dirname(SECRET_KEY_PATH)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700, exist_ok=True)

    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            return f.read()

    key = Fernet.generate_key()
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(key)
    os.chmod(SECRET_KEY_PATH, 0o600)
    return key


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        with _fernet_lock:
            if _fernet is None:
                _fernet = Fernet(_get_or_create_key())
    return _fernet


def encrypt(plaintext):
    if not plaintext:
        return None
    f = get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    if not ciphertext:
        return None
    f = get_fernet()
    return f.decrypt(ciphertext.encode()).decode()
