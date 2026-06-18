import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def derive_aes_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_payload(plaintext: bytes, master_password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_aes_key(master_password, salt)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return salt + iv + tag + ciphertext


def decrypt_payload(payload: bytes, master_password: str) -> bytes:
    salt = payload[:16]
    iv = payload[16:28]
    tag = payload[28:44]
    ciphertext = payload[44:]
    key = derive_aes_key(master_password, salt)
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
