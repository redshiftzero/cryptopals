from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_ecb_encrypt():
    pass
