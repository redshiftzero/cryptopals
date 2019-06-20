import math
import os
import random
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from cryptopals.padding import pkcs_7, remove_pkcs_7
from cryptopals.utils import xor


def aes_ecb_decrypt(
    key: bytes, ciphertext: bytes, remove_padding: bool = True
) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if remove_padding:
        plaintext = remove_pkcs_7(plaintext)
    return plaintext


def aes_ecb_encrypt(key: bytes, plaintext: bytes, block_size: int = 16) -> bytes:
    padded_plaintext = pkcs_7(plaintext, block_size)

    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def aes_cbc_decrypt(
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    block_size: int = 16,
    remove_padding: bool = True,
) -> bytes:

    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext is not a multiple of the block size!")

    num_blocks = len(ciphertext) // block_size
    blocks = [
        ciphertext[x * block_size : (x + 1) * block_size] for x in range(num_blocks)
    ]

    plaintext = b""

    for ind, block in enumerate(reversed(blocks)):
        block_num = num_blocks - ind

        if block_num == 1:
            block_to_xor = iv
        else:
            block_to_xor = blocks[block_num - 2]  # previous ciphertext block

        aes_output = aes_ecb_decrypt(key, block, remove_padding=remove_padding)
        this_block = xor(aes_output, block_to_xor)

        if remove_padding:
            plaintext = remove_pkcs_7(plaintext)
        plaintext = this_block + plaintext

    return plaintext


def aes_cbc_encrypt(
    key: bytes, plaintext: bytes, iv: bytes, block_size: int = 16
) -> bytes:
    plaintext = pkcs_7(plaintext, block_size)

    num_blocks = len(plaintext) // block_size
    blocks = [
        plaintext[x * block_size : (x + 1) * block_size] for x in range(num_blocks)
    ]

    ciphertext = b""
    aes_output = b""
    for ind, block in enumerate(blocks):
        if ind == 0:
            block_to_xor = iv
        else:
            block_to_xor = aes_output  # AES output from last block

        this_block = xor(block, block_to_xor)
        aes_output = aes_ecb_encrypt(key, this_block)

        ciphertext = ciphertext + aes_output

    return ciphertext


def detect_ecb_use(ciphertext: bytes, block_size: int = 16) -> bool:
    num_blocks = math.ceil(len(ciphertext) / block_size)

    blocks = []
    for i in range(num_blocks):
        blocks.append(ciphertext[i * block_size : (i + 1) * block_size])

    unique_blocks = set(blocks)
    if len(unique_blocks) != len(blocks):
        return True
    else:
        return False


def gen_random_block(block_size: int = 16) -> bytes:
    return os.urandom(block_size)


def encryption_ecb_cbc_detection_oracle(key: bytes, plaintext: bytes) -> bytes:
    # neither num_bytes_to_append nor pick_ecb_or_cbc needs a CSPRNG
    num_bytes_to_append = random.randrange(5, 10)
    pick_ecb_or_cbc = random.randrange(0, 2)

    for _ in range(num_bytes_to_append):
        # prepend a byte
        plaintext = random.choice(string.printable).encode("utf-8") + plaintext
        # append a byte
        plaintext = plaintext + random.choice(string.printable).encode("utf-8")

    if pick_ecb_or_cbc == 0:  # ECB
        ciphertext = aes_ecb_encrypt(key, plaintext)
    elif pick_ecb_or_cbc == 1:  # CBC
        iv = gen_random_block()
        ciphertext = aes_cbc_encrypt(key, plaintext, iv)

    return ciphertext
