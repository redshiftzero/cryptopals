import math
import os
import random
import string
from typing import Dict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from cryptopals.exceptions import BadPaddingValidation
from cryptopals.frequency import TEST_CHARACTERS
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


def aes_ecb_encrypt(
    key: bytes, plaintext: bytes, block_size: int = 16, padding: bool = True
) -> bytes:
    if padding:
        plaintext = pkcs_7(plaintext, block_size)

    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


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

        aes_output = aes_ecb_decrypt(key, block, remove_padding=False)
        this_block = xor(aes_output, block_to_xor)

        plaintext = this_block + plaintext

    if remove_padding:
        plaintext = remove_pkcs_7(plaintext)

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
        aes_output = aes_ecb_encrypt(key, this_block, padding=False)

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


def ecb_encrypt_append(key: bytes, plaintext: bytes, append: bytes) -> bytes:
    # append our bytes
    plaintext = plaintext + append

    return aes_ecb_encrypt(key, plaintext)


def ecb_encrypt_prepend_and_append(
    key: bytes, plaintext: bytes, append: bytes, prepend: bytes
) -> bytes:
    plaintext = prepend + plaintext + append

    return aes_ecb_encrypt(key, plaintext)


def cbc_encrypt_prepend_and_append(
    key: bytes, iv: bytes, plaintext: bytes, append: bytes, prepend: bytes
) -> bytes:
    plaintext = prepend + plaintext + append

    return aes_cbc_encrypt(key, plaintext, iv)


def construct_ecb_attack_dict(
    key: bytes, prefix: bytes, blocksize: int = 16
) -> Dict[bytes, str]:
    dict_to_construct = {}
    for char in TEST_CHARACTERS:
        plaintext = prefix + char.encode("utf-8")
        ciphertext = aes_ecb_encrypt(key, plaintext)[0:blocksize]

        # We want the ciphertexts to be the keys as we want to be able to look
        # up test ciphertext block and find the unknown (last) character.
        dict_to_construct[ciphertext] = char

    return dict_to_construct


def cbc_padding_oracle(key: bytes, ciphertext: bytes, iv: bytes) -> bool:
    try:
        aes_cbc_decrypt(key, ciphertext, iv, remove_padding=True)
        return True
    except BadPaddingValidation:
        return False


class CounterMode(object):
    def __init__(self, key: bytes, nonce: int, block_size: int):
        self.key = key
        self.nonce = bytes([nonce])
        self.counter = 0
        self.block_size = block_size
        self.cipher = "AES"

    def _generate_keystream_block(self) -> bytes:
        num_bytes_for_nonce = 7  # to use same format as problem statement
        counter = bytes([self.counter]).rjust(
            self.block_size - num_bytes_for_nonce, b"\x00"
        ) + self.nonce.ljust(num_bytes_for_nonce, b"\x00")
        keystream = aes_ecb_encrypt(self.key, counter, self.block_size, False)
        self.counter += 1
        return keystream

    def _xor_with_keystream(self, text: bytes) -> bytes:
        result = []
        keystream = b""
        for text_byte in text:
            if len(keystream) == 0:
                keystream = self._generate_keystream_block()
            result_byte = keystream[0] ^ text_byte
            result.append(bytes([result_byte]))
            keystream = keystream[1:]
        return b"".join(result)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._xor_with_keystream(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._xor_with_keystream(plaintext)


def aes_ctr_decrypt(
    key: bytes, ciphertext: bytes, nonce: int, block_size: int = 16
) -> bytes:

    count = CounterMode(key, nonce, block_size)
    return count.decrypt(ciphertext)


def aes_ctr_encrypt(
    key: bytes, plaintext: bytes, nonce: int, block_size: int = 16
) -> bytes:

    count = CounterMode(key, nonce, block_size)
    return count.encrypt(plaintext)
