import math
import os

from cryptopals.block import aes_ecb_decrypt, aes_ecb_encrypt
from cryptopals.utils import base64_to_bytes, hex_to_bytes


def test_aes_ecb_decrypt():
    # Set 1, challenge 7: AES in ECB mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/7.txt"
    )

    with open(path_to_data, "r") as f:
        base64_ciphertext = f.read()

    ciphertext = base64_to_bytes(base64_ciphertext)

    key = "YELLOW SUBMARINE".encode("utf-8")

    plaintext = aes_ecb_decrypt(key, ciphertext)
    assert "Play that funky music A little louder now" in plaintext.decode("utf8")


def test_aes_ecb_detection():
    # Set 1, challenge 8: Detect AES in ECB mode

    BLOCK_SIZE = 16

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/8.txt"
    )

    with open(path_to_data, "r") as f:
        hex_ciphertexts = f.read().split("\n")

    texts_with_repeated_blocks = []
    for ciphertext in hex_ciphertexts:
        # Look for repeated blocks
        bytes_ciphertext = hex_to_bytes(ciphertext)

        num_blocks = math.ceil(len(bytes_ciphertext) / BLOCK_SIZE)
        blocks = []
        for i in range(num_blocks):
            blocks.append(bytes_ciphertext[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE])

        unique_blocks = set(blocks)
        if len(unique_blocks) != len(blocks):
            texts_with_repeated_blocks.append(ciphertext)

    assert len(texts_with_repeated_blocks) == 1
