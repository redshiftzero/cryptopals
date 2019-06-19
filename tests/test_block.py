import os

from cryptopals.block import (
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    detect_ecb_use,
    encryption_ecb_cbc_detection_oracle,
    gen_random_block,
)
from cryptopals.utils import base64_to_bytes, hex_to_bytes


BLOCK_SIZE = 16


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


def test_aes_ecb_encrypt():
    key = "YELLOW SUBMARINE".encode("utf-8")
    plaintext = "test".encode("utf-8")

    ciphertext = aes_ecb_encrypt(key, plaintext)

    computed_plaintext = aes_ecb_decrypt(key, ciphertext)

    assert plaintext == computed_plaintext


def test_aes_cbc_encrypt():
    key = "YELLOW SUBMARINE".encode("utf-8")
    plaintext = "test".encode("utf-8")
    iv = bytes([0]) * BLOCK_SIZE

    ciphertext = aes_cbc_encrypt(key, plaintext, iv, BLOCK_SIZE)

    computed_plaintext = aes_cbc_decrypt(key, ciphertext, iv, BLOCK_SIZE)

    assert plaintext == computed_plaintext


def test_aes_cbc_decrypt():
    # Set 2, challenge 10: Implement CBC mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/10.txt"
    )

    with open(path_to_data, "r") as f:
        base64_ciphertext = f.read()

    ciphertext = base64_to_bytes(base64_ciphertext)

    key = "YELLOW SUBMARINE".encode("utf-8")

    iv = bytes([0]) * BLOCK_SIZE

    plaintext = aes_cbc_decrypt(key, ciphertext, iv)

    assert "Vanilla's on the mike, man I'm not lazy." in plaintext.decode("utf-8")
    assert "I'm back and I'm ringin' the bell" in plaintext.decode("utf-8")


def test_aes_ecb_detection():
    # Set 1, challenge 8: Detect AES in ECB mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/8.txt"
    )

    with open(path_to_data, "r") as f:
        hex_ciphertexts = f.read().split("\n")

    texts_with_repeated_blocks = []
    for ciphertext in hex_ciphertexts:
        # Look for repeated blocks
        bytes_ciphertext = hex_to_bytes(ciphertext)

        if detect_ecb_use(bytes_ciphertext):
            texts_with_repeated_blocks.append(bytes_ciphertext)

    assert len(texts_with_repeated_blocks) == 1


def test_ecb_cbc_detection_oracle():
    # Set 2, challenge 11: Detect ECB or CBC

    num_ecbs = 0
    num_cbcs = 0
    num_total_iterations = 100

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "cryptopals/data/lotr.txt"
    )

    with open(path_to_data, "r") as f:
        plaintext = f.read().encode("utf-8")

    for _ in range(num_total_iterations):
        key = gen_random_block()
        ciphertext = encryption_ecb_cbc_detection_oracle(key, plaintext)

        if detect_ecb_use(ciphertext):
            num_ecbs += 1
        else:
            num_cbcs += 1

    cbc_rate = num_cbcs / num_total_iterations
    ecb_rate = num_ecbs / num_total_iterations

    # Expect 50 ECBs, 50 CBCs
    assert cbc_rate > 0.40 and cbc_rate < 0.60
    assert ecb_rate > 0.40 and ecb_rate < 0.60
