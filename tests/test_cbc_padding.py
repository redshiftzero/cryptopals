import os
import random

from cryptopals.block import aes_cbc_encrypt
from cryptopals.cbc_padding import Solver
from cryptopals.padding import pkcs_7
from cryptopals.utils import base64_to_bytes


def test_cbc_padding_oracle():
    # Set 3, challenge 17 CBC Padding Oracle

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/17.txt"
    )

    with open(path_to_test_data, "r") as f:
        plaintexts = f.read().split("\n")

    block_size = 16
    key = os.urandom(block_size)
    iv = os.urandom(block_size)

    plaintext = random.choice(plaintexts)
    unpadded_plaintext_bytes = base64_to_bytes(plaintext)
    plaintext_bytes = pkcs_7(unpadded_plaintext_bytes, block_size)
    ciphertext = aes_cbc_encrypt(key, unpadded_plaintext_bytes, iv)

    cbc_solver = Solver(block_size, iv, key, ciphertext)
    reconstructed_bytes = cbc_solver.run(plaintext_bytes)

    # Since I'm pretending as if I didn't know the IV, I'm going to compare
    # only the blocks that were *not* constructed by XORing with the IV.
    # As an attacker I could guess e.g. that the IV was all 0s or some other
    # insecure default that might have been due to an insecure default in the
    # crypto library used by the developer.
    result_without_iv_based_block = "".join([chr(x) for x in reconstructed_bytes])
    plaintext_without_iv_based_block = plaintext_bytes[
        2 * cbc_solver.block_size : (cbc_solver.num_blocks - 1) * cbc_solver.block_size
    ].decode("utf-8")

    assert plaintext_without_iv_based_block in result_without_iv_based_block
