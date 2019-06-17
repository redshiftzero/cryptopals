import os

from cryptopals.block import aes_ecb_decrypt, aes_ecb_encrypt
from cryptopals.utils import base64_to_bytes


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
