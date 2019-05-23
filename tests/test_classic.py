import os

from cryptopals.classic import break_single_char_xor
from cryptopals.utils import single_char_xor, hex_to_bytes


def test_single_character_xor():
    # Set 1, challenge 3 (shift cipher)
    ciphertext = (
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )  # type: str
    expected_plaintext = "Cooking MC's like a pound of bacon"  # type: str

    bytes_ciphertext = hex_to_bytes(ciphertext)
    bytes_key, _ = break_single_char_xor(bytes_ciphertext)

    actual_plaintext = single_char_xor(bytes_ciphertext, bytes_key)
    assert expected_plaintext == actual_plaintext.decode("utf8")


def test_detect_single_character_xor():
    # Set 1, challenge 4 (detect single character xor)
    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/4.txt"
    )

    with open(path_to_data, "r") as f:
        ciphertexts = f.read().split("\n")

    metrics = []
    for ciphertext in ciphertexts:
        _, metric = break_single_char_xor(hex_to_bytes(ciphertext))
        metrics.append(metric)

    best_metric = min(metrics)
    argmin_metric = metrics.index(best_metric)

    xored_ciphertext = hex_to_bytes(ciphertexts[argmin_metric])
    key, _ = break_single_char_xor(xored_ciphertext)
    plaintext = single_char_xor(xored_ciphertext, key)

    assert "Now that the party is jumping" in plaintext.decode("utf8")
