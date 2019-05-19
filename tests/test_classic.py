from cryptopals.classic import break_single_char_xor
from cryptopals.utils import single_char_xor, hex_to_bytes


def test_single_character_xor():
    # Set 1, challenge 3 (shift cipher)
    ciphertext = (
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )  # type: str
    expected_plaintext = "Cooking MC's like a pound of bacon"  # type: str

    bytes_ciphertext = hex_to_bytes(ciphertext)
    bytes_key = break_single_char_xor(bytes_ciphertext)

    actual_plaintext = single_char_xor(bytes_ciphertext, bytes_key)
    assert expected_plaintext == actual_plaintext.decode("utf8")
