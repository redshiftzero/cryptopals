import string
from typing import Tuple

from cryptopals.frequency import score_english_text, TEST_CHARACTERS
from cryptopals.utils import hex_to_ascii, single_char_xor


def break_single_char_xor(ciphertext: bytes) -> Tuple[bytes, float]:
    potential_keys = [x.encode("utf8") for x in list(TEST_CHARACTERS)]

    best_key = b""
    best_metric = 100.0
    for key in potential_keys:
        result = single_char_xor(ciphertext, key)
        # print(result, key)
        try:
            metric = score_english_text(result.decode("utf8"))
        except UnicodeDecodeError:  # Not valid UTF-8
            metric = 1000.0

        if metric < best_metric:
            best_metric = metric
            best_key = key

    return best_key, best_metric


def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    def key_byte(key):
        i = 0
        while True:
            i = i % len(key)
            yield key[i]
            i += 1

    ciphertext_bytes_list = []
    key_generator = key_byte(key)

    while len(plaintext) > 0:
        # XOR first byte of plaintext with next key byte
        ciphertext_byte = plaintext[0] ^ next(key_generator)
        ciphertext_bytes_list.append(ciphertext_byte)
        plaintext = plaintext[1:]  # Strip off first byte since we've handled it

    return bytes(ciphertext_bytes_list)
