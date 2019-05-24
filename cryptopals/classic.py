import string
from typing import Tuple

from cryptopals.frequency import score_english_text, TEST_CHARACTERS
from cryptopals.utils import hex_to_ascii, xor


def break_single_char_xor(ciphertext: bytes) -> Tuple[bytes, float]:
    potential_keys = [x.encode("utf8") for x in list(TEST_CHARACTERS)]

    best_key = b""
    best_metric = 100.0
    for key in potential_keys:
        result = xor(ciphertext, key)
        try:
            metric = score_english_text(result.decode("utf8"))
        except UnicodeDecodeError:  # Not valid UTF-8
            metric = 1000.0

        if metric < best_metric:
            best_metric = metric
            best_key = key

    return best_key, best_metric
