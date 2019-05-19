import string

from cryptopals.frequency import score_english_text
from cryptopals.utils import hex_to_ascii, single_char_xor


def break_single_char_xor(ciphertext: bytes) -> bytes:
    potential_keys = [x.encode("utf8") for x in list(string.ascii_uppercase)]

    best_key = b""
    best_metric = 100.0
    for key in potential_keys:
        result = single_char_xor(ciphertext, key)
        metric = score_english_text(result.decode("utf8"))
        print(key, result, metric)

        if metric < best_metric:
            best_metric = metric
            best_key = key

    return best_key
