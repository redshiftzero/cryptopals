import math
from typing import Tuple

from cryptopals.frequency import score_english_text_bytes
from cryptopals.utils import xor


def break_single_char_xor(ciphertext: bytes) -> Tuple[bytes, float]:
    # potential_keys = [x.encode("utf8") for x in list(TEST_CHARACTERS)]
    potential_keys = [bytes([x]) for x in range(255)]

    best_key = b""
    best_metric = 100.0
    for key in potential_keys:
        result = xor(ciphertext, key)
        metric = score_english_text_bytes(result)

        if metric < best_metric:
            print(
                f"metric {metric!r} is better than the best {best_metric!r}, setting best key to {key!r}"
            )
            best_metric = metric
            best_key = key

    print("best_key", best_key)
    print("best_metric", best_metric)
    return best_key, best_metric


def break_ctr_statistically(ciphertext: bytes, truncate_len: int = 48) -> bytes:
    keysize = truncate_len
    num_fragments = math.floor(len(ciphertext) / keysize)
    key = b""

    for key_index in range(keysize):
        ciphertext_for_this_problem = ""

        # Take the key_index'th character from each fragment, solve the XOR problem
        for fragment_index in range(1, num_fragments):
            starting_index = (fragment_index - 1) * keysize
            ending_index = fragment_index * keysize
            fragment = ciphertext[starting_index:ending_index]
            ciphertext_for_this_problem += chr(fragment[key_index])

        key_this_problem, _ = break_single_char_xor(
            ciphertext_for_this_problem.encode("utf8")
        )
        print(key_this_problem)
        key += key_this_problem

    return key
