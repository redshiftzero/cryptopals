import string
import math
from typing import Tuple

from cryptopals.frequency import score_english_text, TEST_CHARACTERS
from cryptopals.utils import hex_to_ascii, xor, edit_distance


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


def break_repeating_key_xor(ciphertext: bytes, max_keysize: int = 40) -> bytes:
    keysizes = range(2, max_keysize + 1)

    best_edit_distance = 1000.0  # start at really high value
    best_keysize = 0  # we'll store the best fit key in here
    for keysize in keysizes:
        num_fragments = math.floor(len(ciphertext) / keysize)
        total_edit_distance = 0

        for fragment_index in range(1, num_fragments):

            first_keysize_worth_of_bytes = ciphertext[
                (fragment_index - 1) * keysize : fragment_index * keysize
            ]
            second_keysize_worth_of_bytes = ciphertext[
                fragment_index * keysize : (fragment_index + 1) * keysize
            ]

            fragment_edit_distance = edit_distance(
                first_keysize_worth_of_bytes, second_keysize_worth_of_bytes
            )

            total_edit_distance += fragment_edit_distance

        average_edit_distance = total_edit_distance / num_fragments
        normalized_edit_distance = average_edit_distance / float(keysize)

        if normalized_edit_distance < best_edit_distance:
            best_edit_distance = normalized_edit_distance
            best_keysize = keysize

    # At this point we know the keysize. Now we solve individual single char XOR problems.
    num_fragments = math.floor(len(ciphertext) / best_keysize)
    key = b""

    for key_index in range(best_keysize):
        ciphertext_for_this_problem = ""

        # Take the key_index'th character from each fragment, solve the XOR problem

        for fragment_index in range(1, num_fragments):
            starting_index = (fragment_index - 1) * best_keysize
            ending_index = fragment_index * best_keysize
            fragment = ciphertext[starting_index:ending_index]
            ciphertext_for_this_problem += chr(fragment[key_index])

        key_this_problem, _ = break_single_char_xor(
            ciphertext_for_this_problem.encode("utf8")
        )
        key += key_this_problem

    return key
