from collections import Counter
import string
import os

from typing import Dict, List


RELATIVE_PATH_TO_ENGLISH_TEXT = "data/lotr.txt"
TEST_CHARACTERS = string.printable


def compute_english_frequencies() -> Dict[str, float]:
    path_to_english_text = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), RELATIVE_PATH_TO_ENGLISH_TEXT
    )

    with open(path_to_english_text, "rb") as f:
        text = f.read().decode("utf8")

    english_frequencies = {}
    for char in TEST_CHARACTERS:
        english_frequencies[char] = text.count(char) / len(text)

    return english_frequencies


def top_n_english_words(n: int) -> List[str]:
    path_to_english_text = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), RELATIVE_PATH_TO_ENGLISH_TEXT
    )

    with open(path_to_english_text, "rb") as f:
        text = f.read().decode("utf8").split()

    counter = Counter(text)
    words_and_frequencies = counter.most_common(n)
    words = [x for (x, y) in words_and_frequencies]
    return words


def score_english_text(text: str) -> float:
    # Using a simple test statistic to measure how well the english char
    # frequency distribution fits to the observed character frequency
    # distribution.
    # metric = \Sigma_i^N \abs(o_i - e_i)
    # tl;dr Low values = good fit, high values = bad fit

    metric = 0.0
    english_frequencies = compute_english_frequencies()

    text = text.lower()
    for letter in TEST_CHARACTERS:
        observed = text.count(letter) / len(text)  # occurences of letter in the text
        expected = english_frequencies[letter]
        metric += abs(observed - expected)

    return metric


def score_english_text_bytes(text: bytes) -> float:

    metric = 0.0
    english_frequencies = compute_english_frequencies()

    text = text.lower()
    for letter in TEST_CHARACTERS:
        observed = text.count(letter.encode("utf8")) / len(
            text
        )  # occurences of letter in the text
        expected = english_frequencies[letter]
        metric += abs(observed - expected) / (observed + 1)

    return metric
