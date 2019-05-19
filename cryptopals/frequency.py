import string

# https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
ENGLISH_FREQUENCIES = {
    "a": 8.12,
    "b": 1.49,
    "c": 2.71,
    "d": 4.32,
    "e": 12.02,
    "f": 2.30,
    "g": 2.03,
    "h": 5.92,
    "i": 7.31,
    "j": 0.10,
    "k": 0.69,
    "l": 3.98,
    "m": 2.61,
    "n": 6.95,
    "o": 7.68,
    "p": 1.82,
    "q": 0.11,
    "r": 6.02,
    "s": 6.28,
    "t": 9.10,
    "u": 2.88,
    "v": 1.11,
    "w": 2.09,
    "x": 0.17,
    "y": 2.11,
    "z": 0.07,
}


def score_english_text(text: str) -> float:
    # Using the chi sq statistic to measure how well the english char frequency
    # distribution fits to the observed character frequency distribution.
    # http://www.stat.yale.edu/Courses/1997-98/101/chigf.htm

    chi_sq = 0.0

    text = text.lower()
    for letter in string.ascii_lowercase:
        observed = text.count(letter) / len(text)  # occurences of letter in the text
        expected = ENGLISH_FREQUENCIES[letter]
        chi_sq += (observed - expected) ** 2 / (expected)

    return chi_sq
