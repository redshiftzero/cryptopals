from cryptopals.prng import MersenneTwister


def test_mersenne_twister():
    mt_prng = MersenneTwister(123123132123)

    first_number = mt_prng.extract_number()
    second_number = mt_prng.extract_number()

    assert first_number != second_number
