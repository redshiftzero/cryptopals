from cryptopals.prng import MersenneTwister


def test_mersenne_twister_cpp():
    seed = 5489
    mt_prng = MersenneTwister(seed)

    # https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine
    output_10000 = 4123659995
    n_outputs = 10000

    for rand in range(n_outputs):
        random_number = mt_prng.extract_number()

    assert random_number == output_10000
