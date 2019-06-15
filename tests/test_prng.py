import random
import time
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


def test_crack_mt_seed():
    # Set 3, challenge 22: Crack an MT19937 seed

    # The below have smaller values compared to the problem description
    # just so that this test is fast
    # lower_num_seconds = 40
    lower_num_seconds = 1
    # upper_num_seconds = 1000
    upper_num_seconds = 2

    random_seconds_to_wait = random.randrange(lower_num_seconds, upper_num_seconds)
    time.sleep(random_seconds_to_wait)

    current_unix_timestamp = int(time.time())

    random_seconds_to_wait = random.randrange(lower_num_seconds, upper_num_seconds)
    time.sleep(random_seconds_to_wait)

    mt_prng = MersenneTwister(current_unix_timestamp)
    first_output = mt_prng.extract_number()

    upper_seed_to_crack = int(time.time())
    lower_seed_to_crack = upper_seed_to_crack - upper_num_seconds * 2
    for possible_seed in range(lower_seed_to_crack, upper_seed_to_crack):
        mt_prng = MersenneTwister(possible_seed)
        test_output = mt_prng.extract_number()
        if test_output == first_output:
            break

    assert current_unix_timestamp == possible_seed
