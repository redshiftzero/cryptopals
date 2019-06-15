import random
import time
from cryptopals.prng import MersenneTwister, mersenne_untemper


def test_mersenne_twister_cpp():
    """Test to validate the MT implementation is correct"""
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
    # just so that this test is fast (also passes with the larger values).
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


def test_mersenne_twister_reconstruct_single_state_test():
    seed = 5489
    mt_prng = MersenneTwister(seed)

    output = mt_prng.extract_number()
    state_to_reconstruct = mt_prng.mt[0]

    reconstructed_state = mersenne_untemper(output)

    assert state_to_reconstruct == reconstructed_state


def test_clone_mersenne_twister_from_output():
    # Set 3, challenge 23: Clone an MT19937 RNG from its output

    seed = 5489
    mt_prng = MersenneTwister(seed)

    N = 624
    observed_values = []
    reconstructed_states = []
    for _ in range(N):
        output = mt_prng.extract_number()
        reconstructed_state = mersenne_untemper(output)
        observed_values.append(output)
        reconstructed_states.append(reconstructed_state)

    # Now clone the state and reset internal index
    mt_prng = MersenneTwister(0)  # Passing dummy seed
    mt_prng.mt = reconstructed_states
    mt_prng.index = 0

    # Now assert the output is the same (i.e. MT output can be predicted)
    for i in range(N):
        assert observed_values[i] == mt_prng.extract_number()
