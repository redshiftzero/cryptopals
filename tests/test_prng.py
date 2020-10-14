import random
import string
import time
from typing import Optional
from cryptopals.prng import (
    MersenneTwister,
    mersenne_untemper,
    mt_stream_encrypt,
    mt_stream_decrypt,
)


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


def test_crack_mersenne_stream_cipher():
    # Set 3, challenge 24: Create the MT19937 stream cipher and break it

    # You can create a trivial stream cipher out of any PRNG; use it to generate a
    # sequence of 8 bit outputs and call those outputs a keystream.
    # XOR each byte of plaintext with each successive byte of keystream.

    # Write the function that does this for MT19937 using a 16-bit seed.
    # Reduced so that this test runs faster, but this method works for any 16-bit value.
    seed = 900

    # Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.
    plaintext = b"teehee"

    ciphertext = mt_stream_encrypt(seed, plaintext)
    plaintext_recovered = mt_stream_decrypt(seed, ciphertext)
    assert plaintext == plaintext_recovered

    # Use your function to encrypt a known plaintext (say, 14 consecutive
    # 'A' characters) prefixed by a random number of random characters.

    random_num_char = random.randrange(2, 10)
    prefix_chars = [
        random.choice(string.printable).encode("utf-8") for x in range(random_num_char)
    ]
    known_plaintext = b"aaaaaaaaaaaaaa"
    test_plaintext = b"".join(prefix_chars) + known_plaintext

    test_ciphertext = mt_stream_encrypt(seed, test_plaintext)

    # Problem: From the ciphertext, recover the "key" (the 16 bit seed).

    len_known_plaintext = len(known_plaintext)
    len_unknown_plaintext = len(test_plaintext) - len_known_plaintext
    # KPA attack model. 16-bit seed space, small enough to bruteforce.

    for test_seed in range(2 ** 16):
        if test_seed % 1000 == 0:
            print(f"on {test_seed}")
        prefix_bytes = b"a" * len_unknown_plaintext
        plaintext = prefix_bytes + known_plaintext
        ciphertext = mt_stream_encrypt(test_seed, plaintext)
        if (
            ciphertext[len_unknown_plaintext:]
            == test_ciphertext[len_unknown_plaintext:]
        ):
            assert seed == test_seed
            return


def test_detect_mersenne_password_reset_token():
    # Set 3, challenge 24 continued.

    # Use the same idea to generate a random "password reset token"
    # using MT19937 seeded from the current time.

    # Write a function to check if any given password token is
    # actually the product of an MT19937 PRNG seeded with the current time.

    def gen_random_password_token(current_unix_timestamp: Optional[int] = None):
        if not current_unix_timestamp:
            current_unix_timestamp = int(time.time())
            print(f"target seed: {current_unix_timestamp}")
        mt_prng = MersenneTwister(current_unix_timestamp)
        return mt_prng.extract_number()

    token = gen_random_password_token()

    def detect_mt_password_token(token: int) -> bool:
        upper_seed_to_crack = int(time.time())
        # Assumes this is ran within 1 hr (=3600s) of token generation
        lower_seed_to_crack = upper_seed_to_crack - 3600
        print(f"lower seed {lower_seed_to_crack}")
        print(f"upper seed {upper_seed_to_crack}")
        for possible_seed in range(lower_seed_to_crack, upper_seed_to_crack + 1):
            test_token = gen_random_password_token(possible_seed)
            if test_token == token:
                return True
        else:
            return False

    assert detect_mt_password_token(token)
