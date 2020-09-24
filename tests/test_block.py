from collections import namedtuple
import os
import random

from cryptopals.block import (
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_ctr_edit,
    CounterMode,
    detect_ecb_use,
    ecb_encrypt_append,
    ecb_encrypt_prepend_and_append,
    cbc_encrypt_prepend_and_append,
    encryption_ecb_cbc_detection_oracle,
    gen_random_block,
    construct_ecb_attack_dict,
)
from cryptopals.block_attacks import break_ctr_statistically
from cryptopals.frequency import top_n_english_words
from cryptopals.utils import base64_to_bytes, hex_to_bytes, xor


BLOCK_SIZE = 16


def test_aes_ecb_decrypt():
    # Set 1, challenge 7: AES in ECB mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/7.txt"
    )

    with open(path_to_data, "r") as f:
        base64_ciphertext = f.read()

    ciphertext = base64_to_bytes(base64_ciphertext)

    key = "YELLOW SUBMARINE".encode("utf-8")

    plaintext = aes_ecb_decrypt(key, ciphertext)
    assert "Play that funky music A little louder now" in plaintext.decode("utf8")


def test_aes_ecb_encrypt():
    key = "YELLOW SUBMARINE".encode("utf-8")
    plaintext = "test".encode("utf-8")

    ciphertext = aes_ecb_encrypt(key, plaintext)

    computed_plaintext = aes_ecb_decrypt(key, ciphertext)

    assert plaintext == computed_plaintext


def test_aes_cbc_encrypt():
    key = "YELLOW SUBMARINE".encode("utf-8")
    plaintext = "test".encode("utf-8")
    iv = bytes([0]) * BLOCK_SIZE

    ciphertext = aes_cbc_encrypt(key, plaintext, iv, BLOCK_SIZE)

    computed_plaintext = aes_cbc_decrypt(key, ciphertext, iv, BLOCK_SIZE)

    assert plaintext == computed_plaintext


def test_aes_cbc_decrypt():
    # Set 2, challenge 10: Implement CBC mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/10.txt"
    )

    with open(path_to_data, "r") as f:
        base64_ciphertext = f.read()

    ciphertext = base64_to_bytes(base64_ciphertext)

    key = "YELLOW SUBMARINE".encode("utf-8")

    iv = bytes([0]) * BLOCK_SIZE

    plaintext = aes_cbc_decrypt(key, ciphertext, iv, remove_padding=False)

    assert "Vanilla's on the mike, man I'm not lazy." in plaintext.decode("utf-8")
    assert "I'm back and I'm ringin' the bell" in plaintext.decode("utf-8")


def test_aes_ecb_detection():
    # Set 1, challenge 8: Detect AES in ECB mode

    path_to_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/8.txt"
    )

    with open(path_to_data, "r") as f:
        hex_ciphertexts = f.read().split("\n")

    texts_with_repeated_blocks = []
    for ciphertext in hex_ciphertexts:
        # Look for repeated blocks
        bytes_ciphertext = hex_to_bytes(ciphertext)

        if detect_ecb_use(bytes_ciphertext):
            texts_with_repeated_blocks.append(bytes_ciphertext)

    assert len(texts_with_repeated_blocks) == 1


def test_ecb_cbc_detection_oracle():
    # Set 2, challenge 11: Detect ECB or CBC

    num_ecbs = 0
    num_cbcs = 0
    num_total_iterations = 100

    plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode("utf-8")

    for _ in range(num_total_iterations):
        key = gen_random_block()
        ciphertext = encryption_ecb_cbc_detection_oracle(key, plaintext)

        if detect_ecb_use(ciphertext):
            num_ecbs += 1
        else:
            num_cbcs += 1

    cbc_rate = num_cbcs / num_total_iterations
    ecb_rate = num_ecbs / num_total_iterations

    # Expect 50 ECBs, 50 CBCs
    assert cbc_rate > 0.40 and cbc_rate < 0.60
    assert ecb_rate > 0.40 and ecb_rate < 0.60


def test_byte_at_a_time_ecb_decryption():
    # Set 2, challenge 12: Byte-at-a-time ECB decryption (Simple)

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/12.txt"
    )

    with open(path_to_test_data, "r") as f:
        append_text_str = f.read()

    append_bytes = base64_to_bytes(append_text_str)

    # We won't actually use the key anywhere other than to pass it to the
    # oracle function ecb_encrypt_append.
    key = gen_random_block()

    # Determine blocksize
    previous_ciphertext_len = None
    test_input = "A"
    for blocksize in range(100):
        test_input = "A" + test_input
        test_ciphertext = ecb_encrypt_append(
            key, test_input.encode("utf-8"), append_bytes
        )

        if (
            previous_ciphertext_len
            and len(test_ciphertext) - previous_ciphertext_len != 0
        ):
            blocksize = len(test_ciphertext) - previous_ciphertext_len
            break

        previous_ciphertext_len = len(test_ciphertext)

    assert blocksize == BLOCK_SIZE  # Check we inferred blocksize correctly.

    ciphertext = ecb_encrypt_append(key, b"", append_bytes)

    # Now we make repeated calls (as described in problem statement) to
    # pass inputs that are (blocksize - 1) in length.
    reconstructed_str = ""

    for index_of_target_block in range(1, len(ciphertext) // blocksize):

        bytes_so_far_this_block = b""
        for test_byte in range(blocksize):

            if index_of_target_block == 1:
                # If it's the first block, we control the prefix bytes.
                attacker_controlled_bytes = "A" * (blocksize - test_byte - 1)

                # Prefix is used for the dict calculation
                prefix = (
                    attacker_controlled_bytes.encode("utf-8") + bytes_so_far_this_block
                )
            else:
                # But if it's the second block or later, we need to use the
                # bytes we reconstructed from the previous block as the prefix.
                previous_block_bytes = reconstructed_str[-1 * (blocksize - 1) :]

                # The prefix is used for the dict calculation
                prefix = previous_block_bytes.encode("utf-8")

                # Attacker-controlled bytes here are just to make sure there is only
                # a single unknown character in the target block.
                attacker_controlled_bytes = "A" * (blocksize - test_byte - 1)

            ciphertext = ecb_encrypt_append(
                key, attacker_controlled_bytes.encode("utf-8"), append_bytes
            )

            cipher_dict = construct_ecb_attack_dict(key, prefix)

            target_block_ciphertext = ciphertext[
                (index_of_target_block - 1)
                * blocksize : index_of_target_block
                * blocksize
            ]

            last_char = cipher_dict[target_block_ciphertext]

            reconstructed_str = reconstructed_str + last_char
            bytes_so_far_this_block = bytes_so_far_this_block + last_char.encode(
                "utf-8"
            )

    assert "With my rag-top down so my hair can blow" in reconstructed_str


def test_random_prefix_byte_at_a_time_ecb_decryption():
    # Set 2, challenge 14: Byte-at-a-time ECB decryption (harder)

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/12.txt"
    )

    with open(path_to_test_data, "r") as f:
        append_text_str = f.read()

    append_bytes = base64_to_bytes(append_text_str)

    # We won't actually use the key anywhere other than to pass it to the
    # oracle function.
    key = gen_random_block()

    # Get random number of bytes. This we will prepend to the plaintext.
    random_number_of_bytes = random.randint(1, 15)
    prepend_bytes = os.urandom(random_number_of_bytes)

    blocksize = 16

    ciphertext = ecb_encrypt_prepend_and_append(key, b"", append_bytes, prepend_bytes)

    test_str = "A" * blocksize
    ciphertext_of_all_As = aes_ecb_encrypt(key, test_str.encode("utf-8"))[0:blocksize]

    # We don't really know where to start in the ciphertext. Previously we started
    # decrypting with the first ciphertext block, when we manipulated it to
    # contain one target character.
    # We need to first determine how much space the prefix bytes are taking up.
    block_to_begin_at = None
    number_of_characters_in_test_string = None
    for num_of_test_characters in range(blocksize * 2 - 1, 1, -1):
        test_str = "A" * num_of_test_characters

        ciphertext = ecb_encrypt_prepend_and_append(
            key, test_str.encode("utf-8"), append_bytes, prepend_bytes
        )

        for block_num in range(1, len(ciphertext) // blocksize):

            if (
                ciphertext_of_all_As
                == ciphertext[(block_num - 1) * blocksize : block_num * blocksize]
            ):
                block_to_begin_at = block_num
                number_of_characters_in_test_string = num_of_test_characters

    # We add sufficient characters in the target block so that the unknown prefix
    # bytes fill a block boundary. Then we start at that block boundary and decrypt
    # as before.
    reconstructed_str = ""

    for index_of_target_block in range(block_to_begin_at, len(ciphertext) // blocksize):

        bytes_so_far_this_block = b""
        for test_byte in range(blocksize):

            if index_of_target_block == block_to_begin_at:
                # If it's the first block, we control the prefix bytes.
                attacker_controlled_bytes = "A" * (blocksize - test_byte - 1)

                # Prefix is used for the dict calculation
                prefix = (
                    attacker_controlled_bytes.encode("utf-8") + bytes_so_far_this_block
                )

                # Add our prefix to pad the unknown bytes to the block boundary.
                attacker_controlled_bytes = (
                    "A" * number_of_characters_in_test_string
                    + attacker_controlled_bytes
                )
            else:
                # But if it's the second block or later, we need to use the
                # bytes we reconstructed from the previous block as the prefix.
                previous_block_bytes = reconstructed_str[-1 * (blocksize - 1) :]

                # The prefix is used for the dict calculation
                prefix = previous_block_bytes.encode("utf-8")

                # Add our prefix to pad the unknown bytes to the block boundary.
                attacker_controlled_bytes = (
                    "A" * number_of_characters_in_test_string
                    + "A" * (blocksize - test_byte - 1)
                )

            ciphertext = ecb_encrypt_prepend_and_append(
                key,
                attacker_controlled_bytes.encode("utf-8"),
                append_bytes,
                prepend_bytes,
            )

            cipher_dict = construct_ecb_attack_dict(key, prefix)

            target_block_ciphertext = ciphertext[
                (index_of_target_block - 1)
                * blocksize : index_of_target_block
                * blocksize
            ]

            last_char = cipher_dict[target_block_ciphertext]

            reconstructed_str = reconstructed_str + last_char
            bytes_so_far_this_block = bytes_so_far_this_block + last_char.encode(
                "utf-8"
            )

    assert "With my rag-top down so my hair can blow" in reconstructed_str


def test_cbc_bitflip_attack():
    # Set 2, challenge 16 CBC Bitflipping
    # Note: I did this assuming the prepended text was known by the attacker.

    block_size = BLOCK_SIZE
    key = gen_random_block()
    iv = gen_random_block()

    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"

    # Make sure ; and = are quoted
    # Selecting user controlled value exactly twice the target text
    plaintext = "123456789012123456789012".replace(";", "").replace("=", "")
    full_plaintext = prepend + plaintext + append
    ciphertext = cbc_encrypt_prepend_and_append(
        key,
        iv,
        plaintext.encode("utf-8"),
        append.encode("utf-8"),
        prepend.encode("utf-8"),
    )

    modified_ciphertext = b""
    target_text = ";admin=true;"
    edit_start_position = 0
    edit_stop_position = len(target_text)

    # Now tweak the bytes in the first ciphertext (comment field) such that the change
    # is introduced in the second plaintext.
    for ind, by in enumerate(ciphertext):
        if ind in range(edit_start_position, edit_stop_position):
            new_value = bytes(
                [
                    int.from_bytes(
                        target_text[edit_start_position + ind].encode("utf-8"), "big"
                    )
                    ^ ciphertext[ind]
                    ^ int.from_bytes(
                        full_plaintext[ind + block_size].encode("utf-8"), "big"
                    )
                ]
            )

            modified_ciphertext = modified_ciphertext + new_value
        else:
            modified_ciphertext = modified_ciphertext + bytes([by])

    decrypted_plaintext = aes_cbc_decrypt(key, modified_ciphertext, iv)

    assert target_text.encode("utf-8") in decrypted_plaintext


def test_aes_ctr_decrypt():
    # Set 3, challenge 18: Implement CTR, the stream cipher mode

    ciphertext = base64_to_bytes(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    key = "YELLOW SUBMARINE".encode("utf-8")
    nonce = 0

    result = aes_ctr_decrypt(key, ciphertext, nonce, BLOCK_SIZE)

    assert result == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def test_aes_ctr_consistency():
    test_text = b"pizza pie"
    key = "YELLOW SUBMARINE".encode("utf-8")
    nonce = 0

    ciphertext = aes_ctr_encrypt(key, test_text, nonce, BLOCK_SIZE)
    decrypted_plaintext = aes_ctr_decrypt(key, ciphertext, nonce, BLOCK_SIZE)

    assert test_text == decrypted_plaintext


def test_break_fixed_nonce_ctr():
    # Set 3, challenge 19: Break fixed-nonce CTR mode using substitutions

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/19.txt"
    )

    with open(path_to_test_data, "r") as f:
        plaintexts_b64 = f.readlines()

    plaintexts = [base64_to_bytes(x) for x in plaintexts_b64]
    key = os.urandom(BLOCK_SIZE)
    nonce = 0  # Fixed nonce

    ciphertexts = [aes_ctr_encrypt(key, x, nonce, BLOCK_SIZE) for x in plaintexts]

    # Each ciphertext has been encrypted against the same keystream:
    # c_1 = p_1 xor k_1
    # c_2 = p_2 xor k_2
    # since k_1 = k_2 = k, we can xor ciphertexts to get:
    # c_1 xor c_2 = p_1 xor k xor p_2 xor k = p_1 xor p_2

    C1_xor_C2 = namedtuple("C1_xor_C2", "c1_index c2_index value")
    xored = []
    for ind_x, ciphertext_x in enumerate(ciphertexts):
        for ind_y, ciphertext_y in enumerate(ciphertexts):
            if ind_x != ind_y:
                result = [bytes([x ^ y]) for x, y in zip(ciphertext_x, ciphertext_y)]
                result_bytes = b"".join(result)
                result_tuple = C1_xor_C2(ind_x, ind_y, result_bytes)
                xored.append(result_tuple)

    xored = list(set(xored))

    reconstructed_keystream = b"\x00" * 32
    keystream_byte_guesses = {}  # this will be a dict of lists

    # Crib dragging:
    # we have pairs of p_1 xor p_2
    # if we xor with p_{test} = sp_1 = p, we'll get; p_1 xor p_{test} xor p_2 = p_2 only
    # so let's try some trigrams and see if we get any english text, this will be p_2
    common_ngrams = [
        b"the ",
        b" and ",
        b"ing ",
        b" her ",
        b" his ",
        b"this ",
        b"And ",
        b"This ",
        b"The ",
        b" in the ",
        b" in ",
        b" or ",
        b"Or ",
        b"What ",
        b"To ",
        b"When ",
        b" when ",
        b"All ",
        b"of the ",
        b" my ",
        b"and th",
        b"ation",
        b"There ",
        b" there ",
        b" I ",
        b" I had ",
        b"Her ",
        b"His ",
        b" which ",
        b"Which ",
        b"Their ",
        b" their ",
        b" would ",
        b"Would ",
        b"end",
        b"for ",
        b"ate",
        b"eth",
        b"all",
        b" said",
        b" will",
        b"I have ",
    ]
    # top_words = [x.encode('utf8') for x in top_n_english_words(10)]
    top_words_with_space = [(x + " ").encode("utf8") for x in top_n_english_words(10)]
    english_guesses = list(set(common_ngrams + top_words_with_space))

    for pair in xored:
        for test_ngram in english_guesses:
            result = xor(pair.value, test_ngram)
            for found_ngram in english_guesses:
                if found_ngram != test_ngram and found_ngram in result:
                    # if the area where we found a match in c1_xor_c2 = \x00, then skip
                    # that's what we are doing with the found_ngram != test_ngram

                    # Otherwise we found a few bytes of keystream
                    starting_index = result.find(found_ngram)
                    len_ngram = len(found_ngram)
                    for index in range(len_ngram):
                        # k = p xor c
                        # but we don't know _which_ c to xor with
                        # let's add both and then vote at the end
                        ct_index = starting_index + index
                        c1 = ciphertexts[pair.c1_index]
                        c2 = ciphertexts[pair.c2_index]
                        keystream_byte_guess_c1 = bytes(
                            [found_ngram[index] ^ c1[ct_index]]
                        )
                        keystream_byte_guess_c2 = bytes(
                            [found_ngram[index] ^ c2[ct_index]]
                        )

                        try:
                            keystream_byte_guesses[ct_index].append(
                                keystream_byte_guess_c1
                            )
                            keystream_byte_guesses[ct_index].append(
                                keystream_byte_guess_c2
                            )
                        except KeyError:
                            keystream_byte_guesses[ct_index] = [
                                keystream_byte_guess_c1,
                                keystream_byte_guess_c2,
                            ]

    for ct_index in keystream_byte_guesses.keys():
        guesses = keystream_byte_guesses[ct_index]
        winning_guess = max(set(guesses), key=guesses.count)
        reconstructed_keystream = (
            reconstructed_keystream[:ct_index]
            + winning_guess
            + reconstructed_keystream[ct_index + 1 :]
        )

    expected_keystream = aes_ctr_encrypt(key, b"\x00" * 32, nonce, BLOCK_SIZE)

    percent_correct = (
        [x == y for x, y in zip(expected_keystream, reconstructed_keystream)].count(
            True
        )
        / len(reconstructed_keystream)
        * 100
    )
    assert percent_correct > 80.0


def test_break_fixed_nonce_ctr_statistically():
    # Set 3, challenge 20: Break fixed-nonce CTR mode statistically

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/20.txt"
    )

    with open(path_to_test_data, "r") as f:
        plaintexts_b64 = f.readlines()

    plaintexts = [base64_to_bytes(x) for x in plaintexts_b64]

    key = b"aaaaaaaaaaaaaaaa"
    nonce = 0  # Fixed nonce

    ciphertexts = [aes_ctr_encrypt(key, x, nonce, BLOCK_SIZE) for x in plaintexts]

    # Truncate to shortest ciphertext.
    num_blocks = len(min(ciphertexts)) // BLOCK_SIZE
    truncate = num_blocks * BLOCK_SIZE
    truncated_ciphertexts = [x[:truncate] for x in ciphertexts]

    # Generate keystream to compare the reconstructed answer with.
    counter = CounterMode(key, nonce, BLOCK_SIZE)
    keystream_blocks = [counter._generate_keystream_block() for x in range(num_blocks)]
    true_keystream = b"".join(keystream_blocks)

    assert truncate == len(true_keystream)

    combined_ciphertext = b"".join(truncated_ciphertexts)

    reconstructed_keystream = break_ctr_statistically(combined_ciphertext, truncate)

    percent_correct = (
        [x == y for x, y in zip(true_keystream, reconstructed_keystream)].count(True)
        / len(reconstructed_keystream)
        * 100
    )
    assert percent_correct > 70.0


def test_break_random_access_rw_ctr():
    # Set 4, challenge 25: Break "random access read/write" AES CTR

    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/20.txt"
    )

    with open(path_to_test_data, "r") as f:
        plaintexts_b64 = f.readlines()

    plaintexts = [base64_to_bytes(x) for x in plaintexts_b64]

    key = os.urandom(BLOCK_SIZE)
    nonce = 0

    ciphertexts = [aes_ctr_encrypt(key, x, nonce, BLOCK_SIZE) for x in plaintexts]
    edited_ciphertexts = []

    for ciphertext in ciphertexts:
        # Edit at position 0... why not!
        # And we'll edit to have all null bytes as the "new" plaintext. Allowed by the API!
        new_plaintext = b"\x00" * len(ciphertext)
        edited_ciphertext = aes_ctr_edit(key, ciphertext, 0, new_plaintext, nonce)
        edited_ciphertexts.append(edited_ciphertext)

    # This means that the "edited_ciphertexts" are really just the keystream.
    for ind, ciphertext in enumerate(ciphertexts):
        reconstructed_plaintext = xor(edited_ciphertexts[ind], ciphertext)
        assert reconstructed_plaintext == plaintexts[ind]
