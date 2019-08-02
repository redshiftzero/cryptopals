import os
import random

from cryptopals.block import (
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    detect_ecb_use,
    cbc_padding_oracle,
    ecb_encrypt_append,
    ecb_encrypt_prepend_and_append,
    cbc_encrypt_prepend_and_append,
    encryption_ecb_cbc_detection_oracle,
    gen_random_block,
    construct_ecb_attack_dict,
)
from cryptopals.frequency import TEST_CHARACTERS
from cryptopals.utils import base64_to_bytes, hex_to_bytes


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

    # Making the input short and super easy for ECB detection
    input_bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode("utf-8")

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

                # Attacker-controlled bytes here are just to make sure there is only a single
                # unknown character in the target block.
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
    # decrypting with the first ciphertext block, when we manipulated it to contain one target character.
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

    number_of_characters_in_previous_block = (
        number_of_characters_in_test_string - blocksize
    )

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


def test_cbc_padding_oracle():
    path_to_test_data = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data/17.txt"
    )

    with open(path_to_test_data, "r") as f:
        plaintexts = f.read().split("\n")

    plaintext = random.choice(plaintexts)

    block_size = 16
    key = os.urandom(block_size)
    iv = os.urandom(block_size)

    plaintext_bytes = base64_to_bytes(plaintext)

    ciphertext = aes_cbc_encrypt(key, plaintext_bytes, iv)

    reconstructed_bytes = []
    for possible_byte in TEST_CHARACTERS:
        previous_block_ciphertext = os.urandom(block_size - 1) + possible_byte.encode(
            "utf-8"
        )
        print(len(previous_block_ciphertext))

        test_ciphertext = (
            previous_block_ciphertext + ciphertext[block_size : 2 * block_size]
        )
        print(test_ciphertext)

        valid_padding = cbc_padding_oracle(key, test_ciphertext, iv)
        if valid_padding == True:
            print("true!")
            reconstructed_bytes.append(possible_byte)

    import pdb

    pdb.set_trace()

    pass
