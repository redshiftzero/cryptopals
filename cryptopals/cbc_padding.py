import math
import os
from typing import List, Optional

from cryptopals.block import cbc_padding_oracle


def flip_nth_bit(text: bytes, num: int):
    modified = text[:num] + bytes([text[num] ^ 1]) + text[num + 1 :]
    return modified


class Solver(object):
    def __init__(self, block_size: int, iv: bytes, key: bytes, ciphertext: bytes):
        self.block_size = block_size
        self.ciphertext = ciphertext

        # We won't look at these, these would be used by the server
        self.iv = iv
        self.key = key

        self.reconstructed_bytes = []  # type: List
        self.debug = False  # type: bool

    def _decrypt_single_block(self, block_num):
        previous_block_ciphertext = self.ciphertext[
                (block_num - 2)
                * self.block_size : (block_num - 1)
                * self.block_size
            ]
        this_block_ciphertext = self.ciphertext[
            (block_num - 1) * self.block_size : block_num * self.block_size
        ]

        block_cipher_outputs_prior_to_xor = []

        for byte_num in range(self.block_size, 0, -1):

            valid_padding_byte = self.block_size - byte_num + 1
            found_a_byte = False

            for num in range(255):
                num_of_prefix_bytes = byte_num - 1

                test_block = b'0' * num_of_prefix_bytes + bytes(
                    [num]
                )

                # Now add the byte that will be padding for the bytes we've already
                # reconstructed.
                for block_cipher_output_byte in block_cipher_outputs_prior_to_xor:
                    padding_byte = block_cipher_output_byte ^ valid_padding_byte
                    test_block = test_block + bytes([padding_byte])

                full_test_ciphertext = test_block + this_block_ciphertext

                # Note that we're passing in the key and IV but we're only
                # returning whether or not the padding is valid, not the
                # decrypted content.
                valid_padding = cbc_padding_oracle(
                    self.key, full_test_ciphertext, self.iv
                )

                if not valid_padding:
                    continue

                block_cipher_output_byte = num ^ valid_padding_byte
                plaintext_byte = (
                    previous_block_ciphertext[num_of_prefix_bytes]
                    ^ block_cipher_output_byte
                )

                # Handling the padding block by ensuring we get the choice of
                # num correct (e.g. if the second to last byte in the block
                # happens to be 2, we will get valid padding for _two_ possible
                # bytes in the last byte position).
                byte_num_to_edit = self.block_size + byte_num - 2
                degeneracy_ciphertext = flip_nth_bit(
                    full_test_ciphertext, byte_num_to_edit - self.block_size
                )
                if cbc_padding_oracle(self.key, degeneracy_ciphertext, self.iv):
                    pass
                else:
                    continue

                if self.debug:  # Fail when we get a byte wrong before going any further
                    try:
                        expected_byte = self.plaintext_bytes[
                                self.block_size * (block_num - 1) + byte_num - 1]
                        assert plaintext_byte == expected_byte
                    except AssertionError:
                        breakpoint()

                found_a_byte = True

                # Save the reconstructed byte and the output of the block cipher
                # prior to XOR as we'll need it for the next byte to reconstruct.
                block_cipher_outputs_prior_to_xor = [
                    block_cipher_output_byte
                ] + block_cipher_outputs_prior_to_xor
                self.reconstructed_bytes = [
                    plaintext_byte
                ] + self.reconstructed_bytes

                break

            if self.debug and not found_a_byte:
                breakpoint()
            elif not found_a_byte:
                raise Exception("Did not reconstruct a byte this block!")

    def run(self, plaintext_bytes) -> List:
        self.plaintext_bytes = plaintext_bytes
        self.num_blocks = math.ceil(len(plaintext_bytes) / self.block_size)

        # We start at rightmost block and move right to left.
        for block_num in range(self.num_blocks, 0, -1):
            if block_num == 1:
                # We don't have the IV to decrypt further, so we stop here.
                break

            self._decrypt_single_block(block_num)

        return self.reconstructed_bytes
