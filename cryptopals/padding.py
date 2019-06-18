def pkcs_7(plaintext: bytes, block_len: int) -> bytes:
    num_bytes_in_last_block = len(plaintext) % block_len

    num_bytes_of_padding = block_len - num_bytes_in_last_block

    # We always add some padding. If the length of the plaintext is a multiple
    # of the block length, then we add a block consisting entirely of padding.
    if num_bytes_of_padding == 0:
        num_bytes_of_padding = block_len

    return plaintext + bytes([num_bytes_of_padding] * num_bytes_of_padding)


def remove_pkcs_7(plaintext: bytes) -> bytes:
    num_bytes_of_padding = int.from_bytes(plaintext[-1:], byteorder="little")

    unpadded_plaintext = plaintext
    for _ in range(num_bytes_of_padding):
        if plaintext[-1:] != unpadded_plaintext[-1:]:
            # not padding bytes
            return plaintext
        unpadded_plaintext = unpadded_plaintext[:-1]

    return unpadded_plaintext
