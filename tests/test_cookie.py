import pytest

from cryptopals.block import (
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    detect_ecb_use,
    ecb_encrypt_append,
    encryption_ecb_cbc_detection_oracle,
    gen_random_block,
    construct_ecb_attack_dict,
)
from cryptopals.cookie import parse_structured_cookie, generate_profile_for


def test_cookie_parsed_correctly():
    test_value = "foo=bar&baz=qux&zap=zazzle"

    profile_dict = parse_structured_cookie(test_value)

    assert profile_dict["foo"] == "bar"
    assert profile_dict["baz"] == "qux"
    assert profile_dict["zap"] == "zazzle"


def test_profile_for_success():
    cookie = generate_profile_for("foo@bar.com", 10, "user")

    assert cookie == "email=foo@bar.com&uid=10&role=user"


def test_profile_for_failure():
    with pytest.raises(ValueError):
        generate_profile_for("foo=bar.com", 10, "user")


def test_ecb_cut_and_paste_cookie():
    # Set 2, challenge 13

    block_size = 16
    key = gen_random_block(block_size)

    original_cookie = generate_profile_for("foo@bar.com")
    encrypted_original_cookie = aes_ecb_encrypt(key, original_cookie.encode("utf-8"))

    # Get a block containing (we'll take block two from the ciphertext):
    # email=blahhhhhhh | admin            | &uid...

    oracle_cookie = generate_profile_for("blahhhhhhhadmin           ")
    encrypted_oracle_cookie = aes_ecb_encrypt(key, oracle_cookie.encode("utf-8"))

    # Get a ciphertext with role at the block boundary
    # so we can strip off the existing role:
    #                 |                |
    # email=blaaaaaaaaaaah&uid=10&role=

    cut_and_pasted_cookie = generate_profile_for("blaaaaaaaaaah")
    encrypted_cut_and_pasted_cookie = aes_ecb_encrypt(
        key, cut_and_pasted_cookie.encode("utf-8")
    )

    # Since the ECB plaintexts are padded, we need to also add a block
    # of padding on the end such that the padding will validate.
    #                 |                |
    # email=blaaaaaah&uid=10&role=user

    padding_cookie = generate_profile_for("blaaaaaah")
    encrypted_padding_cookie = aes_ecb_encrypt(key, padding_cookie.encode("utf-8"))

    block_to_paste = encrypted_oracle_cookie[block_size : 2 * block_size]
    block_to_cut = encrypted_cut_and_pasted_cookie[0 : -1 * block_size]
    block_to_pad = encrypted_padding_cookie[-1 * block_size :]
    encrypted_admin_profile = block_to_cut + block_to_paste + block_to_pad

    decrypted_admin_profile = aes_ecb_decrypt(key, encrypted_admin_profile)
    admin_profile = parse_structured_cookie(decrypted_admin_profile.decode("utf-8"))

    assert admin_profile["role"] == "admin"
