from cryptopals.utils import hex_to_base64, xor_hex_strings


def test_hex_str_to_base64_str():
    # Set 1, challenge 1
    test_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"  # type: str
    expected_result = (
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )  # type: str

    actual_result = hex_to_base64(test_input)
    assert actual_result == expected_result


def test_fixed_xor():
    # Set 1, challenge 2
    input_a = "1c0111001f010100061a024b53535009181c"  # type: str
    input_b = "686974207468652062756c6c277320657965"  # type: str

    expected_result = "746865206b696420646f6e277420706c6179"  # type: str

    actual_result = xor_hex_strings(input_a, input_b)

    assert actual_result == expected_result
