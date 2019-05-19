from cryptopals.utils import hex_to_base64

def test_a_thing():
    # Set 1, challenge 1
    test_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'  # type: str
    expected_result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'  # type: str

    actual_result = hex_to_base64(test_input)
    assert actual_result == expected_result
