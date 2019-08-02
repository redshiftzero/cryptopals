import pytest

from cryptopals.exceptions import BadPaddingValidation
from cryptopals.padding import pkcs_7, remove_pkcs_7


@pytest.mark.parametrize(
    "test_input, block_size, expected",
    [
        ("YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04"),
        ("YEL", 3, "YEL\x03\x03\x03"),
    ],
)
def test_pkcs_7(test_input, block_size, expected):
    assert pkcs_7(test_input.encode("utf-8"), block_size) == expected.encode("utf-8")


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("YELLOW SUBMARINE\x04\x04\x04\x04", "YELLOW SUBMARINE"),
        ("YEL\x03\x03\x03", "YEL"),
    ],
)
def test_removal_of_pkcs_7(test_input, expected):
    assert remove_pkcs_7(test_input.encode("utf-8")) == expected.encode("utf-8")


@pytest.mark.parametrize(
    "test_input",
    [("ICE ICE BABY\x01\x02\x03\x04"), ("ICE ICE BABY\x05\x05\x05\x05"), ("YE\x03"),
     ("ICE ICE BABY HI\x00")],
)
def test_removal_of_pkcs_7_raises_exception_invalid_padding(test_input):
    with pytest.raises(BadPaddingValidation):
        remove_pkcs_7(test_input.encode("utf-8"))
