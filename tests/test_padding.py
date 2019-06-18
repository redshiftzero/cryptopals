import pytest

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
        ("YE\x03", "YE\x03"),
    ],
)
def test_removal_of_pkcs_7(test_input, expected):
    assert remove_pkcs_7(test_input.encode("utf-8")) == expected.encode("utf-8")
