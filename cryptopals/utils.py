import base64
import itertools


def hex_to_base64(hex_str: str) -> str:
    hex_bytes = hex_to_bytes(hex_str)
    base64_str = bytes_to_base64(hex_bytes)
    return base64_str


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def bytes_to_hex(bytes_input: bytes) -> str:
    return bytes_input.hex()


def base64_to_bytes(str_input: str) -> bytes:
    return base64.b64decode(str_input)


def bytes_to_base64(bytes_input: bytes) -> str:
    return base64.b64encode(bytes_input).decode("utf-8")


def xor_hex_strings(input_a: str, input_b: str) -> str:
    bytes_result = xor(hex_to_bytes(input_a), hex_to_bytes(input_b))
    return bytes_to_hex(bytes_result)


def hex_to_ascii(hex_str: str) -> str:
    return bytes.fromhex(hex_str).decode("utf8")


def xor(input_a: bytes, input_b: bytes) -> bytes:
    input_b_generator = itertools.cycle(input_b)
    result = [a ^ b for a, b in zip(input_a, input_b_generator)]
    return bytes(result)


def edit_distance(input_a: bytes, input_b: bytes) -> int:
    differing_bits = [x ^ y for x, y in zip(input_a, input_b)]
    return "".join([bin(x) for x in differing_bits]).count("1")
