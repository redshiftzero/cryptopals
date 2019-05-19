import base64

def hex_to_base64(hex_str: str) -> str:
    hex_bytes = bytes.fromhex(hex_str)
    base64_str = base64.b64encode(hex_bytes).decode('utf-8')
    return base64_str
