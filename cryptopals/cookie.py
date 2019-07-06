from typing import Dict


def parse_structured_cookie(cookie: str) -> Dict[str, str]:
    unpacked_cookie = {}
    fields = cookie.split("&")
    for field in fields:
        key = field.split("=")[0].strip()
        value = field.split("=")[1].strip()
        unpacked_cookie[key] = value

    return unpacked_cookie


def generate_profile_for(email: str, uid: int = 10, role: str = "user") -> str:
    if "=" in email or "&" in email:
        raise ValueError("Metadata characters found in email")

    return "email={}&uid={}&role={}".format(email, uid, role)
