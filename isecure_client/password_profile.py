"""Explicit, downgrade-resistant password envelope for the additive v2 profile."""

import base64
import hashlib
import re
from typing import Any, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PASSWORD_ENCRYPTION_PROFILE = "password-rsa-oaep-sha256-v1"  # noqa: S105 - public protocol name


def validate_discovery(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("Invalid password discovery")
    raw_fields = {name: value.get(name) for name in ("Challenge", "EncryptionProfile", "KeyId", "PublicKey")}
    if not all(isinstance(item, str) for item in raw_fields.values()):
        raise ValueError("Invalid password discovery")
    fields = cast(dict[str, str], raw_fields)
    if (
        fields["EncryptionProfile"] != PASSWORD_ENCRYPTION_PROFILE
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", fields["KeyId"])
        or len(fields["Challenge"]) > 3072
        or not re.fullmatch(r"p1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", fields["Challenge"])
        or len(fields["PublicKey"]) > 2048
        or not fields["PublicKey"].startswith("-----BEGIN PUBLIC KEY-----")
    ):
        raise ValueError("Unsupported password discovery; no legacy fallback")
    return fields


def encrypt_password(discovery: dict[str, str], password: str) -> str:
    discovery = validate_discovery(discovery)
    raw = password.encode("utf-8", errors="strict")
    if not 1 <= len(raw) <= 283:
        raise ValueError("Password must contain 1–283 UTF-8 bytes")
    key = load_pem_public_key(discovery["PublicKey"].encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in (3072, 4096) or key.public_numbers().e != 65537:
        raise ValueError("Unsupported password encryption key")
    frame = (
        b"\x01" + hashlib.sha256(discovery["Challenge"].encode("ascii")).digest() + len(raw).to_bytes(2, "big") + raw
    )
    encrypted = key.encrypt(
        frame, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"")
    )
    return base64.b64encode(encrypted).decode("ascii")
