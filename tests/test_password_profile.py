"""Local synthetic interop; no AWS or network effects."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from isecure_client.password_profile import encrypt_password, validate_discovery

VECTORS = json.loads((Path(__file__).parent / "fixtures/password-profile/vectors.json").read_text())


@pytest.mark.parametrize("case", VECTORS["Cases"], ids=lambda c: c["Name"])
def test_interoperability(case: dict[str, Any]) -> None:
    key = next(k for k in VECTORS["Keys"] if k["KeyId"] == case["KeyId"])
    discovery = {**case, "PublicKey": key["PublicKey"]}
    encrypted = encrypt_password(discovery, case["Password"])
    private = serialization.load_pem_private_key(key["PrivateKey"].encode(), password=None)
    if not isinstance(private, rsa.RSAPrivateKey):
        raise TypeError("Synthetic fixture must be RSA")
    plain = private.decrypt(
        base64.b64decode(encrypted),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b""),
    )
    assert plain.hex() == case["FrameHex"]  # noqa: S101 - test assertion


@pytest.mark.parametrize("password", ["", "x" * 284, "🔐" * 71, "\ud800"])
def test_password_bounds(password: str) -> None:
    with pytest.raises((ValueError, UnicodeError)):
        encrypt_password({**VECTORS["Cases"][0], "PublicKey": VECTORS["Keys"][0]["PublicKey"]}, password)


@pytest.mark.parametrize("fields", [{}, {"Challenge": "legacy"}, {"EncryptionProfile": "wrong"}])
def test_no_downgrade(fields: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        validate_discovery(fields)
