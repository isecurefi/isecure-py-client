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


@pytest.mark.parametrize("operation", ["login", "register", "reset"])
@pytest.mark.parametrize("selector", [None, "legacy"])
def test_client_default_and_explicit_legacy_wire(operation: str, selector: str | None) -> None:
    from unittest.mock import patch

    import requests

    from isecure_client import ISECureClient

    key = VECTORS["Keys"][0]
    case = VECTORS["Cases"][0]
    client = ISECureClient(
        company="Synthetic", name="Test", password=case["Password"], email="user@example.invalid",
        mode="data", phone="+358000000000", public_key=key["PublicKey"],
        base_url="https://example.invalid/v2", bank="nordea", api_key="tenant",
        encryption_profile=selector,
    )
    discovery = {**case, "PublicKey": key["PublicKey"]}
    if selector == "legacy":
        discovery = {"Challenge": "nonce|1789841000000|request-id"}
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(discovery).encode()
    with patch("isecure_client.client.requests.get", return_value=response) as get:
        if operation == "reset":
            with patch("isecure_client.client.requests.post", return_value=response) as post:
                client.init_password_reset()
                client.reset_password("123456", case["Password"])
                body = json.loads(post.call_args.kwargs["data"])
        else:
            body = client._password_request(operation, case["Password"])
    private = serialization.load_pem_private_key(key["PrivateKey"].encode(), password=None)
    assert isinstance(private, rsa.RSAPrivateKey)  # noqa: S101
    algorithm = hashes.SHA1() if selector == "legacy" else hashes.SHA256()  # noqa: S303
    plain = private.decrypt(base64.b64decode(body["Encrypted"]), padding.OAEP(
        mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None))
    if selector == "legacy":
        assert "EncryptionProfile" not in body and "KeyId" not in body  # noqa: S101
        assert all("?" not in c.args[0] for c in get.call_args_list)  # noqa: S101
        assert plain.decode() == case["Password"] + "||1789841000000"  # noqa: S101
    else:
        assert body["EncryptionProfile"] == "password-rsa-oaep-sha256-v1"  # noqa: S101
        assert plain.hex() == case["FrameHex"]  # noqa: S101
        assert "EncryptionProfile=" in get.call_args.args[0]  # noqa: S101
        if operation == "register":
            assert "ApiKey=tenant" in get.call_args.args[0]  # noqa: S101
        if operation == "reset":
            assert "/password?" in get.call_args.args[0]  # noqa: S101


def test_default_refuses_old_server_and_invalid_override() -> None:
    from unittest.mock import patch

    import requests

    from isecure_client import PASSWORD_ENCRYPTION_PROFILE, ISECureClient

    client = ISECureClient(company="Synthetic", name="Test", password="Synthetic-42!", email="user@example.invalid",
                          mode="data", phone="+358000000000", public_key="unused",
                          base_url="https://example.invalid/v2", bank="nordea")
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"Challenge":"old-server"}'
    with patch("isecure_client.client.requests.get", return_value=response) as get:
        with pytest.raises(ValueError):
            client._password_request("login", "Synthetic-42!")
        assert get.call_count == 1  # noqa: S101
    client.update_props(encryption_profile="legacy")
    client.update_props(encryption_profile=None)
    assert client.encryption_profile == PASSWORD_ENCRYPTION_PROFILE  # noqa: S101
    with pytest.raises(ValueError):
        client.update_props(encryption_profile="unsupported")
    assert client.encryption_profile == PASSWORD_ENCRYPTION_PROFILE  # noqa: S101
