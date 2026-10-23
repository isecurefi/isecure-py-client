"""Upload response regression tests using the real client and a mocked HTTP boundary."""

# Pytest assertions are intentional; all credentials below are synthetic.
# ruff: noqa: S101

import base64
import json
from typing import Any
from unittest.mock import patch

import pytest
import requests

from isecure_client import ISECureClient


@pytest.fixture
def client() -> ISECureClient:
    instance = ISECureClient(
        company="Synthetic",
        name="Test",
        password="synthetic-password",
        email="test@example.invalid",
        mode="data",
        phone="+358000000000",
        public_key="unused-for-upload",
        base_url="https://example.invalid/v2",
        bank="osuuspankki",
        api_key="synthetic-key",
        log_level="debug",
    )
    instance._id_token = "synthetic-token"  # noqa: S105
    return instance


def http_response(body: Any, status: int = 201) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    response.url = "https://example.invalid/v2/files/osuuspankki"
    return response


@pytest.mark.parametrize("content", ["AAEC//6A", "", None])
@pytest.mark.parametrize("signature", ["synthetic-signature", None])
def test_preserves_inline_content_and_acknowledgements(
    client: ISECureClient, caplog: pytest.LogCaptureFixture, content: str | None, signature: str | None
) -> None:
    body: dict[str, Any] = {"ResponseCode": "00", "ResponseText": "OK"}
    if content is not None:
        body["Content"] = content
    exact = base64.b64encode(b"\x00\xff\r\nquery").decode()
    with patch("isecure_client.client.requests.put", return_value=http_response(body)) as put:
        result = client.upload_file(exact, "query.xml", "camt.060.001.02", signature)
    assert result == body
    assert ("Content" in result) == (content is not None)
    put.assert_called_once()
    assert put.call_args.kwargs["url"] == "https://example.invalid/v2/files/osuuspankki"
    sent = json.loads(put.call_args.kwargs["data"])
    assert sent["FileContents"] == exact
    assert sent["FileName"] == "query.xml"
    assert sent["FileType"] == "camt.060.001.02"
    assert sent.get("Signature") == signature
    assert put.call_args.kwargs["headers"]["Authorization"] == "synthetic-token"
    assert "AAEC//6A" not in caplog.text
    assert exact not in caplog.text


def test_http_refusal_still_raises(client: ISECureClient) -> None:
    response = http_response({"ResponseCode": "01", "ResponseText": "Access denied"}, 403)
    with patch("isecure_client.client.requests.put", return_value=response) as put:
        with pytest.raises(requests.exceptions.HTTPError) as error:
            client.upload_file("eA==", "query.xml", "type", "signature")
    assert error.value.response is response
    put.assert_called_once()


@pytest.mark.parametrize("body", [[], None, "not an object"])
def test_non_object_response_is_rejected(client: ISECureClient, body: Any) -> None:
    with patch("isecure_client.client.requests.put", return_value=http_response(body)):
        with pytest.raises(ValueError, match="JSON object"):
            client.upload_file("eA==", "query.xml", "type")
