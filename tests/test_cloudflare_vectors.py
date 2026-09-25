"""Known-answer interop against cloudflare/web-bot-auth architecture vectors.

Vendored (Apache-2.0) at tests/data/cloudflare-web-bot-auth-architecture-v1.json.
Only the Ed25519 vectors are exercised; rsa-pss-sha512 support is P1.
"""

import json
from pathlib import Path

from wbactl.verify import verify_request

DATA = Path(__file__).parent / "data" / "cloudflare-web-bot-auth-architecture-v1.json"
NOW = 1735689600


def _vectors() -> list[dict]:
    return json.loads(DATA.read_text())


def _headers(vector: dict) -> dict[str, str]:
    headers = {
        "Signature-Input": vector["signature_input"],
        "Signature": vector["signature"],
    }
    if "signature_agent" in vector:
        headers["Signature-Agent"] = vector["signature_agent"]
    return headers


def test_ed25519_architecture_vectors_verify() -> None:
    checked = 0
    for vector in _vectors():
        if vector["key"].get("kty") != "OKP":
            continue
        result = verify_request(
            "GET",
            vector["target_url"],
            _headers(vector),
            {"keys": [vector["key"]]},
            now=NOW,
            max_age=None,
        )
        assert result.ok, (vector["label"], result.reason)
        checked += 1
    assert checked == 2


def test_rsa_vectors_report_unsupported_alg() -> None:
    checked = 0
    for vector in _vectors():
        if vector["key"].get("kty") != "RSA":
            continue
        result = verify_request(
            "GET",
            vector["target_url"],
            _headers(vector),
            {"keys": [vector["key"]]},
            now=NOW,
            max_age=None,
        )
        assert result.reason == "unsupported_alg"
        checked += 1
    assert checked == 2
