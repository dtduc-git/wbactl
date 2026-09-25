#!/usr/bin/env python3
"""Regenerate src/wbactl/vectors/wbactl.json deterministically.

Run from the repo root: uv run python scripts/generate_vectors.py
Ed25519 signing is deterministic, so the output is reproducible.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wbactl import spec
from wbactl.keys import b64, jwk_thumbprint, public_jwk
from wbactl.sign import SignatureParams, sign_request, signature_base

OUT = Path(__file__).resolve().parents[1] / "src" / "wbactl" / "vectors" / "wbactl.json"
KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"wbactl conformance key v1").digest())
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"wbactl conformance other key v1").digest()
)
URL = "https://example.com/path/to/resource"
AGENT = "https://signature-agent.test"
CREATED = 1735689600
EXPIRES = 4102444800  # 2100-01-01, so positive vectors never expire
NOW = CREATED + 60


def _signed(**kwargs) -> dict[str, str]:
    return sign_request("GET", URL, {}, KEY, AGENT, created=CREATED, expires=EXPIRES, **kwargs)


def _manual(
    covered: tuple[str, ...],
    agent_header: str,
    *,
    tag: str = spec.TAG,
    sign: bool = True,
) -> dict[str, str]:
    params = SignatureParams(
        covered=covered,
        created=CREATED,
        expires=EXPIRES,
        keyid=jwk_thumbprint(public_jwk(KEY.public_key())),
        tag=tag,
    )
    headers = {"Signature-Agent": agent_header}
    if sign:
        base = signature_base("GET", URL, headers, covered, params.serialize())
        signature = b64(KEY.sign(base))
    else:
        signature = "AAAA"
    return {
        "Signature-Agent": agent_header,
        "Signature-Input": f"sig1={params.serialize()}",
        "Signature": f"sig1=:{signature}:",
    }


def _flip_base64(value: str) -> str:
    marker = value.index(":") + 2
    replacement = "A" if value[marker] != "A" else "B"
    return value[:marker] + replacement + value[marker + 1 :]


def build() -> dict:
    legacy = _signed()
    structured = _signed(signature_agent_type="directory")
    no_agent = _signed(covered=('"@authority"',))
    del no_agent["Signature-Agent"]
    missing_coverage = _signed(covered=('"@authority"',))
    expired = sign_request("GET", URL, {}, KEY, AGENT, created=CREATED, expires=CREATED + 3600)
    future = sign_request(
        "GET", URL, {}, KEY, AGENT, created=CREATED + 3600, expires=CREATED + 7200
    )

    bad_signature = dict(legacy)
    bad_signature["Signature"] = _flip_base64(bad_signature["Signature"])

    bad_encoding = dict(legacy)
    bad_encoding["Signature"] = "sig1=:AAAA=:"

    untagged = _manual(('"@authority"', '"signature-agent"'), f'"{AGENT}"', tag="other-tag")

    malformed = dict(legacy)
    malformed["Signature-Input"] = "garbage"

    agent_tamper = dict(structured)
    agent_tamper["Signature-Agent"] = 'sig1="https://attacker.test";type=directory'

    label_mismatch = dict(structured)
    label_mismatch["Signature-Agent"] = 'sig2="https://signature-agent.test";type=directory'

    header_removed = dict(legacy)
    del header_removed["Signature-Agent"]

    duplicate_components = _manual(
        ('"@authority"', '"signature-agent"', '"signature-agent";key="sig1"'),
        'sig1="https://signature-agent.test";type=directory',
    )
    unknown_params = SignatureParams(
        covered=('"@authority"', '"signature-agent";foo="x"'),
        created=CREATED,
        expires=EXPIRES,
        keyid=jwk_thumbprint(public_jwk(KEY.public_key())),
    )
    unknown_base = "\n".join(
        [
            '"@authority": example.com',
            f'"signature-agent";foo="x": "{AGENT}"',
            f'"@signature-params": {unknown_params.serialize()}',
        ]
    ).encode()
    unknown_param = {
        "Signature-Agent": f'"{AGENT}"',
        "Signature-Input": f"sig1={unknown_params.serialize()}",
        "Signature": f"sig1=:{b64(KEY.sign(unknown_base))}:",
    }
    no_authority = _manual(('"signature-agent"',), f'"{AGENT}"')

    def vector(name: str, headers: dict[str, str], **kwargs) -> dict:
        entry = {"name": name, "method": "GET", "url": URL, "headers": headers, "now": NOW}
        entry.update(kwargs)
        return entry

    return {
        "spec": spec.DRAFT,
        "keys": [public_jwk(KEY.public_key())],
        "vectors": [
            vector("accept-legacy", legacy, expect="accept", reason="ok"),
            vector("accept-structured", structured, expect="accept", reason="ok"),
            vector("accept-no-agent", no_agent, expect="accept", reason="ok"),
            vector("reject-unsigned", {}, expect="reject", reason="no_signature"),
            vector("reject-bad-signature", bad_signature, expect="reject", reason="bad_signature"),
            vector(
                "reject-expired",
                expired,
                expect="reject",
                reason="expired",
                now=CREATED + 7200,
            ),
            vector(
                "reject-created-in-future",
                future,
                expect="reject",
                reason="created_in_future",
                now=CREATED,
            ),
            vector(
                "reject-wrong-authority",
                legacy,
                url="https://other.example/path/to/resource",
                expect="reject",
                reason="bad_signature",
            ),
            vector(
                "reject-malformed-signature-input",
                malformed,
                expect="reject",
                reason="malformed_signature_input",
            ),
            vector("reject-untagged", untagged, expect="reject", reason="tag_missing"),
            vector("reject-agent-tamper", agent_tamper, expect="reject", reason="bad_signature"),
            vector(
                "reject-agent-label-mismatch",
                label_mismatch,
                expect="reject",
                reason="signature_agent_malformed",
            ),
            vector(
                "reject-agent-header-removed",
                header_removed,
                expect="reject",
                reason="bad_signature",
            ),
            vector(
                "reject-bad-encoding",
                bad_encoding,
                expect="reject",
                reason="bad_signature_encoding",
            ),
            vector(
                "reject-missing-agent-coverage",
                missing_coverage,
                expect="reject",
                reason="signature_agent_not_covered",
            ),
            vector(
                "reject-duplicate-agent-components",
                duplicate_components,
                expect="reject",
                reason="signature_agent_not_covered",
            ),
            vector(
                "reject-unknown-agent-param",
                unknown_param,
                expect="reject",
                reason="signature_agent_not_covered",
            ),
            vector(
                "reject-authority-not-covered",
                no_authority,
                expect="reject",
                reason="authority_not_covered",
            ),
            vector(
                "reject-keyid-not-found",
                legacy,
                expect="reject",
                reason="keyid_not_found",
                keys=[public_jwk(OTHER_KEY.public_key())],
            ),
        ],
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2, sort_keys=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
