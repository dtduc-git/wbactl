"""Verifier rejection paths (negative controls)."""

import re
import time

import pytest

from wbactl.keys import generate_private_key, public_jwk
from wbactl.sign import sign_request
from wbactl.verify import _parse_params, verify_request

_UNCOVERED_AUTHORITY_HEADERS = {
    "Signature-Agent": '"https://agent.example"',
    "Signature-Input": (
        'sig1=("signature-agent");created=1;keyid="x";alg="ed25519"'
        ';expires=9999999999;tag="web-bot-auth"'
    ),
    "Signature": "sig1=:AAAA:",
}


def _signed(url: str = "https://example.com/a", **kwargs):
    key = generate_private_key()
    headers = sign_request("GET", url, {}, key, "https://agent.example", **kwargs)
    return key, headers


def test_unsigned_request_rejected() -> None:
    assert verify_request("GET", "https://example.com/a", {}).reason == "no_signature"


def test_untagged_signature_ignored() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace("web-bot-auth", "other-tag")
    assert verify_request("GET", "https://example.com/a", headers).reason == "tag_missing"


def test_authority_not_covered_rejected() -> None:
    result = verify_request("GET", "https://example.com/a", _UNCOVERED_AUTHORITY_HEADERS)
    assert result.reason == "authority_not_covered"


def test_signature_agent_must_be_covered() -> None:
    key, headers = _signed(covered=('"@authority"',))
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "signature_agent_not_covered"


def test_structured_agent_url_tamper_rejected() -> None:
    key = generate_private_key()
    headers = sign_request(
        "GET",
        "https://example.com/a",
        {},
        key,
        "https://agent.example",
        signature_agent_type="directory",
    )
    headers["Signature-Agent"] = 'sig1="https://attacker.example";type=directory'
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "bad_signature"


def test_structured_agent_label_mismatch_rejected() -> None:
    key = generate_private_key()
    headers = sign_request(
        "GET",
        "https://example.com/a",
        {},
        key,
        "https://agent.example",
        signature_agent_type="directory",
    )
    headers["Signature-Agent"] = 'sig2="https://agent.example";type=directory'
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "signature_agent_malformed"


def test_structured_agent_header_on_legacy_signature_rejected() -> None:
    key, headers = _signed()
    headers["Signature-Agent"] = 'sig1="https://agent.example";type=directory'
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "signature_agent_malformed"


_AGENT_PREFIX = 'sig1=("@authority" "signature-agent"{});created=1;keyid="x";alg="ed25519"'
_AGENT_SUFFIX = ';expires=9999999999;tag="web-bot-auth"'


@pytest.mark.parametrize(
    ("agent_header", "component", "reason"),
    [
        (
            'sig1="https://agent.example"',
            ';foo="x"',
            "signature_agent_not_covered",
        ),
        (
            'sig1="https://agent.example"',
            ' "signature-agent";key="sig1"',
            "signature_agent_not_covered",
        ),
        (
            'sig1="https://agent.example"',
            ';key="Sig1"',
            "signature_agent_not_covered",
        ),
        (
            'Sig1="https://agent.example"',
            ';key="sig1"',
            "signature_agent_malformed",
        ),
        (
            'sig1=""',
            ';key="sig1"',
            "signature_agent_malformed",
        ),
        (
            'sig1="https://agent.example";type=bogus',
            ';key="sig1"',
            "signature_agent_malformed",
        ),
        (
            'sig1="https://a.example",sig1="https://b.example"',
            ';key="sig1"',
            "signature_agent_malformed",
        ),
    ],
)
def test_agent_form_rejections(agent_header: str, component: str, reason: str) -> None:
    headers = {
        "Signature-Agent": agent_header,
        "Signature-Input": f"{_AGENT_PREFIX.format(component)}{_AGENT_SUFFIX}",
        "Signature": "sig1=:AAAA:",
    }
    assert verify_request("GET", "https://example.com/a", headers).reason == reason


def test_covered_agent_header_missing_rejected() -> None:
    key, headers = _signed()
    del headers["Signature-Agent"]
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "bad_signature"


def test_signature_without_agent_header_or_component_accepted() -> None:
    """Reference behaviour: agent coverage is only required when the header is present."""
    key, headers = _signed(covered=('"@authority"',))
    del headers["Signature-Agent"]
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.ok, result.reason
    assert result.signature_agent is None


def test_tampered_authority_rejected() -> None:
    """WBA covers @authority (not @path), so replaying to another host must fail."""
    key, headers = _signed()
    result = verify_request(
        "GET",
        "https://other.example/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
    )
    assert result.reason == "bad_signature"


def test_tampered_signature_agent_rejected() -> None:
    key, headers = _signed()
    headers["Signature-Agent"] = '"https://attacker.example"'
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
    )
    assert result.reason == "bad_signature"


def test_appended_param_rejected() -> None:
    """Regression: @signature-params must be used verbatim, not re-serialized."""
    key, headers = _signed()
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        ';tag="web-bot-auth"', ';tag="web-bot-auth";foo="bar"'
    )
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "bad_signature"


def test_reordered_params_rejected() -> None:
    key, headers = _signed()
    match = re.match(
        r'(sig1=\("[^)]*"\));created=(\d+);keyid="([^"]+)"(.*)', headers["Signature-Input"]
    )
    assert match is not None
    headers["Signature-Input"] = (
        f"{match.group(1)};keyid=\"{match.group(3)}\";created={match.group(2)}{match.group(4)}"
    )
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "bad_signature"


def test_expired_rejected() -> None:
    key, headers = _signed(created=1000, expires=2000)
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
        now=3000,
    )
    assert result.reason == "expired"


def test_created_in_future_rejected() -> None:
    key, headers = _signed(created=1_000_000, expires=1_000_300)
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
        now=1_000_000 - 3600,
    )
    assert result.reason == "created_in_future"


def test_created_too_old_rejected() -> None:
    now = 2_000_000
    key, headers = _signed(created=now - 200_000, expires=now + 300)
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
        now=now,
    )
    assert result.reason == "created_too_old"


def test_expires_before_created_rejected() -> None:
    key, headers = _signed(created=2000, expires=1000)
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
        now=1500,
    )
    assert result.reason == "expires_before_created"


def test_missing_created_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace("created=1;", "")
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")'
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == "created_missing"


def test_missing_expires_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace(";expires=9999999999", "")
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")'
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == "expires_missing"


def test_unsupported_alg_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace("ed25519", "rsa-pss-sha512")
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")'
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == "unsupported_alg"


def test_missing_keyid_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace('keyid="x";', "")
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")'
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == "keyid_missing"


def test_malformed_signature_input_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = "garbage"
    assert verify_request("GET", "https://example.com/a", headers).reason == (
        "malformed_signature_input"
    )


def test_quoted_timestamp_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = (
        headers["Signature-Input"]
        .replace("created=1;", 'created="1";')
        .replace('sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")')
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == (
        "malformed_signature_input"
    )


def test_param_hidden_in_string_is_not_a_tag() -> None:
    """A tag that only appears inside another parameter's string must not count."""
    hidden = ';created=1;keyid="x";alg="ed25519";expires=9999999999;n-once="a;tag=web-bot-auth b"'
    parsed = _parse_params(hidden)
    assert parsed is not None
    assert "tag" not in parsed

    headers = {
        "Signature-Agent": '"https://agent.example"',
        "Signature-Input": f'sig1=("@authority" "signature-agent"){hidden}',
        "Signature": "sig1=:AAAA:",
    }
    assert verify_request("GET", "https://example.com/a", headers).reason == "tag_missing"


def test_whitespace_after_semicolon_is_accepted() -> None:
    now = int(time.time())
    headers = {
        "Signature-Agent": '"https://agent.example"',
        "Signature-Input": (
            f'sig1=("@authority" "signature-agent"); created={now}; keyid="x"; alg="ed25519"'
            f"; expires={now + 300}; tag=\"web-bot-auth\""
        ),
        "Signature": "sig1=:AAAA:",
    }
    assert verify_request("GET", "https://example.com/a", headers).reason == "no_key_source"


def test_duplicate_labels_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = (
        f"{headers['Signature-Input']},{headers['Signature-Input']}"
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == (
        "malformed_signature_input"
    )


@pytest.mark.parametrize(
    "inner",
    [
        '(junk "@authority" "signature-agent")',
        '("" "@authority" "signature-agent")',
        '("@authority" "@authority")',
        '("@authority";req "signature-agent")',
    ],
)
def test_malformed_inner_list_rejected(inner: str) -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = (
        f'sig1={inner};created=1;keyid="x";alg="ed25519"'
        ';expires=9999999999;tag="web-bot-auth"'
    )
    assert verify_request("GET", "https://example.com/a", headers).reason == (
        "malformed_signature_input"
    )


def test_signature_missing_for_label_rejected() -> None:
    key, headers = _signed()
    headers["Signature"] = headers["Signature"].replace("sig1=:", "sig2=:")
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.reason == "signature_missing_for_label"


def test_bad_signature_encoding_rejected() -> None:
    headers = dict(_UNCOVERED_AUTHORITY_HEADERS)
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'sig1=("signature-agent")', 'sig1=("@authority" "signature-agent")'
    )
    headers["Signature"] = "sig1=:AAAA=:"
    assert verify_request("GET", "https://example.com/a", headers).reason == (
        "bad_signature_encoding"
    )


def test_missing_key_source_rejected() -> None:
    key, headers = _signed()
    assert verify_request("GET", "https://example.com/a", headers).reason == "no_key_source"


def test_unknown_keyid_rejected() -> None:
    key, headers = _signed()
    other = generate_private_key()
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(other.public_key())]},
    )
    assert result.reason == "keyid_not_found"


def test_hostile_jwks_does_not_crash() -> None:
    key, headers = _signed()
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [{"kty": "oct"}, "not-a-dict", {}]},
    )
    assert result.reason == "keyid_not_found"
