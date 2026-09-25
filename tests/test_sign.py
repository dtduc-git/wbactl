"""Signature base construction and sign/verify roundtrip."""

import pytest

from wbactl.keys import generate_private_key, jwk_thumbprint, private_from_jwk, public_jwk
from wbactl.sign import (
    SignatureParams,
    _canonical_member_value,
    authority,
    dictionary_member_value,
    sign_request,
    signature_base,
)
from wbactl.verify import verify_request

# Published RFC 9421 test key from cloudflare/web-bot-auth (public test material).
CLOUDFLARE_TEST_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "test-key-ed25519",
    "d": "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
}
CLOUDFLARE_AGENT = "https://http-message-signatures-example.research.cloudflare.com"
CLOUDFLARE_URL = CLOUDFLARE_AGENT + "/"

# Generated with cloudflare/web-bot-auth (web-bot-auth@0.2.0, signSync) on
# 2026-09-24 — cross-implementation known answer.
CLOUDFLARE_VECTOR_INPUT = (
    'sig1=("@authority" "signature-agent");created=1735689600'
    ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"'
    ';alg="ed25519";expires=1798761600;tag="web-bot-auth"'
)
CLOUDFLARE_VECTOR_SIGNATURE = (
    "sig1=:Sm5jzYyhJcAxVVzpI4tC+cfdvcJrtwlaky/QEsuHiArg4KSArBmsWxy58pAY"
    "//54jlA7BdmHX6QxLJ6BYnRmCg==:"
)
CLOUDFLARE_STRUCTURED_AGENT = (
    'sig1="https://http-message-signatures-example.research.cloudflare.com";type=directory'
)
CLOUDFLARE_STRUCTURED_INPUT = (
    'sig1=("@authority" "signature-agent";key="sig1");created=1735689600'
    ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"'
    ';alg="ed25519";expires=1798761600;tag="web-bot-auth"'
)
CLOUDFLARE_STRUCTURED_SIGNATURE = (
    "sig1=:D/owE4IjbOivq0/hSy+Zy1XoVtH2K+D+/k38yJgcNJe5eD9T/Nm3FBPaMG"
    "6bnSSZ35T98jcdaHKO2b0+j1ArDg==:"
)


def test_cloudflare_reference_vector() -> None:
    key = private_from_jwk(CLOUDFLARE_TEST_JWK)
    headers = sign_request(
        "GET",
        CLOUDFLARE_URL,
        {},
        key,
        CLOUDFLARE_AGENT,
        created=1735689600,
        expires=1798761600,
    )
    assert headers["Signature-Input"] == CLOUDFLARE_VECTOR_INPUT
    assert headers["Signature"] == CLOUDFLARE_VECTOR_SIGNATURE


def test_cloudflare_structured_reference_vector() -> None:
    """Structured Signature-Agent uses the Dictionary member value (RFC 9421 §2.1.2)."""
    key = private_from_jwk(CLOUDFLARE_TEST_JWK)
    headers = sign_request(
        "GET",
        CLOUDFLARE_URL,
        {},
        key,
        CLOUDFLARE_AGENT,
        signature_agent_type="directory",
        created=1735689600,
        expires=1798761600,
    )
    assert headers["Signature-Agent"] == CLOUDFLARE_STRUCTURED_AGENT
    assert headers["Signature-Input"] == CLOUDFLARE_STRUCTURED_INPUT
    assert headers["Signature"] == CLOUDFLARE_STRUCTURED_SIGNATURE


def test_cloudflare_structured_known_answer_verifies() -> None:
    headers = {
        "Signature-Agent": CLOUDFLARE_STRUCTURED_AGENT,
        "Signature-Input": CLOUDFLARE_STRUCTURED_INPUT,
        "Signature": CLOUDFLARE_STRUCTURED_SIGNATURE,
    }
    result = verify_request(
        "GET",
        CLOUDFLARE_URL,
        headers,
        {"keys": [CLOUDFLARE_TEST_JWK]},
        now=1735689600,
        max_age=None,
    )
    assert result.ok, result.reason
    assert result.signature_agent == CLOUDFLARE_AGENT


def test_authority_omits_default_port() -> None:
    assert authority("https://example.com/x") == "example.com"
    assert authority("https://example.com:443/x") == "example.com"
    assert authority("http://example.com:80/x") == "example.com"
    assert authority("https://example.com:8443/x") == "example.com:8443"


def test_authority_brackets_ipv6() -> None:
    assert authority("https://[::1]/x") == "[::1]"
    assert authority("https://[::1]:8443/x") == "[::1]:8443"


def test_authority_idna_encodes_host() -> None:
    assert authority("https://例え.jp/x") == "例え.jp".encode("idna").decode()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"https://agent.test"', '"https://agent.test"'),
        ('"https://agent.test";type=directory', '"https://agent.test";type=directory'),
        ('"https://agent.test"; type=directory', None),
        ('"https://agent.test";type=bogus;type=directory', None),
        ('"https://agent.test";n=007', None),
        ('"https://agent.test";f=?1', None),
        ('"a\\"b"', None),
        ("token", None),
    ],
)
def test_canonical_member_value(raw: str, expected: str | None) -> None:
    assert _canonical_member_value(raw) == expected


def test_dictionary_member_value() -> None:
    header = 'sig1="https://agent.test";type=directory, sig2="https://other.test"'
    assert dictionary_member_value(header, "sig1") == '"https://agent.test";type=directory'
    assert dictionary_member_value(header, "sig2") == '"https://other.test"'
    with pytest.raises(ValueError):
        dictionary_member_value(header, "nope")
    with pytest.raises(ValueError):
        dictionary_member_value('sig1="a",sig1="b"', "sig1")


def test_signature_base_shape() -> None:
    params = SignatureParams(
        covered=('"@authority"', '"signature-agent"'),
        created=1735689600,
        expires=1735693200,
        keyid="abc",
    )
    base = signature_base(
        "GET",
        "https://example.com/path",
        {"Signature-Agent": '"https://agent.example"'},
        params.covered,
        params.serialize(),
    )
    assert base == (
        b'"@authority": example.com\n'
        b'"signature-agent": "https://agent.example"\n'
        b'"@signature-params": ("@authority" "signature-agent")'
        b';created=1735689600;keyid="abc";alg="ed25519"'
        b';expires=1735693200;tag="web-bot-auth"'
    )


def test_sign_verify_roundtrip() -> None:
    key = generate_private_key()
    headers = sign_request("GET", "https://example.com/a", {}, key, "https://agent.example")
    result = verify_request(
        "GET",
        "https://example.com/a",
        headers,
        {"keys": [public_jwk(key.public_key())]},
    )
    assert result.ok, result.reason
    assert result.keyid == jwk_thumbprint(public_jwk(key.public_key()))
    assert result.signature_agent == "https://agent.example"


def test_authority_must_be_covered_when_signing() -> None:
    key = generate_private_key()
    try:
        sign_request(
            "GET",
            "https://example.com/a",
            {},
            key,
            "https://agent.example",
            covered=('"signature-agent"',),
        )
    except ValueError as exc:
        assert "@authority" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_structured_signature_agent_format() -> None:
    key = generate_private_key()
    headers = sign_request(
        "GET",
        "https://example.com/a",
        {},
        key,
        "https://agent.example",
        signature_agent_type="directory",
        created=1735689600,
        expires=1798761600,
    )
    assert headers["Signature-Agent"] == 'sig1="https://agent.example";type=directory'
    assert headers["Signature-Input"].startswith(
        'sig1=("@authority" "signature-agent";key="sig1");created=1735689600'
    )


def test_structured_signature_agent_roundtrip() -> None:
    key = generate_private_key()
    headers = sign_request(
        "GET",
        "https://example.com/a",
        {},
        key,
        "https://agent.example",
        signature_agent_type="directory",
    )
    result = verify_request(
        "GET", "https://example.com/a", headers, {"keys": [public_jwk(key.public_key())]}
    )
    assert result.ok, result.reason
    assert result.signature_agent == "https://agent.example"


def test_unknown_signature_agent_type_rejected() -> None:
    key = generate_private_key()
    try:
        sign_request(
            "GET",
            "https://example.com/a",
            {},
            key,
            "https://agent.example",
            signature_agent_type="bogus",
        )
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:
        raise AssertionError("expected ValueError")
