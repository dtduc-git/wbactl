"""Key handling: RFC 7638 known-answer + Ed25519 roundtrip."""

from pathlib import Path

import pytest

from wbactl.keys import (
    b64_decode,
    b64url_decode,
    generate_private_key,
    jwk_thumbprint,
    load_private_key,
    public_from_jwk,
    public_jwk,
    save_private_key,
)

# RFC 7638 §3.1 example JWK.
RFC7638_RSA_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
        "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
        "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
        "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
        "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
        "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_rfc7638_known_answer() -> None:
    assert jwk_thumbprint(RFC7638_RSA_JWK) == RFC7638_THUMBPRINT


def test_ed25519_roundtrip(tmp_path: Path) -> None:
    key = generate_private_key()
    path = tmp_path / "key.pem"
    save_private_key(key, path)
    loaded = load_private_key(path)
    jwk = public_jwk(loaded.public_key())
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert len(b64url_decode(jwk["x"])) == 32
    raw = key.public_key().public_bytes_raw()
    assert public_from_jwk(jwk).public_bytes_raw() == raw


def test_thumbprint_changes_with_key() -> None:
    first = jwk_thumbprint(public_jwk(generate_private_key().public_key()))
    second = jwk_thumbprint(public_jwk(generate_private_key().public_key()))
    assert first != second


def test_save_private_key_is_owner_only_and_exclusive(tmp_path: Path) -> None:
    path = tmp_path / "key.pem"
    save_private_key(generate_private_key(), path)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        save_private_key(generate_private_key(), path)
    save_private_key(generate_private_key(), path, force=True)


def test_b64_decode_strictness() -> None:
    assert b64_decode("AAAA") == b"\x00\x00\x00"
    assert b64_decode("AAA=") == b"\x00\x00"
    assert b64_decode("AA==") == b"\x00"
    malformed = (
        "AAAA=",
        "A===",
        "====",
        "AB=C",
        "A=A=",
        "AAA",
        "AAAAA",
        "AAA\n",
        "AA A",
        "AA-_",
        "AAAé",
    )
    for text in malformed:
        # Match our own message: stdlib may also raise ValueError, so a bare
        # raises() would pass even if our validation were removed.
        with pytest.raises(ValueError, match="invalid base64"):
            b64_decode(text)
