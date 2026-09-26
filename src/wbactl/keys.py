"""Ed25519 keys, JWK export, RFC 7638 thumbprints."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def b64(data: bytes) -> str:
    """Standard base64, as used for structured-field byte sequences (RFC 9421 signatures)."""
    return base64.b64encode(data).decode("ascii")


_B64_STRICT = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def b64_decode(text: str) -> bytes:
    """Decode standard base64 strictly.

    Older CPython releases accept excess padding with ``validate=True`` while
    newer ones reject it, so length, alphabet and padding are validated here to
    keep verification version-independent (the length check is what catches
    excess padding).
    """
    if len(text) % 4 != 0 or not _B64_STRICT.fullmatch(text):
        raise ValueError("invalid base64")
    return base64.b64decode(text, validate=True)


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: Path, *, force: bool = False) -> None:
    """Write a private key with 0600 permissions; refuse to overwrite unless forced."""
    payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if force:
        path.unlink(missing_ok=True)
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(f"{path} already exists (use --force to overwrite)") from exc
    with os.fdopen(handle, "wb") as stream:
        stream.write(payload)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except TypeError as exc:
        raise ValueError(f"{path}: encrypted private keys are not supported") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: not an Ed25519 private key")
    return key


def _raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_jwk(public_key: Ed25519PublicKey) -> dict:
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(_raw_public_bytes(public_key))}


def public_from_jwk(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("JWK is not an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


def private_from_jwk(jwk: dict) -> Ed25519PrivateKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
        raise ValueError("JWK is not an Ed25519 private key")
    return Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"]))


# RFC 7638 §3.2: required members per key type, in lexicographic order.
_THUMBPRINT_MEMBERS = {
    "OKP": ("crv", "kty", "x"),
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint, base64url encoded."""
    kty = jwk.get("kty")
    if kty not in _THUMBPRINT_MEMBERS:
        raise ValueError(f"unsupported JWK kty: {kty!r}")
    members = {name: jwk[name] for name in _THUMBPRINT_MEMBERS[kty]}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def try_jwk_thumbprint(jwk: object) -> str | None:
    """Thumbprint of a JWK, or None when the entry is malformed or unsupported."""
    if not isinstance(jwk, dict):
        return None
    try:
        return jwk_thumbprint(jwk)
    except (KeyError, TypeError, ValueError):
        return None
