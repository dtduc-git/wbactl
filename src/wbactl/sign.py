"""Web Bot Auth request signing (RFC 9421 profile, draft-00)."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import spec
from .keys import b64, jwk_thumbprint, public_jwk


@dataclass(frozen=True)
class SignatureParams:
    covered: tuple[str, ...]
    created: int
    expires: int
    keyid: str
    alg: str = spec.ALG
    tag: str = spec.TAG
    nonce: str | None = None

    def serialize(self) -> str:
        inner = " ".join(f'"{name}"' for name in self.covered)
        value = (
            f"({inner});created={self.created};keyid=\"{self.keyid}\""
            f";alg=\"{self.alg}\";expires={self.expires}"
        )
        if self.nonce is not None:
            value += f';nonce="{self.nonce}"'
        return value + f';tag="{self.tag}"'


def authority(url: str) -> str:
    """RFC 9421 @authority: host (IDNA A-label), with a port only when non-default."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"URL has no host: {url!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"URL host is not IDNA-encodable: {url!r}") from exc
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    default = (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)
    if port is None or default:
        return host
    return f"{host}:{port}"


def derived_component(name: str, method: str, url: str) -> str:
    parts = urlsplit(url)
    if name == "@authority":
        return authority(url)
    if name == "@method":
        return method.upper()
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return f"?{parts.query}" if parts.query else "?"
    if name == "@scheme":
        return parts.scheme
    if name == "@target-uri":
        return url
    raise ValueError(f"unsupported derived component: {name}")


def signature_base(
    method: str,
    url: str,
    headers: dict[str, str],
    covered: tuple[str, ...],
    params_value: str,
) -> bytes:
    """RFC 9421 §2.5 signature base.

    ``params_value`` must be the exact serialization used in the
    ``Signature-Input`` member: when verifying, pass the received string
    verbatim (never re-serialize parsed parameters).
    """
    lower = {name.lower(): value.strip() for name, value in headers.items()}
    lines: list[str] = []
    for name in covered:
        if name.startswith("@"):
            value = derived_component(name, method, url)
        else:
            if name not in lower:
                raise ValueError(f"covered header {name!r} is not present in the request")
            value = lower[name]
        lines.append(f'"{name}": {value}')
    lines.append(f'"@signature-params": {params_value}')
    return "\n".join(lines).encode("utf-8")


def signature_agent_value(url: str) -> str:
    """The Signature-Agent header value: a structured-field string."""
    return f'"{url}"'


def sign_request(
    method: str,
    url: str,
    headers: dict[str, str],
    private_key: Ed25519PrivateKey,
    signature_agent: str,
    *,
    covered: tuple[str, ...] = spec.REQUIRED_COMPONENTS,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    label: str = "sig1",
) -> dict[str, str]:
    """Return the headers to add to the request (Signature-Agent, Signature-Input, Signature)."""
    if "@authority" not in covered:
        raise ValueError("@authority must be covered (cross-host replay protection)")
    now = int(time.time())
    created = now if created is None else created
    expires = created + spec.DEFAULT_LIFETIME_SECONDS if expires is None else expires
    params = SignatureParams(
        covered=tuple(covered),
        created=created,
        expires=expires,
        keyid=jwk_thumbprint(public_jwk(private_key.public_key())),
        nonce=nonce,
    )
    agent = signature_agent_value(signature_agent)
    request_headers = dict(headers)
    request_headers["Signature-Agent"] = agent
    base = signature_base(method, url, request_headers, params.covered, params.serialize())
    signature = private_key.sign(base)
    return {
        "Signature-Agent": agent,
        "Signature-Input": f"{label}={params.serialize()}",
        "Signature": f"{label}=:{b64(signature)}:",
    }
