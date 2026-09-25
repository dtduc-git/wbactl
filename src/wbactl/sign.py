"""Web Bot Auth request signing (RFC 9421 profile, draft-00)."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import spec
from .keys import b64, jwk_thumbprint, public_jwk

_COMPONENT_NAME = re.compile(r'"([^"]+)"')
_KEY_RE = re.compile(r"[a-z*][a-z0-9_.*-]*")
_BARE_VALUE = re.compile(r"[A-Za-z*][A-Za-z0-9_.:*/-]*|-?\d+|\?[01]")


def split_top_level(value: str) -> list[str]:
    """Split a structured-field list on commas that are not inside quoted strings."""
    entries: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif char == "," and not in_quote:
            entries.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    entries.append("".join(current).strip())
    return [entry for entry in entries if entry]


def component_name(identifier: str) -> str:
    """Component name from a serialized identifier (``"name";param="v"``)."""
    match = _COMPONENT_NAME.match(identifier)
    if not match:
        raise ValueError(f"invalid component identifier: {identifier!r}")
    return match.group(1)


def parse_component(identifier: str) -> tuple[str, dict[str, str]]:
    """Parse a serialized component identifier into (name, parameters)."""
    match = _COMPONENT_NAME.match(identifier)
    if not match:
        raise ValueError(f"invalid component identifier: {identifier!r}")
    name = match.group(1)
    rest = identifier[match.end() :]
    params: dict[str, str] = {}
    position = 0
    while position < len(rest):
        if rest[position] != ";":
            raise ValueError(f"invalid component identifier: {identifier!r}")
        position += 1
        name_match = _KEY_RE.match(rest, position)
        if not name_match:
            raise ValueError(f"invalid component identifier: {identifier!r}")
        param_name = name_match.group(0)
        position = name_match.end()
        if position >= len(rest) or rest[position] != "=":
            raise ValueError(f"invalid component identifier: {identifier!r}")
        position += 1
        if position < len(rest) and rest[position] == '"':
            end = rest.find('"', position + 1)
            if end == -1:
                raise ValueError(f"invalid component identifier: {identifier!r}")
            params[param_name] = rest[position + 1 : end]
            position = end + 1
        else:
            value_match = _BARE_VALUE.match(rest, position)
            if not value_match:
                raise ValueError(f"invalid component identifier: {identifier!r}")
            params[param_name] = value_match.group(0)
            position = value_match.end()
    return name, params


def _canonical_member_value(raw: str) -> str | None:
    """Strict serialization of a Dictionary member value (RFC 8941 §4.1.2)."""
    if not raw.startswith('"'):
        return None
    end = raw.find('"', 1)
    if end == -1:
        return None
    text = raw[1:end]
    if "\\" in text or any(not 0x20 <= ord(char) <= 0x7E for char in text):
        return None
    canonical = f'"{text}"'
    seen: set[str] = set()
    position = end + 1
    while position < len(raw):
        if raw[position] != ";":
            return None
        position += 1
        name_match = _KEY_RE.match(raw, position)
        if not name_match:
            return None
        name = name_match.group(0)
        if name in seen:
            return None
        seen.add(name)
        position = name_match.end()
        if position >= len(raw) or raw[position] != "=":
            return None
        position += 1
        if position < len(raw) and raw[position] == '"':
            param_end = raw.find('"', position + 1)
            if param_end == -1:
                return None
            param_value = raw[position + 1 : param_end]
            if "\\" in param_value or any(
                not 0x20 <= ord(char) <= 0x7E for char in param_value
            ):
                return None
            canonical += f';{name}="{param_value}"'
            position = param_end + 1
        else:
            value_match = _BARE_VALUE.match(raw, position)
            if not value_match:
                return None
            value = value_match.group(0)
            if value.startswith("?"):
                return None  # booleans canonicalize differently; unsupported here
            if value.lstrip("-").isdigit() and (
                len(value.lstrip("-")) > 15 or value.lstrip("-").startswith("0")
            ):
                return None
            canonical += f";{name}={value}"
            position = value_match.end()
    return canonical


def dictionary_member_value(header_value: str, key: str) -> str:
    """Canonical member value of a Dictionary field (RFC 9421 §2.1.2)."""
    found = False
    value: str | None = None
    for item in split_top_level(header_value):
        name, separator, raw = item.partition("=")
        if not separator or not _KEY_RE.fullmatch(name):
            raise ValueError(f"malformed dictionary member: {item!r}")
        if name != key:
            continue
        if found:
            raise ValueError(f"duplicate dictionary member {key!r}")
        found = True
        value = _canonical_member_value(raw)
        if value is None:
            raise ValueError(f"unsupported dictionary member value: {raw!r}")
    if not found or value is None:
        raise ValueError(f"dictionary has no member {key!r}")
    return value


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
        inner = " ".join(self.covered)
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

    ``covered`` holds serialized component identifiers; ``params_value`` must be
    the exact serialization used in the ``Signature-Input`` member: when
    verifying, pass the received string verbatim (never re-serialize).
    """
    lower = {name.lower(): value.strip() for name, value in headers.items()}
    lines: list[str] = []
    for identifier in covered:
        name, params = parse_component(identifier)
        if name.startswith("@"):
            if params:
                raise ValueError(f"derived component {name!r} takes no parameters")
            value = derived_component(name, method, url)
        else:
            if name not in lower:
                raise ValueError(f"covered header {name!r} is not present in the request")
            raw = lower[name]
            if params:
                if name != "signature-agent" or set(params) != {"key"}:
                    raise ValueError(f"unsupported component parameters on {name!r}")
                value = dictionary_member_value(raw, params["key"])
            else:
                value = raw
        lines.append(f"{identifier}: {value}")
    lines.append(f'"@signature-params": {params_value}')
    return "\n".join(lines).encode("utf-8")


def sign_request(
    method: str,
    url: str,
    headers: dict[str, str],
    private_key: Ed25519PrivateKey,
    signature_agent: str,
    *,
    covered: tuple[str, ...] | None = None,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    label: str = "sig1",
    signature_agent_type: str | None = None,
) -> dict[str, str]:
    """Return the headers to add to the request (Signature-Agent, Signature-Input, Signature).

    ``signature_agent_type`` selects the structured Signature-Agent format
    (``label="url";type=directory``) instead of the legacy bare string.
    """
    if signature_agent_type is None:
        agent_value = f'"{signature_agent}"'
        agent_identifier = '"signature-agent"'
    else:
        if signature_agent_type not in spec.SIGNATURE_AGENT_TYPES:
            raise ValueError(f"unsupported Signature-Agent type: {signature_agent_type!r}")
        agent_value = f'{label}="{signature_agent}";type={signature_agent_type}'
        agent_identifier = f'"signature-agent";key="{label}"'
    if covered is None:
        covered = ('"@authority"', agent_identifier)
    if '"@authority"' not in covered:
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
    request_headers = dict(headers)
    request_headers["Signature-Agent"] = agent_value
    base = signature_base(method, url, request_headers, params.covered, params.serialize())
    signature = private_key.sign(base)
    return {
        "Signature-Agent": agent_value,
        "Signature-Input": f"{label}={params.serialize()}",
        "Signature": f"{label}=:{b64(signature)}:",
    }
