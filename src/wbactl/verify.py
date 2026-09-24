"""Reference verifier for Web Bot Auth signatures (draft-00).

Strict by design: rejects unsigned, untagged, cross-host-replayable, expired and
bad-signature requests with a reason code. The ``@signature-params`` line of the
signature base is taken verbatim from the received ``Signature-Input`` member —
parsed parameters are never re-serialized.

The Signature-Input parser covers the profile used by Web Bot Auth (inner list of
sf-strings plus typed parameters) and rejects anything it cannot consume fully.
Full RFC 8941 (escapes, booleans, structured components) is P1.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from . import spec
from .keys import b64_decode, public_from_jwk, try_jwk_thumbprint
from .sign import signature_base

_KEY = r"[a-z*][a-z0-9_.*-]*"
_ENTRY = re.compile(rf"^(?P<label>{_KEY})=(?P<value>.+)$")
_INNER = re.compile(r"^\((?P<inner>.*?)\)(?P<rest>.*)$")
_KEY_RE = re.compile(_KEY)
_INT_RE = re.compile(r"-?\d{1,15}")
_SIGNATURE_ENTRY = re.compile(rf"^(?P<label>{_KEY})=:(?P<sig>[A-Za-z0-9+/=]+):$")


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    keyid: str | None = None
    signature_agent: str | None = None
    created: int | None = None
    expires: int | None = None
    covered: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Param:
    value: str
    quoted: bool


@dataclass(frozen=True)
class _Entry:
    label: str
    covered: tuple[str, ...]
    params_value: str
    params: dict[str, _Param]


def _split_top_level(value: str) -> list[str]:
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


def _unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _parse_params(rest: str) -> dict[str, _Param] | None:
    """Parse ``;name=value`` parameters; None when the string is not fully consumed."""
    params: dict[str, _Param] = {}
    position = 0
    while position < len(rest):
        if rest[position] != ";":
            return None
        position += 1
        while position < len(rest) and rest[position] == " ":
            position += 1
        name_match = _KEY_RE.match(rest, position)
        if not name_match:
            return None
        name = name_match.group(0)
        position = name_match.end()
        if position >= len(rest) or rest[position] != "=":
            return None
        position += 1
        if position < len(rest) and rest[position] == '"':
            end = position + 1
            while end < len(rest) and rest[end] not in ('"', "\\"):
                end += 1
            if end >= len(rest) or rest[end] != '"':
                return None
            params[name] = _Param(rest[position + 1 : end], True)
            position = end + 1
        else:
            int_match = _INT_RE.match(rest, position)
            if not int_match:
                return None
            params[name] = _Param(int_match.group(0), False)
            position = int_match.end()
    return params


def _parse_inner_list(inner: str) -> tuple[str, ...] | None:
    """Parse ``sf-string *(1*SP sf-string)``; None when anything else is present."""
    components: list[str] = []
    position = 0
    while position < len(inner):
        while position < len(inner) and inner[position] == " ":
            position += 1
        if position >= len(inner):
            break
        if inner[position] != '"':
            return None
        end = inner.find('"', position + 1)
        if end == -1:
            return None
        value = inner[position + 1 : end]
        if not value or "\\" in value or any(not 0x20 <= ord(char) <= 0x7E for char in value):
            return None
        components.append(value)
        position = end + 1
        if position < len(inner) and inner[position] != " ":
            return None
    if not components or len(set(components)) != len(components):
        return None
    return tuple(components)


def _parse_entry(entry: str) -> _Entry | None:
    match = _ENTRY.match(entry)
    if not match:
        return None
    value = match.group("value")
    inner = _INNER.match(value)
    if not inner:
        return None
    covered = _parse_inner_list(inner.group("inner"))
    if covered is None:
        return None
    params = _parse_params(inner.group("rest"))
    if params is None:
        return None
    return _Entry(match.group("label"), covered, value, params)


def _parse_signatures(value: str) -> dict[str, str]:
    signatures: dict[str, str] = {}
    for entry in _split_top_level(value):
        match = _SIGNATURE_ENTRY.match(entry)
        if match:
            signatures[match.group("label")] = match.group("sig")
    return signatures


def verify_request(
    method: str,
    url: str,
    headers: dict[str, str],
    jwks: dict | None = None,
    *,
    now: int | None = None,
    max_age: int | None = spec.MAX_SIGNATURE_AGE_SECONDS,
) -> VerifyResult:
    now = int(time.time()) if now is None else now
    lower = {name.lower(): value for name, value in headers.items()}
    signature_input = lower.get("signature-input", "")
    signature_header = lower.get("signature", "")
    if not signature_input or not signature_header:
        return VerifyResult(False, "no_signature")

    entries: list[_Entry] = []
    for raw in _split_top_level(signature_input):
        parsed = _parse_entry(raw)
        if parsed is None:
            return VerifyResult(False, "malformed_signature_input")
        entries.append(parsed)
    labels = [entry.label for entry in entries]
    if len(set(labels)) != len(labels):
        return VerifyResult(False, "malformed_signature_input")

    candidates = [
        entry
        for entry in entries
        if (tag := entry.params.get("tag")) is not None
        and tag.quoted
        and tag.value == spec.TAG
    ]
    if not candidates:
        return VerifyResult(False, "tag_missing")
    entry = candidates[0]

    signatures = _parse_signatures(signature_header)
    if entry.label not in signatures:
        return VerifyResult(False, "signature_missing_for_label")
    try:
        signature_bytes = b64_decode(signatures[entry.label])
    except ValueError:
        return VerifyResult(False, "bad_signature_encoding")

    if "@authority" not in entry.covered:
        return VerifyResult(False, "authority_not_covered")
    agent = _unquote(lower.get("signature-agent", ""))
    if not agent:
        return VerifyResult(False, "signature_agent_missing")
    if "signature-agent" not in entry.covered:
        return VerifyResult(False, "signature_agent_not_covered")

    keyid_param = entry.params.get("keyid")
    if keyid_param is None or not keyid_param.quoted or not keyid_param.value:
        return VerifyResult(False, "keyid_missing")
    keyid = keyid_param.value
    alg_param = entry.params.get("alg")
    if alg_param is None or not alg_param.quoted or alg_param.value != spec.ALG:
        return VerifyResult(False, "unsupported_alg")

    created_param = entry.params.get("created")
    if created_param is None:
        return VerifyResult(False, "created_missing")
    expires_param = entry.params.get("expires")
    if expires_param is None:
        return VerifyResult(False, "expires_missing")
    if (
        created_param.quoted
        or expires_param.quoted
        or not _INT_RE.fullmatch(created_param.value)
        or not _INT_RE.fullmatch(expires_param.value)
    ):
        return VerifyResult(False, "malformed_signature_input")
    created = int(created_param.value)
    expires = int(expires_param.value)
    if created > expires:
        return VerifyResult(False, "expires_before_created")
    if created > now + spec.CLOCK_SKEW_SECONDS:
        return VerifyResult(False, "created_in_future")
    if expires < now:
        return VerifyResult(False, "expired")
    if max_age is not None and now - created > max_age:
        return VerifyResult(False, "created_too_old")

    if not jwks or not isinstance(jwks.get("keys"), list):
        return VerifyResult(False, "no_key_source")
    jwk = next((key for key in jwks["keys"] if try_jwk_thumbprint(key) == keyid), None)
    if jwk is None:
        return VerifyResult(False, "keyid_not_found")

    try:
        base = signature_base(method, url, headers, entry.covered, entry.params_value)
        public_from_jwk(jwk).verify(signature_bytes, base)
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return VerifyResult(
            False,
            "bad_signature",
            keyid=keyid,
            signature_agent=agent,
            created=created,
            expires=expires,
            covered=entry.covered,
        )
    return VerifyResult(
        True,
        "ok",
        keyid=keyid,
        signature_agent=agent,
        created=created,
        expires=expires,
        covered=entry.covered,
    )
