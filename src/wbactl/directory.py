"""Key directory fetch and validation with SSRF guards (draft-00).

The Signature-Agent URL is attacker-controlled input, so the fetch is
https-only, resolves the host exactly once, rejects non-global addresses
(including NAT64 and IPv4-mapped forms), pins the connection to the checked
address, refuses non-200 responses, and caps the response size.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import __version__, spec
from .keys import try_jwk_thumbprint

_USER_AGENT = f"wbactl-directory/{__version__}"
_NAT64_WKP = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")


class DirectoryError(Exception):
    """Directory could not be validated, fetched or parsed."""


def _is_global(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped.is_global
        if address in _NAT64_WKP:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF).is_global
        if address in _NAT64_LOCAL or address in _SIX_TO_FOUR or address in _IPV4_COMPATIBLE:
            return False
    return address.is_global


def _resolve_global_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise DirectoryError(f"cannot resolve host {host!r}: {exc}") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise DirectoryError(f"host {host!r} did not resolve")
    for address in addresses:
        if not _is_global(ipaddress.ip_address(address)):
            raise DirectoryError(f"directory host resolves to non-global address {address}")
    return addresses


@dataclass(frozen=True)
class DirectoryTarget:
    host: str
    port: int
    addresses: tuple[str, ...]
    directory_url: str


def resolve_target(signature_agent: str) -> DirectoryTarget:
    """Validate a Signature-Agent origin and resolve it to pinned addresses."""
    parts = urlsplit(signature_agent)
    if parts.scheme != "https":
        raise DirectoryError(f"directory URL must be https: {signature_agent!r}")
    if not parts.hostname:
        raise DirectoryError(f"directory URL has no host: {signature_agent!r}")
    if parts.username or parts.password:
        raise DirectoryError("directory URL must not contain userinfo")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise DirectoryError("directory URL must be a bare origin (no path, query or fragment)")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise DirectoryError(f"invalid port in directory URL: {signature_agent!r}") from exc
    if port != 443:
        raise DirectoryError(f"directory URL must use port 443, got {port}")
    try:
        host = parts.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DirectoryError(f"invalid host in directory URL: {parts.hostname!r}") from exc
    addresses = tuple(_resolve_global_addresses(host))
    host_header = f"[{host}]" if ":" in host else host
    return DirectoryTarget(
        host=host,
        port=port,
        addresses=addresses,
        directory_url=f"https://{host_header}{spec.WELL_KNOWN_PATH}",
    )


def validate_directory_url(url: str) -> str:
    """Validate a Signature-Agent origin and return the directory URL to fetch."""
    return resolve_target(url).directory_url


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to an already-validated address."""

    def __init__(self, host: str, port: int, addresses: tuple[str, ...], *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._addresses = addresses

    def connect(self) -> None:
        deadline = time.monotonic() + self.timeout
        last_error: OSError | None = None
        for address in self._addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self.sock = socket.create_connection((address, self.port), remaining)
                break
            except OSError as exc:
                last_error = exc
        if self.sock is None:
            raise last_error or OSError(f"cannot connect to {self.host}")
        self.sock.settimeout(max(0.1, deadline - time.monotonic()))
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _parse_jwks(body: bytes) -> dict:
    if len(body) > spec.MAX_DIRECTORY_BYTES:
        raise DirectoryError("directory document exceeds size cap")
    try:
        jwks = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise DirectoryError(f"directory is not valid JSON: {exc}") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise DirectoryError("directory is not a JWK Set")
    return jwks


def fetch_target(target: DirectoryTarget, *, timeout: float = 10.0) -> dict:
    """Fetch and parse the directory for a validated target."""
    connection = _PinnedHTTPSConnection(
        target.host, target.port, target.addresses, timeout=timeout
    )
    host_header = f"[{target.host}]" if ":" in target.host else target.host
    try:
        connection.request(
            "GET",
            spec.WELL_KNOWN_PATH,
            headers={"Host": host_header, "Accept": "application/json", "User-Agent": _USER_AGENT},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise DirectoryError(f"directory fetch failed: HTTP {response.status}")
        body = response.read(spec.MAX_DIRECTORY_BYTES + 1)
    except DirectoryError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise DirectoryError(f"directory fetch failed: {exc}") from exc
    finally:
        connection.close()
    return _parse_jwks(body)


def fetch_directory(url: str, *, timeout: float = 10.0) -> dict:
    """Validate a Signature-Agent origin and fetch its key directory."""
    return fetch_target(resolve_target(url), timeout=timeout)


@dataclass(frozen=True)
class DirectoryCheck:
    directory_url: str
    key_found: bool
    keyids: tuple[str, ...]


def check_directory(signature_agent: str, keyid: str) -> DirectoryCheck:
    target = resolve_target(signature_agent)
    jwks = fetch_target(target)
    keyids = tuple(
        thumbprint for key in jwks["keys"] if (thumbprint := try_jwk_thumbprint(key)) is not None
    )
    return DirectoryCheck(
        directory_url=target.directory_url,
        key_found=keyid in keyids,
        keyids=keyids,
    )
