"""Directory URL guards, JWKS parsing, SSRF rejection, and connection pinning."""

import ipaddress
import socket

import pytest

from wbactl import spec
from wbactl.directory import (
    DirectoryError,
    _is_global,
    _parse_jwks,
    _PinnedHTTPSConnection,
    resolve_target,
    validate_directory_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://user:pass@example.com",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://192.168.1.1",
        "https://[::1]",
        "https://[64:ff9b::a9fe:a9fe]",
    ],
)
def test_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(DirectoryError):
        validate_directory_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/foo",
        "https://example.com/?x=1",
        "https://example.com:8443",
        "https://example.com:99999",
    ],
)
def test_rejects_non_origin_urls(url: str) -> None:
    with pytest.raises(DirectoryError):
        resolve_target(url)


def test_rejects_non_global_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "wbactl.directory.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))],
    )
    with pytest.raises(DirectoryError, match="non-global"):
        resolve_target("https://example.com")


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.0.0.1", False),
        ("93.184.216.34", True),
        ("::ffff:127.0.0.1", False),
        ("64:ff9b::a9fe:a9fe", False),
        ("64:ff9b:1::7f00:1", False),
        ("64:ff9b:1::808:808", False),
        ("2002:7f00:1::", False),
        ("::7f00:1", False),
    ],
)
def test_is_global(address: str, expected: bool) -> None:
    assert _is_global(ipaddress.ip_address(address)) is expected


def test_idna_host_is_encoded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "wbactl.directory._resolve_global_addresses", lambda host: ["93.184.216.34"]
    )
    target = resolve_target("https://例え.jp")
    assert target.host == "例え.jp".encode("idna").decode()


def test_builds_well_known_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "wbactl.directory._resolve_global_addresses", lambda host: ["93.184.216.34"]
    )
    assert (
        validate_directory_url("https://example.com")
        == "https://example.com/.well-known/http-message-signatures-directory"
    )


def test_resolves_once_and_pins_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved: list[str] = []

    def fake_getaddrinfo(host: str, port: int, proto: int | None = None):
        resolved.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("wbactl.directory.socket.getaddrinfo", fake_getaddrinfo)
    target = resolve_target("https://example.com")
    assert resolved == ["example.com"]

    connected: list[tuple[str, int]] = []

    class FakeSocket:
        def settimeout(self, value: float) -> None:
            pass

    def fake_create_connection(address: tuple[str, int], timeout: float) -> FakeSocket:
        connected.append(address)
        return FakeSocket()

    class FakeContext:
        def wrap_socket(self, sock: FakeSocket, server_hostname: str) -> FakeSocket:
            assert server_hostname == "example.com"
            return sock

    monkeypatch.setattr("wbactl.directory.socket.create_connection", fake_create_connection)
    connection = _PinnedHTTPSConnection("example.com", 443, target.addresses, timeout=5)
    connection._context = FakeContext()
    connection.connect()
    assert connected == [("93.184.216.34", 443)]


def test_parse_jwks_rejects_oversize() -> None:
    with pytest.raises(DirectoryError):
        _parse_jwks(b"{" + b" " * spec.MAX_DIRECTORY_BYTES)


def test_parse_jwks_rejects_bad_json() -> None:
    with pytest.raises(DirectoryError):
        _parse_jwks(b"not json")


def test_parse_jwks_rejects_invalid_utf8() -> None:
    with pytest.raises(DirectoryError):
        _parse_jwks(b"\xff\xfe\x00")


def test_parse_jwks_rejects_non_jwks() -> None:
    with pytest.raises(DirectoryError):
        _parse_jwks(b'{"keys": "nope"}')
