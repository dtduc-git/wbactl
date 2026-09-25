"""Bounded HTTP GET used by diagnostics (redirects off by default, size-capped)."""

from __future__ import annotations

import http.client
import ipaddress
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class Response:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _LimitedRedirects(HTTPRedirectHandler):
    """Follow at most three redirects; http/https only, no literal non-global IPs."""

    max_redirections = 3

    def __init__(self, allow_private: bool = False):
        super().__init__()
        self._allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = urljoin(req.full_url, newurl)
        parts = urlsplit(newurl)
        if parts.scheme not in ("http", "https"):
            return None
        try:
            address = ipaddress.ip_address(parts.hostname or "")
        except ValueError:
            address = None
        if address is not None and not self._allow_private and not address.is_global:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def get(
    url: str,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 15.0,
    max_bytes: int = 64 * 1024,
    follow_redirects: bool = False,
    allow_private: bool = False,
) -> Response:
    """GET a URL. HTTP error statuses are returned as responses, not raised."""
    if follow_redirects:
        opener = build_opener(_LimitedRedirects(allow_private=allow_private))
    else:
        opener = build_opener(_NoRedirects)
    request = Request(url, headers=headers or {})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)[:max_bytes]
            return Response(response.status, response.reason, dict(response.headers), body)
    except HTTPError as exc:
        try:
            body = exc.read(max_bytes + 1)[:max_bytes]
        except (OSError, http.client.HTTPException):
            body = b""
        return Response(exc.code, exc.reason, dict(exc.headers or {}), body)
    except (OSError, http.client.HTTPException) as exc:
        raise ConnectionError(str(exc)) from exc
