"""Bounded HTTP GET used by diagnostics (no redirects, size-capped)."""

from __future__ import annotations

import http.client
from dataclasses import dataclass
from urllib.error import HTTPError
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


def get(
    url: str,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 15.0,
    max_bytes: int = 64 * 1024,
) -> Response:
    """GET a URL. HTTP error statuses are returned as responses, not raised."""
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
