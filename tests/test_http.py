"""HTTP helper behaviour: redirect policy and bounded reads."""

import http.server
import threading

from wbactl.http import get


class _Redirecting(http.server.BaseHTTPRequestHandler):
    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/old":
            self._redirect("/new")
            return
        if self.path.startswith("/r"):
            step = int(self.path[2:])
            self._redirect(f"/r{step + 1}" if step < 4 else "/ok")
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def _serve() -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirecting)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_redirects_not_followed_by_default() -> None:
    server, base = _serve()
    try:
        assert get(f"{base}/old").status == 302
    finally:
        server.shutdown()


def test_redirects_followed_when_requested() -> None:
    server, base = _serve()
    try:
        response = get(f"{base}/old", follow_redirects=True, allow_private=True)
    finally:
        server.shutdown()
    assert response.status == 200
    assert response.body == b"ok"


def test_redirect_chain_is_capped() -> None:
    server, base = _serve()
    try:
        # /r1 -> /r2 -> /r3 -> /r4 -> /ok is a fourth hop and must be refused.
        assert get(f"{base}/r1", follow_redirects=True, allow_private=True).status == 302
    finally:
        server.shutdown()


def test_redirect_to_private_address_blocked() -> None:
    server, base = _serve()
    try:
        # allow_private=False (the audit default) refuses loopback redirects.
        assert get(f"{base}/old", follow_redirects=True).status == 302
    finally:
        server.shutdown()
