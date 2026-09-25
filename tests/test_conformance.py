"""Conformance runner: self target, URL target, command target, vector loading."""

import http.server
import json
import sys
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wbactl.cli import app
from wbactl.conformance import run_conformance
from wbactl.vectors import VectorError, load_vectors
from wbactl.verify import verify_request

runner = CliRunner()
DUMMY_KEY = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}


def test_bundled_vectors_pass_self_strict() -> None:
    outcomes = run_conformance(load_vectors(), strict_reason=True)
    assert outcomes
    failed = [outcome.vector.name for outcome in outcomes if not outcome.passed]
    assert not failed, failed


class _Verifier(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        result = verify_request(
            payload["method"],
            payload["url"],
            payload["headers"],
            {"keys": payload["keys"]},
            now=payload.get("now"),
            max_age=None,
        )
        body = json.dumps({"accepted": result.ok, "reason": result.reason}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class _Boom(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.send_response(500)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


def _serve(
    handler: type[http.server.BaseHTTPRequestHandler],
) -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def test_url_target_roundtrip() -> None:
    server, url = _serve(_Verifier)
    try:
        outcomes = run_conformance(load_vectors(), target_url=url, strict_reason=True)
    finally:
        server.shutdown()
    failed = [outcome.vector.name for outcome in outcomes if not outcome.passed]
    assert not failed, failed


def test_url_target_5xx_is_error() -> None:
    server, url = _serve(_Boom)
    try:
        outcomes = run_conformance(load_vectors(), target_url=url)
    finally:
        server.shutdown()
    assert all(outcome.accepted is None and outcome.error for outcome in outcomes)


def test_cmd_target_mismatch_detected() -> None:
    command = (
        f'{sys.executable} -c "import json,sys; json.load(sys.stdin); '
        "print(json.dumps({'accepted': True}))\""
    )
    outcomes = run_conformance(load_vectors(), target_cmd=command)
    failed = [outcome for outcome in outcomes if not outcome.passed]
    assert failed
    assert all(outcome.accepted is True for outcome in failed)


def test_cmd_target_rejecting_everything_fails_accept_vectors() -> None:
    command = (
        f'{sys.executable} -c "import json,sys; json.load(sys.stdin); '
        "print(json.dumps({'accepted': False}))\""
    )
    outcomes = run_conformance(load_vectors(), target_cmd=command)
    failed = {outcome.vector.name for outcome in outcomes if not outcome.passed}
    assert failed == {"accept-legacy", "accept-structured", "accept-no-agent"}


def test_cmd_target_bad_json_is_error() -> None:
    command = f"{sys.executable} -c \"import sys; sys.stdin.read(); print('nope')\""
    outcomes = run_conformance(load_vectors(), target_cmd=command)
    assert all(outcome.accepted is None and outcome.error for outcome in outcomes)


def test_strict_reason_mismatch(tmp_path: Path) -> None:
    base = load_vectors()
    reject = next(vector for vector in base.vectors if vector.expect == "reject")
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            {
                "keys": base.keys,
                "vectors": [
                    {
                        "name": "wrong-reason",
                        "method": reject.method,
                        "url": reject.url,
                        "headers": reject.headers,
                        "expect": "reject",
                        "reason": "definitely_not_the_reason",
                        "now": reject.now,
                    }
                ],
            }
        )
    )
    vectors = load_vectors(path)
    assert not run_conformance(vectors, strict_reason=True)[0].passed
    assert run_conformance(vectors)[0].passed


def test_cmd_target_nonzero_exit_with_verdict() -> None:
    command = (
        f'{sys.executable} -c "import json,sys; json.load(sys.stdin); '
        "print(json.dumps({'accepted': True})); sys.exit(1)\""
    )
    outcomes = run_conformance(load_vectors(), target_cmd=command)
    assert all(outcome.accepted is True for outcome in outcomes)


class _Rejecting(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = json.dumps({"accepted": False, "reason": "nope"}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def test_url_target_4xx_with_verdict() -> None:
    server, url = _serve(_Rejecting)
    try:
        outcomes = run_conformance(load_vectors(), target_url=url)
    finally:
        server.shutdown()
    assert all(outcome.accepted is False for outcome in outcomes)


def test_malformed_vector_file(tmp_path: Path) -> None:
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps({"vectors": [{"name": "x"}]}))
    with pytest.raises(VectorError):
        load_vectors(path)


@pytest.mark.parametrize(
    "data",
    [
        {"keys": [DUMMY_KEY], "vectors": []},
        {
            "keys": [DUMMY_KEY],
            "vectors": [
                {
                    "name": "a",
                    "method": "GET",
                    "url": "https://x",
                    "headers": {},
                    "expect": "accept",
                },
                {
                    "name": "a",
                    "method": "GET",
                    "url": "https://x",
                    "headers": {},
                    "expect": "accept",
                },
            ],
        },
        {
            "keys": [DUMMY_KEY],
            "vectors": [
                {
                    "name": "a",
                    "method": "GET",
                    "url": "https://x",
                    "headers": {},
                    "expect": "accept",
                    "now": "1",
                }
            ],
        },
        {
            "keys": [DUMMY_KEY],
            "vectors": [
                {
                    "name": "a",
                    "method": "GET",
                    "url": "https://x",
                    "headers": {"Signature": 1},
                    "expect": "accept",
                }
            ],
        },
    ],
)
def test_vector_validation(tmp_path: Path, data: dict) -> None:
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps(data))
    with pytest.raises(VectorError):
        load_vectors(path)


def test_cli_conformance_self() -> None:
    result = runner.invoke(app, ["conformance"])
    assert result.exit_code == 0, result.output


def test_cli_conformance_conflicting_targets() -> None:
    result = runner.invoke(
        app, ["conformance", "--target-url", "http://x", "--target-cmd", "y"]
    )
    assert result.exit_code == 1
