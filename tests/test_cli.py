"""CLI smoke tests, keygen safety, and check verdict branches."""

import http.server
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wbactl.check import run_check
from wbactl.cli import app
from wbactl.directory import DirectoryCheck
from wbactl.keys import generate_private_key, save_private_key

runner = CliRunner()


class _Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        status = 200 if self.headers.get("Signature") else 403
        self.send_response(status)
        self.end_headers()
        self.wfile.write(b"ok" if status == 200 else b"blocked")

    def log_message(self, *args: object) -> None:
        pass


def _serve() -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def test_keygen_and_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["keygen", "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "wba-private.pem").exists()
    assert (tmp_path / "wba-directory.json").exists()

    result = runner.invoke(app, ["directory", "--key", str(tmp_path / "wba-private.pem")])
    assert result.exit_code == 0, result.output
    assert "OKP" in result.output
    assert "Ed25519" in result.output


def test_keygen_refuses_overwrite(tmp_path: Path) -> None:
    assert runner.invoke(app, ["keygen", "--out", str(tmp_path)]).exit_code == 0
    second = runner.invoke(app, ["keygen", "--out", str(tmp_path)])
    assert second.exit_code == 1
    assert isinstance(second.exception, SystemExit)
    assert runner.invoke(app, ["keygen", "--out", str(tmp_path), "--force"]).exit_code == 0


def test_check_against_local_origin(tmp_path: Path) -> None:
    result = runner.invoke(app, ["keygen", "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output

    server, url = _serve()
    try:
        report = run_check(url, tmp_path / "wba-private.pem", "https://127.0.0.1")
    finally:
        server.shutdown()

    assert report.unsigned is not None and report.unsigned["status"] == 403
    assert report.signed is not None and report.signed["status"] == 200
    # Probe evidence wins; the SSRF-guarded directory check only adds a finding.
    assert report.verdict == "wba_accepted"
    assert any("directory" in finding for finding in report.findings)


def _install_probe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    unsigned: int | None,
    signed: int | None,
    directory_ok: bool = True,
) -> None:
    def fake_probe(url: str, headers: dict[str, str]) -> dict:
        status = signed if "Signature" in headers else unsigned
        if status is None:
            return {"error": "connection failed"}
        return {"status": status, "reason": "fake"}

    monkeypatch.setattr("wbactl.check._probe", fake_probe)
    monkeypatch.setattr(
        "wbactl.check.check_directory",
        lambda agent, keyid: DirectoryCheck(
            "https://agent.example/.well-known/http-message-signatures-directory",
            directory_ok,
            (keyid,),
        ),
    )


def _run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, unsigned: int | None, signed: int | None
):
    key_path = tmp_path / "key.pem"
    save_private_key(generate_private_key(), key_path)
    _install_probe(monkeypatch, unsigned=unsigned, signed=signed)
    return run_check("https://origin.example/page", key_path, "https://agent.example")


@pytest.mark.parametrize(
    ("unsigned", "signed", "verdict"),
    [
        (403, 200, "wba_accepted"),
        (200, 200, "reachable"),
        (503, 200, "reachable"),
        (403, 403, "blocked"),
        (None, 403, "blocked"),
        (403, 402, "payment_required"),
        (None, 200, "inconclusive"),
        (403, 302, "inconclusive"),
    ],
)
def test_check_verdicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsigned: int | None,
    signed: int | None,
    verdict: str,
) -> None:
    report = _run(tmp_path, monkeypatch, unsigned=unsigned, signed=signed)
    assert report.verdict == verdict


def test_check_setup_error_when_key_missing_from_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "key.pem"
    save_private_key(generate_private_key(), key_path)
    _install_probe(monkeypatch, unsigned=403, signed=403, directory_ok=False)
    report = run_check("https://origin.example/page", key_path, "https://agent.example")
    assert report.verdict == "setup_error"


def test_wba_accepted_not_overridden_by_directory_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "key.pem"
    save_private_key(generate_private_key(), key_path)
    _install_probe(monkeypatch, unsigned=403, signed=200, directory_ok=False)
    report = run_check("https://origin.example/page", key_path, "https://agent.example")
    assert report.verdict == "wba_accepted"


def _invoke_check(tmp_path: Path) -> int:
    result = runner.invoke(
        app,
        [
            "check",
            "--url",
            "https://origin.example",
            "--key",
            str(tmp_path / "key.pem"),
            "--signature-agent",
            "https://agent.example",
        ],
    )
    return result.exit_code


def test_check_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_path = tmp_path / "key.pem"
    save_private_key(generate_private_key(), key_path)

    _install_probe(monkeypatch, unsigned=403, signed=200)
    assert _invoke_check(tmp_path) == 0

    _install_probe(monkeypatch, unsigned=403, signed=403)
    assert _invoke_check(tmp_path) == 1

    _install_probe(monkeypatch, unsigned=403, signed=402)
    assert _invoke_check(tmp_path) == 3
