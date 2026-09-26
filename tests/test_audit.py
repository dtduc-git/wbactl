"""Audit parsing, domain loading, and a local end-to-end probe."""

import http.server
import json
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wbactl.audit import DomainReport, audit_domain, load_domains, parse_robots, summarize
from wbactl.cli import app

runner = CliRunner()

ROBOTS = """# comment
User-agent: GPTBot
Disallow: /

User-agent: *
Disallow: /private
Content-Usage: train-ai=n
Content-Signal: search=yes, ai-train=no
"""


def test_parse_robots() -> None:
    parsed = parse_robots(ROBOTS)
    assert parsed["ai_disallow"] is True
    assert parsed["content_usage"] == ["train-ai=n"]
    assert parsed["content_signal"] == ["search=yes, ai-train=no"]


@pytest.mark.parametrize(
    ("robots", "expected"),
    [
        ("User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n", True),
        ("User-agent: *\nUser-agent: GPTBot\nDisallow: /\n", True),
        ("User-agent: GPTBot\nDisallow: /*\n", True),
        ("User-agent: GPTBot\nAllow: /\nDisallow: /\n", False),
        ("User-agent: *\nDisallow: /private\n", False),
        ("User-agent: GPTBot\n\nUser-agent: *\nDisallow: /x\n", False),
    ],
)
def test_parse_robots_groups(robots: str, expected: bool) -> None:
    assert parse_robots(robots)["ai_disallow"] is expected


def test_load_domains(tmp_path: Path) -> None:
    path = tmp_path / "domains.txt"
    path.write_text("# top\nexample.com\nhttps://www.example.org/path\nexample.com\n\n")
    assert load_domains(path) == ["example.com", "www.example.org"]


def test_load_domains_empty(tmp_path: Path) -> None:
    path = tmp_path / "domains.txt"
    path.write_text("\n# only comments\n")
    with pytest.raises(ValueError):
        load_domains(path)


class _Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/robots.txt":
            body = ROBOTS.encode()
            self.send_response(200)
        elif self.path == "/.well-known/http-message-signatures-directory":
            body = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]}).encode()
            self.send_response(200)
        else:
            body = b"<html></html>"
            self.send_response(200)
            self.send_header("Content-Signal", "search=no")
            self.send_header("Content-Usage", "train-ai=y")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class _BomSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/robots.txt":
            body = b"\xef\xbb\xbfUser-agent: GPTBot\nDisallow: /\n"
            self.send_response(200)
        else:
            body = b""
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def _serve(
    handler: type[http.server.BaseHTTPRequestHandler],
) -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_audit_domain_local() -> None:
    server, base = _serve(_Site)
    try:
        report = audit_domain("127.0.0.1", base_url=base)
    finally:
        server.shutdown()
    assert report.robots_status == 200
    assert report.ai_disallow is True
    assert "train-ai=n" in report.content_usage  # robots directive
    assert "train-ai=y" in report.content_usage  # homepage header
    assert report.homepage_status == 200
    assert any("search=no" in value for value in report.content_signal)  # homepage header
    assert report.directory_status == 200
    assert report.directory_keys == 1
    assert report.reachable is True


def test_audit_domain_strips_bom() -> None:
    server, base = _serve(_BomSite)
    try:
        report = audit_domain("127.0.0.1", base_url=base)
    finally:
        server.shutdown()
    assert report.ai_disallow is True


def test_summarize() -> None:
    reports = [
        DomainReport(
            "a",
            robots_status=200,
            content_usage=["train-ai=n"],
            ai_disallow=True,
            directory_status=200,
            directory_keys=2,
        ),
        DomainReport("b", robots_status=404),
        DomainReport("c", robots_error="boom", content_signal=["search=yes"]),
    ]
    summary = summarize(reports)
    assert summary["domains"] == 3
    assert summary["reachable"] == 2
    assert summary["content_usage"] == 1
    assert summary["content_usage_pct"] == 50.0
    assert summary["content_signal"] == 1
    assert summary["ai_disallow"] == 1
    assert summary["wba_directory"] == 1
    assert summary["errors"] == 1


def test_cli_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    probed: list[str] = []

    def fake_audit(domain: str, **kwargs: object) -> DomainReport:
        probed.append(domain)
        return DomainReport(domain, robots_status=200, content_usage=["train-ai=n"])

    monkeypatch.setattr("wbactl.audit.audit_domain", fake_audit)
    domains = tmp_path / "domains.txt"
    domains.write_text("example.com\nsecond.example\n")
    out = tmp_path / "raw.jsonl"
    result = runner.invoke(
        app, ["audit", "--domains", str(domains), "--out", str(out), "--delay", "0"]
    )
    assert result.exit_code == 0, result.output
    assert "example.com" in out.read_text()
    assert "Content-Usage" in result.output
    assert probed == ["example.com", "second.example"]


def test_cli_audit_timeout_passed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(domains: list[str], **kwargs: object) -> list[DomainReport]:
        captured.update(kwargs)
        return [DomainReport(domains[0], robots_status=200)]

    monkeypatch.setattr("wbactl.cli.run_audit", fake_run)
    domains = tmp_path / "domains.txt"
    domains.write_text("example.com\n")
    result = runner.invoke(
        app, ["audit", "--domains", str(domains), "--timeout", "7", "--delay", "0"]
    )
    assert result.exit_code == 0, result.output
    assert captured["timeout"] == 7.0


def test_cli_audit_json_and_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    probed: list[str] = []

    def fake_audit(domain: str, **kwargs: object) -> DomainReport:
        probed.append(domain)
        return DomainReport(domain, robots_status=200)

    monkeypatch.setattr("wbactl.audit.audit_domain", fake_audit)
    domains = tmp_path / "domains.txt"
    domains.write_text("example.com\nsecond.example\n")
    result = runner.invoke(
        app, ["audit", "--domains", str(domains), "--json", "--limit", "1", "--delay", "0"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["domains"] == 1
    assert probed == ["example.com"]
