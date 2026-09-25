"""Passive audit of public AI-access signals.

Per domain, this fetches only public metadata: robots.txt (AI user-agent rules,
``Content-Usage`` directive, ``Content-Signal``), the homepage response headers,
and the well-known Web Bot Auth key directory. No agent-like probing, no
credentials, no execution. Raw per-domain reports are for private use; publish
aggregates only.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .http import get

USER_AGENT = f"wbactl-audit/{__version__} (+https://github.com/dtduc-git/wbactl)"
WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"
ROBOTS_MAX_BYTES = 512 * 1024  # RFC 9309 §2.4: parse at least 500 KiB
AI_USER_AGENT_TOKENS = (
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "google-extended",
    "ccbot",
    "bytespider",
    "amazonbot",
    "applebot-extended",
    "meta-externalagent",
    "facebookbot",
    "perplexitybot",
    "youbot",
    "cohere-ai",
    "diffbot",
    "omgili",
    "petalbot",
    "imagesiftbot",
)


@dataclass
class DomainReport:
    domain: str
    robots_status: int | None = None
    robots_error: str | None = None
    content_usage: list[str] = field(default_factory=list)
    content_signal: list[str] = field(default_factory=list)
    ai_disallow: bool = False
    homepage_status: int | None = None
    homepage_error: str | None = None
    directory_status: int | None = None
    directory_keys: int | None = None
    directory_error: str | None = None

    @property
    def reachable(self) -> bool:
        return self.robots_status is not None or self.homepage_status is not None


def load_domains(path: Path) -> list[str]:
    """Read one domain per line; tolerate URLs, comments and duplicates."""
    domains: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "//" in line:
            line = line.split("//", 1)[1]
        line = line.split("/", 1)[0].strip().lower()
        if not line or line in seen:
            continue
        seen.add(line)
        domains.append(line)
    if not domains:
        raise ValueError(f"{path}: no domains found")
    return domains


def parse_robots(text: str) -> dict:
    """Extract AI-user-agent disallows and Content-Usage/Content-Signal directives."""
    groups: list[tuple[list[str], list[tuple[str, str]]]] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []
    content_usage: list[str] = []
    content_signal: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "user-agent":
            if rules:
                groups.append((agents, rules))
                agents, rules = [], []
            agents.append(value.lower())
        elif name in ("disallow", "allow"):
            rules.append((name, value))
        elif name == "content-usage":
            content_usage.append(value)
        elif name == "content-signal":
            content_signal.append(value)
    if rules:
        groups.append((agents, rules))

    def blocks_everything(group_rules: list[tuple[str, str]]) -> bool:
        blocks = any(
            rule == "disallow" and value in ("/", "/*") for rule, value in group_rules
        )
        allowed = any(rule == "allow" and value == "/" for rule, value in group_rules)
        return blocks and not allowed

    ai_disallow = any(
        any(token in agent for agent in agents for token in AI_USER_AGENT_TOKENS)
        and blocks_everything(group_rules)
        for agents, group_rules in groups
    )
    return {
        "content_usage": content_usage,
        "content_signal": content_signal,
        "ai_disallow": ai_disallow,
    }


def audit_domain(
    domain: str, *, base_url: str | None = None, timeout: float = 15.0
) -> DomainReport:
    """Fetch public metadata for one domain. ``base_url`` is for tests."""
    report = DomainReport(domain=domain)
    base = base_url or f"https://{domain}"

    try:
        response = get(
            f"{base}/robots.txt",
            {"User-Agent": USER_AGENT},
            timeout=timeout,
            max_bytes=ROBOTS_MAX_BYTES,
            follow_redirects=True,
        )
        report.robots_status = response.status
        if response.status == 200:
            parsed = parse_robots(response.body.decode("utf-8-sig", "replace"))
            report.content_usage.extend(parsed["content_usage"])
            report.content_signal.extend(parsed["content_signal"])
            report.ai_disallow = parsed["ai_disallow"]
    except ConnectionError as exc:
        report.robots_error = str(exc)

    try:
        response = get(
            f"{base}/", {"User-Agent": USER_AGENT}, timeout=timeout, follow_redirects=True
        )
        report.homepage_status = response.status
        headers = {name.lower(): value for name, value in response.headers.items()}
        if "content-usage" in headers:
            report.content_usage.append(headers["content-usage"])
        if "content-signal" in headers:
            report.content_signal.append(headers["content-signal"])
    except ConnectionError as exc:
        report.homepage_error = str(exc)

    try:
        response = get(
            f"{base}{WELL_KNOWN_PATH}",
            {"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
            follow_redirects=True,
        )
        report.directory_status = response.status
        if response.status == 200:
            try:
                data = json.loads(response.body)
            except (ValueError, RecursionError):
                data = None
            if isinstance(data, dict) and isinstance(data.get("keys"), list):
                report.directory_keys = len(data["keys"])
            else:
                report.directory_keys = 0
    except ConnectionError as exc:
        report.directory_error = str(exc)
    return report


def _safe_audit(domain: str, timeout: float) -> DomainReport:
    """One broken domain must not kill a long audit run."""
    try:
        return audit_domain(domain, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - defensive: report and continue
        return DomainReport(domain, robots_error=f"unexpected error: {exc}")


def run_audit(
    domains: list[str],
    *,
    delay: float = 1.0,
    limit: int | None = None,
    timeout: float = 15.0,
    on_report: Callable[[DomainReport], None] | None = None,
) -> list[DomainReport]:
    """Audit domains politely: bounded list, fixed delay between domains."""
    selected = domains[:limit] if limit is not None else domains
    reports: list[DomainReport] = []
    for index, domain in enumerate(selected):
        if index and delay > 0:
            time.sleep(delay)
        report = _safe_audit(domain, timeout)
        if on_report is not None:
            on_report(report)
        reports.append(report)
    return reports


def summarize(reports: list[DomainReport]) -> dict:
    total = len(reports)
    reachable = sum(1 for report in reports if report.reachable)

    def pct(count: int) -> float:
        return round(100 * count / reachable, 1) if reachable else 0.0

    with_usage = sum(1 for report in reports if report.content_usage)
    with_signal = sum(1 for report in reports if report.content_signal)
    ai_disallow = sum(1 for report in reports if report.ai_disallow)
    directories = sum(
        1 for report in reports if report.directory_status == 200 and report.directory_keys
    )
    return {
        "domains": total,
        "reachable": reachable,
        "content_usage": with_usage,
        "content_usage_pct": pct(with_usage),
        "content_signal": with_signal,
        "content_signal_pct": pct(with_signal),
        "ai_disallow": ai_disallow,
        "ai_disallow_pct": pct(ai_disallow),
        "wba_directory": directories,
        "wba_directory_pct": pct(directories),
        "errors": sum(
            1
            for report in reports
            if report.robots_error or report.homepage_error or report.directory_error
        ),
    }
