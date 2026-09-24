"""wbactl check — agent-side Web Bot Auth doctor."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .directory import DirectoryError, check_directory
from .http import get
from .keys import jwk_thumbprint, load_private_key, public_jwk
from .sign import sign_request

USER_AGENT = f"wbactl/{__version__} (+https://github.com/dtduc-git/wbactl)"


@dataclass
class CheckReport:
    url: str
    unsigned: dict | None = None
    signed: dict | None = None
    directory: dict | None = None
    verdict: str = "inconclusive"
    findings: list[str] = field(default_factory=list)


def _probe(url: str, headers: dict[str, str]) -> dict:
    try:
        response = get(url, {"User-Agent": USER_AGENT, **headers})
    except (ConnectionError, ValueError) as exc:
        return {"error": str(exc)}
    return {"status": response.status, "reason": response.reason}


def _status(probe: dict | None) -> int | None:
    return probe.get("status") if probe else None


def run_check(url: str, key_path: Path | None, signature_agent: str | None) -> CheckReport:
    report = CheckReport(url=url)
    report.unsigned = _probe(url, {})

    if key_path is None or signature_agent is None:
        report.findings.append("--key and --signature-agent are required for the signed probe")
        report.verdict = "inconclusive"
        return report

    private_key = load_private_key(key_path)
    keyid = jwk_thumbprint(public_jwk(private_key.public_key()))
    report.signed = _probe(url, sign_request("GET", url, {}, private_key, signature_agent))

    key_missing = False
    try:
        directory = check_directory(signature_agent, keyid)
        report.directory = {
            "url": directory.directory_url,
            "key_found": directory.key_found,
            "keys": len(directory.keyids),
        }
        key_missing = not directory.key_found
        if key_missing:
            report.findings.append(
                f"directory {directory.directory_url} does not list keyid {keyid}"
            )
    except DirectoryError as exc:
        report.directory = {"error": str(exc)}
        report.findings.append(f"directory check failed: {exc}")

    unsigned_status = _status(report.unsigned)
    signed_status = _status(report.signed)

    if signed_status is None:
        report.verdict = "inconclusive"
        report.findings.append("signed probe did not complete; cannot compare outcomes")
    elif 200 <= signed_status < 300:
        if unsigned_status in (401, 403):
            report.verdict = "wba_accepted"
            report.findings.append(
                "signed request accepted while the unsigned probe was blocked: "
                "Web Bot Auth is being honored"
            )
        elif unsigned_status is None:
            report.verdict = "inconclusive"
            report.findings.append(
                "signed request accepted, but the unsigned probe failed; cannot compare outcomes"
            )
        else:
            report.verdict = "reachable"
            report.findings.append(
                f"signed request accepted; unsigned probe returned HTTP {unsigned_status}"
            )
    elif signed_status in (401, 403):
        report.verdict = "blocked"
        report.findings.extend(
            [
                f"origin rejected the signed request with HTTP {signed_status}",
                "likely causes: origin does not verify Web Bot Auth; Signature-Agent "
                "origin not allowlisted; draft revision mismatch",
            ]
        )
    elif signed_status == 402:
        report.verdict = "payment_required"
        report.findings.append("origin returned 402 Payment Required for the signed request")
    else:
        report.verdict = "inconclusive"
        report.findings.append(f"unexpected signed response HTTP {signed_status}")

    if key_missing and report.verdict != "wba_accepted":
        report.verdict = "setup_error"
    return report
