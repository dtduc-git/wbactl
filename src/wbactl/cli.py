"""wbactl command line interface."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, spec
from .check import run_check
from .conformance import run_conformance
from .keys import (
    generate_private_key,
    jwk_thumbprint,
    load_private_key,
    public_jwk,
    save_private_key,
)
from .vectors import VectorError, load_vectors

app = typer.Typer(
    no_args_is_help=True,
    help="Static/CI toolkit for Web Bot Auth (draft-00).",
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"wbactl {__version__} (spec: {spec.DRAFT})")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


@app.command()
def keygen(
    out: Path = typer.Option(Path("."), "--out", "-o", help="Directory for key files."),
    name: str = typer.Option("wba", "--name", help="File name prefix."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing key files."),
) -> None:
    """Generate an Ed25519 signing key and its JWKS directory document."""
    private_key = generate_private_key()
    key_path = out / f"{name}-private.pem"
    jwks_path = out / f"{name}-directory.json"
    jwks = {"keys": [public_jwk(private_key.public_key())]}
    try:
        out.mkdir(parents=True, exist_ok=True)
        save_private_key(private_key, key_path, force=force)
        jwks_path.write_text(json.dumps(jwks, indent=2) + "\n")
    except OSError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"private key: {key_path}")
    console.print(f"directory:   {jwks_path}  (host at {spec.WELL_KNOWN_PATH})")
    console.print(f"keyid:       {jwk_thumbprint(jwks['keys'][0])}")


@app.command()
def directory(
    key: Path = typer.Option(..., "--key", help="Ed25519 private key (PEM)."),
) -> None:
    """Print the JWKS directory document for a key."""
    try:
        jwks = {"keys": [public_jwk(load_private_key(key).public_key())]}
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print_json(json.dumps(jwks))


@app.command()
def check(
    url: str = typer.Option(..., "--url", help="URL to test as an agent."),
    key: Path | None = typer.Option(None, "--key", help="Ed25519 private key (PEM)."),
    signature_agent: str | None = typer.Option(
        None,
        "--signature-agent",
        help="Public origin of your key directory.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Diagnose why an agent request is blocked (unsigned vs signed)."""
    try:
        report = run_check(url, key, signature_agent)
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if as_json:
        console.print_json(json.dumps(asdict(report)))
    else:
        table = Table(title=f"wbactl check {url}")
        table.add_column("probe")
        table.add_column("result")
        for name, probe in (("unsigned", report.unsigned), ("signed", report.signed)):
            if probe is None:
                table.add_row(name, "skipped")
            elif "error" in probe:
                table.add_row(name, f"error: {probe['error']}")
            else:
                table.add_row(name, f"{probe['status']} {probe['reason']}")
        console.print(table)
        if report.directory is not None:
            console.print(f"directory: {json.dumps(report.directory)}")
        console.print(f"verdict: [bold]{report.verdict}[/bold]")
        for finding in report.findings:
            console.print(f"- {finding}")
    if report.verdict in {"wba_accepted", "reachable"}:
        return
    if report.verdict in {"inconclusive", "payment_required"}:
        raise typer.Exit(3)
    raise typer.Exit(1)


@app.command()
def conformance(
    vectors_path: Path | None = typer.Option(
        None, "--vectors", help="Vector file (default: bundled vectors)."
    ),
    target_url: str | None = typer.Option(
        None, "--target-url", help="Verifier service URL (POST JSON, returns JSON verdict)."
    ),
    target_cmd: str | None = typer.Option(
        None, "--target-cmd", help="Verifier command (JSON on stdin, JSON on stdout)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    strict_reason: bool = typer.Option(
        False,
        "--strict-reason",
        help="Also compare verifier reason codes (use for the bundled reference verifier).",
    ),
) -> None:
    """Run conformance vectors against a Web Bot Auth verifier."""
    if target_url is not None and target_cmd is not None:
        console.print("[red]error:[/red] use either --target-url or --target-cmd, not both")
        raise typer.Exit(1)
    try:
        vectors = load_vectors(vectors_path)
    except VectorError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc

    outcomes = run_conformance(
        vectors, target_url=target_url, target_cmd=target_cmd, strict_reason=strict_reason
    )
    passed = sum(1 for outcome in outcomes if outcome.passed)
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "total": len(outcomes),
                    "passed": passed,
                    "outcomes": [
                        {
                            "name": outcome.vector.name,
                            "expect": outcome.vector.expect,
                            "accepted": outcome.accepted,
                            "reason": outcome.reason,
                            "error": outcome.error,
                            "passed": outcome.passed,
                        }
                        for outcome in outcomes
                    ],
                }
            )
        )
    else:
        table = Table(title=f"wbactl conformance ({passed}/{len(outcomes)} passed)")
        table.add_column("vector")
        table.add_column("expect")
        table.add_column("result")
        table.add_column("detail")
        for outcome in outcomes:
            if outcome.error is not None:
                result, detail = "ERROR", outcome.error
            else:
                result = "PASS" if outcome.passed else "FAIL"
                detail = f"accepted={outcome.accepted} reason={outcome.reason}"
            table.add_row(outcome.vector.name, outcome.vector.expect, result, detail)
        console.print(table)
    if passed != len(outcomes):
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
