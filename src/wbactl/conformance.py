"""Run conformance vectors against a Web Bot Auth verifier target.

Targets:
- default (self): the bundled reference verifier.
- ``--target-url``: POST ``{"method","url","headers","now","keys"}`` as JSON,
  read ``{"accepted": bool, "reason": str?}``.
- ``--target-cmd``: same JSON on stdin, same JSON on stdout.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass

from .vectors import Vector, VectorSet
from .verify import verify_request


@dataclass
class Outcome:
    vector: Vector
    accepted: bool | None
    reason: str | None = None
    error: str | None = None
    strict_reason: bool = False

    @property
    def passed(self) -> bool:
        if self.accepted is None:
            return False
        if self.accepted != self.vector.expect_accept:
            return False
        if (
            self.strict_reason
            and self.vector.reason is not None
            and self.reason != self.vector.reason
        ):
            return False
        return True


def _payload(vector: Vector, keys: list[dict]) -> dict:
    return {
        "method": vector.method,
        "url": vector.url,
        "headers": vector.headers,
        "now": vector.now,
        "keys": vector.keys if vector.keys is not None else keys,
    }


def _target_self(vector: Vector, keys: list[dict]) -> Outcome:
    result = verify_request(
        vector.method,
        vector.url,
        vector.headers,
        {"keys": vector.keys if vector.keys is not None else keys},
        now=vector.now,
        max_age=None,
    )
    return Outcome(vector, result.ok, result.reason)


def _parse_verdict(vector: Vector, payload: bytes) -> Outcome:
    try:
        data = json.loads(payload)
    except (ValueError, RecursionError) as exc:
        return Outcome(vector, None, error=f"target returned non-JSON: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("accepted"), bool):
        return Outcome(vector, None, error='target JSON must be {"accepted": bool}')
    reason = data.get("reason")
    return Outcome(vector, data["accepted"], reason if isinstance(reason, str) else None)


def _target_url(vector: Vector, keys: list[dict], url: str) -> Outcome:
    body = json.dumps(_payload(vector, keys)).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return _parse_verdict(vector, response.read(64 * 1024))
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read(64 * 1024)
        except (OSError, http.client.HTTPException):
            payload = b""
        outcome = _parse_verdict(vector, payload)
        if outcome.accepted is not None:
            return outcome
        return Outcome(vector, None, error=f"target HTTP {exc.code}")
    except (OSError, ValueError, http.client.HTTPException, RecursionError) as exc:
        return Outcome(vector, None, error=f"target unreachable: {exc}")


def _target_cmd(vector: Vector, keys: list[dict], command: str) -> Outcome:
    try:
        completed = subprocess.run(
            command,
            shell=True,
            input=json.dumps(_payload(vector, keys)).encode(),
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return Outcome(vector, None, error=f"target command failed: {exc}")
    stdout = completed.stdout.decode("utf-8", "replace")
    outcome = _parse_verdict(vector, stdout.encode())
    if outcome.accepted is not None:
        return outcome
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        detail = stderr[0][:200] if stderr else ""
        return Outcome(vector, None, error=f"target command exit {completed.returncode}: {detail}")
    return outcome


def run_conformance(
    vectors: VectorSet,
    *,
    target_url: str | None = None,
    target_cmd: str | None = None,
    strict_reason: bool = False,
) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for vector in vectors.vectors:
        if target_url is not None:
            outcome = _target_url(vector, vectors.keys, target_url)
        elif target_cmd is not None:
            outcome = _target_cmd(vector, vectors.keys, target_cmd)
        else:
            outcome = _target_self(vector, vectors.keys)
        outcome.strict_reason = strict_reason
        outcomes.append(outcome)
    return outcomes
