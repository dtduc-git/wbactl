"""Conformance vector loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import spec

DEFAULT_VECTORS = Path(__file__).parent / "vectors" / "wbactl.json"


class VectorError(Exception):
    """Vector file is missing or malformed."""


@dataclass(frozen=True)
class Vector:
    name: str
    method: str
    url: str
    headers: dict[str, str]
    expect: str
    now: int | None = None
    reason: str | None = None
    note: str | None = None
    keys: list[dict] | None = None

    @property
    def expect_accept(self) -> bool:
        return self.expect == "accept"


@dataclass(frozen=True)
class VectorSet:
    spec: str
    keys: list[dict]
    vectors: tuple[Vector, ...]


def _require_string(raw: dict, field: str, path: Path) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value:
        raise VectorError(f"{path}: vector {raw.get('name')!r}: {field} must be a non-empty string")
    return value


def _optional_int(raw: dict, field: str, path: Path) -> int | None:
    value = raw.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"{path}: vector {raw.get('name')!r}: {field} must be an integer")
    return value


def load_vectors(path: Path | None = None) -> VectorSet:
    path = DEFAULT_VECTORS if path is None else path
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise VectorError(f"cannot read vectors {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vectors"), list):
        raise VectorError(f"{path}: not a vector file")
    keys = data.get("keys", [])
    if not isinstance(keys, list) or not keys:
        raise VectorError(f"{path}: keys must be a non-empty list")
    if not data["vectors"]:
        raise VectorError(f"{path}: vector list is empty")

    vectors: list[Vector] = []
    names: set[str] = set()
    for raw in data["vectors"]:
        if not isinstance(raw, dict):
            raise VectorError(f"{path}: malformed vector: {raw!r}")
        name = _require_string(raw, "name", path)
        if name in names:
            raise VectorError(f"{path}: duplicate vector name {name!r}")
        names.add(name)
        expect = raw.get("expect")
        if expect not in ("accept", "reject"):
            raise VectorError(f"{path}: vector {name!r}: bad expect {expect!r}")
        headers = raw.get("headers", {})
        if not isinstance(headers, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
        ):
            raise VectorError(f"{path}: vector {name!r}: headers must map strings to strings")
        vector_keys = raw.get("keys")
        if vector_keys is not None and not isinstance(vector_keys, list):
            raise VectorError(f"{path}: vector {name!r}: keys must be a list")
        reason = raw.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise VectorError(f"{path}: vector {name!r}: reason must be a string")
        vectors.append(
            Vector(
                name=name,
                method=_require_string(raw, "method", path),
                url=_require_string(raw, "url", path),
                headers=dict(headers),
                expect=expect,
                now=_optional_int(raw, "now", path),
                reason=reason,
                note=raw.get("note"),
                keys=vector_keys,
            )
        )
    return VectorSet(spec=data.get("spec", spec.DRAFT), keys=keys, vectors=tuple(vectors))
