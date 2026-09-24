# wbactl — agent notes

Local-first toolkit for Web Bot Auth (draft-00). No server execution, no telemetry.

- Spec revision is pinned in `src/wbactl/spec.py`; bump deliberately and update fixtures.
- Crypto primitives come from `cryptography`; we own only the Web Bot Auth profile
  (header construction, directory rules). No custom crypto.
- Verification changes require negative controls in tests (a rejection test that
  fails if the check stops rejecting).
- Run: `uv sync --all-groups && uv run ruff check . && uv run pytest`
- Keep `check` diagnostic-only: it probes the target URL at low volume and never
  writes to the target.
