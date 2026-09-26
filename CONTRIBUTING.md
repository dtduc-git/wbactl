# Contributing

Thanks for considering a contribution. This project is small and review-heavy.

## Development

```sh
uv sync --all-groups
uv run ruff check .
uv run pytest
```

## Ground rules

- The supported spec revision is pinned in `src/wbactl/spec.py`; bump it
  deliberately and update fixtures in the same commit.
- Verification changes need a negative control: a test that fails if the check
  stops rejecting.
- No custom crypto: use `cryptography` primitives plus RFC 9421 construction.
- Keep it local-first: no telemetry, no server execution, no network calls
  outside the documented probes (`check`, `conformance` targets, `audit`).
- Open an issue before large changes so we can agree on scope.

## Reporting bugs

Include the command you ran, the observed output, and the spec section (or
reference implementation) you expected it to follow.
