# wbactl

Static/CI toolkit for **Web Bot Auth** — the IETF profile of RFC 9421 that lets
agents and bots sign their HTTP requests (draft-ietf-webbotauth-httpsig-protocol-00).

Three jobs, all local-first, no server, no telemetry:

- **`check`** — agent-side doctor: why is my agent blocked? Compares unsigned vs
  signed request outcomes and validates your key directory setup.
- **`conformance`** — verifier test vectors: prove an implementation rejects
  what the spec says to reject. *(P1)*
- **`audit`** — passive adoption audit of public AI-access signals
  (robots.txt AI rules, `Content-Usage`, key directories). *(P1)*

Status: early work in progress. P0 is `keygen` + `directory` + `check`.

## Install (dev)

```sh
uv sync --all-groups
uv run wbactl --help
```

## Quickstart

```sh
# 1. Generate a signing key and the JWKS directory document
uv run wbactl keygen --out ./wba

# 2. Host ./wba/wba-directory.json at
#    https://your-domain.example/.well-known/http-message-signatures-directory

# 3. Diagnose a URL as an agent
uv run wbactl check \
  --url https://example.com/some/page \
  --key ./wba/wba-private.pem \
  --signature-agent https://your-domain.example
```

## Spec revision

The supported draft revision is pinned in `src/wbactl/spec.py`
(`draft-ietf-webbotauth-httpsig-protocol-00`, 2026-09-01). Bump it deliberately
and update fixtures when the draft changes.

## Interop

- Known-answer test against `cloudflare/web-bot-auth` reference output
  (`tests/test_sign.py`, generated with `web-bot-auth@0.2.0`).
- Manual smoke: a `wbactl`-signed request is accepted by Cloudflare's live test
  deployment ("You successfully authenticated as owning the test public key").

## License

Apache-2.0
