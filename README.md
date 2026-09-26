# wbactl

Static/CI toolkit for **Web Bot Auth** — the IETF profile of RFC 9421 that lets
agents and bots sign their HTTP requests (draft-ietf-webbotauth-httpsig-protocol-00).

Four jobs, all local-first, no server, no telemetry:

- **`check`** — agent-side doctor: why is my agent blocked? Compares unsigned vs
  signed request outcomes and validates your key directory setup.
- **`conformance`** — verifier test vectors: run the bundled accept/reject
  vectors against a verifier implementation (bundled reference verifier, an
  HTTP service, or a command).
- **`audit`** — passive adoption audit of public AI-access signals: robots.txt
  AI rules, AIPREF `Content-Usage`, `Content-Signal`, and WBA key directories.
- **`keygen` / `directory`** — generate an Ed25519 signing key and the JWKS
  directory document to host at the well-known path.

Status: early work in progress (pre-1.0, PyPI release pending).

Dataset: [State of Agent Access — 2026-09](research/2026-09-agent-access.md).

## Install

```sh
pip install "git+https://github.com/dtduc-git/wbactl"   # PyPI pending
```

Development:

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

# 4. Run conformance vectors against a verifier
uv run wbactl conformance                     # bundled reference verifier
uv run wbactl conformance --target-url http://localhost:8080/verify
uv run wbactl conformance --target-cmd "my-verifier --stdin"

# 5. Passively audit public AI-access signals
uv run wbactl audit --domains domains.txt --out audit-raw.jsonl --delay 1
```

### Conformance target contract

`--target-url` receives a POST with
`{"method","url","headers","now","keys"}` and must return
`{"accepted": true|false, "reason": "..."}`. `--target-cmd` gets the same JSON
on stdin and must print the same JSON on stdout (a non-zero exit is fine when a
verdict was printed).

The target MUST treat `now` as the current time and apply any max-age policy
against it; vectors use fixed timestamps and are otherwise unverifiable.

### Audit ethics

`audit` fetches only public metadata (robots.txt, response headers, the
well-known key directory) with a fixed delay and an honest User-Agent. It never
probes like an agent, never executes anything, and does not follow more than
three redirects. Never publish the raw JSONL: publish aggregates and
hand-validated examples of public metadata only.

## Spec revision

The supported draft revision is pinned in `src/wbactl/spec.py`
(`draft-ietf-webbotauth-httpsig-protocol-00`, 2026-09-01). Bump it deliberately
and update fixtures when the draft changes.

## Interop

- Known-answer tests against `cloudflare/web-bot-auth` reference output:
  legacy and structured signatures reproduce byte-for-byte (`tests/test_sign.py`).
- Cloudflare architecture vectors (vendored, Ed25519) verified in
  `tests/test_cloudflare_vectors.py`.
- Manual smoke (2026-09-25): legacy `wbactl`-signed requests are accepted by
  Cloudflare's live test deployment.
- Known upstream inconsistency (observed 2026-09-25, not yet confirmed
  upstream): that deployment rejects the RFC 9421 §2.1.2 Dictionary
  member-value structured signature that `cloudflare/web-bot-auth` itself
  produces; wbactl follows the RFC and the reference library.

## License

Apache-2.0
