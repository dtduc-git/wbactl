# State of Agent Access — 2026-09

A first aggregate snapshot of public AI-access signals, produced with
`wbactl audit`. Raw per-domain data is not published; this report contains only
aggregates and a few hand-validated examples of public metadata.

## Method

- **Tool**: `wbactl audit` (passive only).
- **Sample**: Tranco list **K9PXW** (created 2026-09-24).
  - Pass 1: top-100, unfiltered — 72 reachable.
  - Pass 2: top-500 after filtering infrastructure/CDN/DNS/ads domains with
    [`build_domains.py`](build_domains.py) (heuristic suffix+substring list),
    drawn from ranks 1–591 — 359 reachable. Input list:
    [`domains-top500-filtered.txt`](domains-top500-filtered.txt).
  - Parameters: pass 1 `--delay 1.0 --timeout 15` (commit `b86f279`); pass 2
    `--delay 0.5 --timeout 6` (commit `818242c`).
  - Aggregates: [`2026-09-summary-pass1.json`](2026-09-summary-pass1.json),
    [`2026-09-summary-pass2.json`](2026-09-summary-pass2.json); the refined
    crawler counts are in the `-refined.json` variants, produced with
    [`recompute_ai_disallow.py`](recompute_ai_disallow.py) (re-fetch +
    re-parse, refined token list in this commit).
- **Per domain** (3 GETs, honest User-Agent, ≤3 redirects):
  1. `/robots.txt` — AI user-agent groups, `Content-Usage`, `Content-Signal`.
  2. `/` — response headers `Content-Usage` / `Content-Signal`.
  3. `/.well-known/http-message-signatures-directory` — Web Bot Auth key directory.
- Percentages are over **reachable** domains (robots or homepage responded).

## Results

| Signal | Pass 1 (n=100, reachable 72) | Pass 2 (n=500, reachable 359) |
|---|---|---|
| AIPREF `Content-Usage` | 0 (0.0%) | **1 (0.3%)** |
| `Content-Signal` | 2 (2.8%) | **11 (3.1%)** |
| AI/training crawler disallowed (robots) | 11 (15.3%) | **64 (17.8%)** |
| Web Bot Auth key directory | 1 (1.4%) | **4 (1.1%)** |
| Homepages returning 403 to an honest UA | — | 45 (12.5%) |

Only domains that serve `robots.txt` can match the crawler row (pass 1: 60 of
72 reachable; pass 2: 298 of 359). The crawler numbers were re-parsed after
refining the token list (see Caveats); the plain summary JSONs are the raw run
outputs and still carry the earlier, broader counts.

## Hand-validated findings

### Web Bot Auth key directories (4)

- **chatgpt.com** — OpenAI publishes a JWKS with one Ed25519 key
  (`purpose: ai`, `signature_agent: https://chatgpt.com`).
- **forter.com** — Ed25519 key with `use: sig`, `nbf`/`exp`.
- **checkpoint.com** — Ed25519 key, `signature_agent: https://www.checkpoint.com`.
- One further site in the sample serves a JWKS containing the public RFC 9421
  test key (`test-key-ed25519`) and no metadata — likely a test deployment. We
  are not naming it: if a verifier trusted that directory, anyone could sign as
  that agent, because the key's private half is published in RFC 9421. That is
  the site's misconfiguration to fix, not ours to disclose.

### AIPREF `Content-Usage` (1)

- **launchpad.net** robots.txt: `Content-Usage: ai=n` (plus
  `Content-Signal: ai-train=no, search=yes, ai-input=no`) — the first real
  adoption of the new IETF vocabulary in the sample.

### `Content-Signal` (11)

- Opt-in (`ai-train=yes`): cloudflare.com, sentry.io, forter.com, avast.com,
  amplitude.com, nvidia.com.
- Opt-out (`ai-train=no`): linktr.ee, launchpad.net, weibo.com, hostinger.com,
  trendmicro.com.
- Cloudflare's own site sets it in `www.cloudflare.com/robots.txt` (the apex
  301s) — a probe that does not follow redirects would miss it.

### AI/training crawler blocking

Robots.txt groups disallowing AI/training user-agents (GPTBot, ClaudeBot,
CCBot, Bytespider, Google-Extended, …) include large platforms, news sites and
e-commerce: instagram, amazon, github, tiktok, chatgpt, yahoo, nytimes,
theguardian, bbc, reuters, washingtonpost, bloomberg and others. GitHub allows
a few paths and disallows the rest.

## Caveats

- **Errors**: pass 1: 29 domains with at least one probe error, 28 unreachable;
  pass 2: 147 with at least one error, 141 unreachable (DNS failures 88,
  timeouts 30, TLS errors 19, refused/reset 4). Filtering is heuristic; some
  CDN/API domains remain.
- **Vantage point**: one datacenter IP in one region. 403 responses (45
  homepages, 26 robots) are likely bot management, not deliberate AI policy.
- **Token list**: the crawler row counts 16 known AI/training user-agent tokens
  (list in `src/wbactl/audit.py`); a broader list that also included
  search/data crawlers (PetalBot, Omgili, FacebookBot, Diffbot) yielded 12 and
  69 for the two passes. The number is a lower bound on "AI-related blocking",
  not a precise taxonomy.
- **Re-fetch variance**: robots.txt content changes and rate limits mean a
  second run can differ by a few domains.
- Percentages over reachable are not comparable with reports that use a
  different denominator; pass 1 was unfiltered, pass 2 filtered.
- `Content-Usage` being ~0 is expected for a brand-new draft; the single hit
  was hand-validated.

## Next

- Re-run quarterly to track `Content-Usage` and key-directory adoption.
- Extend to top-1000+ with a varied vantage point.
