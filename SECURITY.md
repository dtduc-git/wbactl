# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security
Advisories ("Report a vulnerability" on the Security tab) instead of a public
issue.

Include the affected version or commit, a reproduction, and the impact you
believe it has. We aim to acknowledge reports within 72 hours.

## Scope notes

- Signature verification bypasses (accepting a request that should be rejected)
  are security issues.
- The bundled keys under `tests/data/` and in `tests/test_sign.py` are published
  test material from `cloudflare/web-bot-auth` and RFC 9421, not secrets.
- `wbactl` never executes remote code; `check`/`audit` only issue the documented
  GET probes.
