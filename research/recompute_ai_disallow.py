#!/usr/bin/env python3
"""Re-parse the AI-crawler count from a re-fetch with the refined token list.

The raw audit JSONL stores only an ``ai_disallow`` flag, so the refined count
requires re-fetching robots.txt for the domains that served it. Usage:

    python3 recompute_ai_disallow.py <raw.jsonl> [delay]

Writes nothing; prints the count and the matching domains.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from wbactl.audit import ROBOTS_MAX_BYTES, USER_AGENT, parse_robots
from wbactl.http import get


def main() -> None:
    raw_path = Path(sys.argv[1])
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    rows = [json.loads(line) for line in raw_path.read_text().splitlines()]
    targets = [row["domain"] for row in rows if row["robots_status"] == 200]
    print(f"re-fetching {len(targets)} robots.txt files")

    hits: list[str] = []
    for index, domain in enumerate(targets):
        if index:
            time.sleep(delay)
        try:
            response = get(
                f"https://{domain}/robots.txt",
                {"User-Agent": USER_AGENT},
                timeout=6,
                max_bytes=ROBOTS_MAX_BYTES,
                follow_redirects=True,
            )
            if response.status != 200:
                continue
            parsed = parse_robots(response.body.decode("utf-8-sig", "replace"))
            if parsed["ai_disallow"]:
                hits.append(domain)
        except ConnectionError:
            continue
    print(f"ai_disallow: {len(hits)}/{len(targets)} robots-serving domains")
    print(json.dumps(hits))


if __name__ == "__main__":
    main()
