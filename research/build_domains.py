#!/usr/bin/env python3
"""Build a filtered domain list from the Tranco top-1m CSV.

Excludes infrastructure, CDN, DNS and ad/analytics domains that do not serve
websites, so the audit sample is registrable sites. Usage:

    python3 build_domains.py <tranco-top-1m.csv> <count> <out.txt>
"""

from __future__ import annotations

import sys
from pathlib import Path

# Suffix matches: the domain itself or any parent domain.
EXCLUDE_SUFFIXES = (
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "ggpht.com",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "gvt1.com",
    "gvt2.com",
    "akamai.net",
    "akamaiedge.net",
    "akadns.net",
    "akamaihd.net",
    "akamaitechnologies.com",
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "edgekey.net",
    "edgesuite.net",
    "fbcdn.net",
    "cdninstagram.com",
    "fbsbx.com",
    "aaplimg.com",
    "apple-dns.net",
    "microsoftonline.com",
    "office.net",
    "domaincontrol.com",
    "gtld-servers.net",
    "akamaitechnologies.com",
    "edgecastcdn.net",
    "hwcdn.net",
    "cdn77.org",
    "bunnycdn.com",
    "cachefly.net",
    "stackpathdns.com",
    "cloudflare.net",
    "cloudflare-dns.com",
    "verisign.net",
    "akamai.com",
    "scorecardresearch.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "adsrvr.org",
    "adnxs.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
)

# Substring heuristics for CDN / DNS / ads infrastructure.
EXCLUDE_SUBSTRINGS = (
    "cdn",
    "akamai",
    "cloudfront",
    "fastly",
    "gstatic",
    "googleapis",
    "googleusercontent",
    "googlevideo",
    "fbcdn",
    "aaplimg",
    "gtld-servers",
    "domaincontrol",
    "doubleclick",
    "adservice",
    "adsystem",
    "scorecardresearch",
    "trafficmanager",
    "tagmanager",
    "amazonaws",
    "azurewebsites",
    "windows.net",
    "app-measurement",
    "dns",
)


def is_excluded(domain: str) -> bool:
    for suffix in EXCLUDE_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return any(token in domain for token in EXCLUDE_SUBSTRINGS)


def main() -> None:
    csv_path, count, out_path = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
    selected: list[str] = []
    for line in csv_path.read_text().splitlines():
        _, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if not domain or is_excluded(domain):
            continue
        selected.append(domain)
        if len(selected) >= count:
            break
    out_path.write_text("\n".join(selected) + "\n")
    print(f"wrote {len(selected)} domains to {out_path}")


if __name__ == "__main__":
    main()
