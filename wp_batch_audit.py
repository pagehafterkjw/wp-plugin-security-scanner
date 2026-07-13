#!/usr/bin/env python3
"""
Batch deep-audit: download each (slug, version) and run the function-body
unauth-audit. Print only plugins that have at least one flagged handler
(no permission guard + user input + raw sql in the handler body).

Reads a JSON array of {slug, version, ...} on stdin (the discover script output).
"""

import json
import os
import sys
import tempfile
import zipfile
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_unauth_audit as audit

DOWNLOAD = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Batch deep-audit plugins for unauth SQLi/XSS")
    ap.add_argument("--xss", action="store_true", help="flag XSS candidates instead of (default) sqli")
    args = ap.parse_args()

    data = json.load(sys.stdin)
    flagged = []
    scanned = 0
    sink_key = "xss_interesting" if args.xss else "interesting"
    for entry in data:
        slug = entry.get("slug")
        version = entry.get("version")
        if not slug or not version:
            continue
        scanned += 1
        print(f"[*] {scanned}/{len(data)} {slug} {version}", file=sys.stderr)
        url = DOWNLOAD.format(slug=slug, version=version)
        tmp = tempfile.mkdtemp(prefix=f"ba_{slug}_")
        zpath = os.path.join(tmp, f"{slug}.zip")
        try:
            req = Request(url, headers={"User-Agent": "wp-plugin-security-scanner/1.0"})
            with urlopen(req, timeout=60) as r, open(zpath, "wb") as f:
                f.write(r.read())
            with zipfile.ZipFile(zpath) as z:
                z.extractall(tmp)
        except Exception as e:
            print(f"    download failed: {e}", file=sys.stderr)
            continue
        root = os.path.join(tmp, slug)
        if not os.path.isdir(root):
            root = tmp
        res = audit.audit_plugin(root)
        hits = [r for r in res if r.get(sink_key)]
        if hits:
            flagged.append({"slug": slug, "version": version,
                            "active_installs": entry.get("active_installs"),
                            "last_updated": entry.get("last_updated"),
                            "flagged_handlers": hits})
            print(f"    [+] FLAGGED: {len(hits)} handler(s)", file=sys.stderr)

    print(json.dumps(flagged, indent=2, ensure_ascii=False), file=sys.stdout)
    print(f"\n[done] scanned {scanned}, flagged {len(flagged)} ({'xss' if args.xss else 'sqli'})", file=sys.stderr)


if __name__ == "__main__":
    main()
