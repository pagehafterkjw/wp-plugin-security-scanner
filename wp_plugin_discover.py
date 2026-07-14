#!/usr/bin/env python3
"""
WordPress plugin discovery for security auditing.

Pulls plugin lists from the wordpress.org plugins API, filters down to
abandoned or stale plugins (last updated beyond a year threshold — high attack
surface, low scrutiny), downloads their source, and greps each one for the
overlap of an unauthenticated AJAX handler and a raw SQL call. The grep is
inline (two patterns), not a call to wp_plugin_scanner.py, since discovery only
needs the two-signal filter.

Output is a ranked candidate list: plugins whose unauthenticated AJAX
handlers feed user input into a raw SQL call.

Defensive use: audit plugins for responsible disclosure. Do not run payloads
against sites you do not own or are not authorized to test.
"""

import argparse
import json
import os
import re
import sys
import tempfile
import zipfile
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOAD = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"

# niches that tend to do AJAX + DB work: booking, clinic, map, form, directory, stats
DEFAULT_SEARCHES = [
    "booking", "appointment", "clinic", "reservation",
    "directory", "listing", "form builder", "survey", "poll",
]


def api_get(params):
    """Call the wordpress.org plugins API (GET only, params URL-encoded)."""
    qs = "&".join(f"{quote(k)}={quote(str(v), safe='')}" for k, v in params.items())
    url = f"{API}?{qs}"
    req = Request(url, headers={"User-Agent": "wp-plugin-security-scanner/1.0"})
    with urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def query_plugins(search, per_page, page):
    # NOTE: do NOT pass request[browse] here — when both browse and search are
    # present the API ignores search and returns the browse list. search-only.
    return api_get({
        "action": "query_plugins",
        "request[search]": search,
        "request[per_page]": per_page,
        "request[page]": page,
    })


def looks_abandoned(plugin, max_year=None):
    """active installs in a small/niche band (high surface, low scrutiny).

    max_year: if set, also require last_updated year <= max_year (abandoned-ish).
    If None, keep all small-install plugins (don't over-filter on freshness)."""
    ai = plugin.get("active_installs", 0)
    if not (100 <= ai <= 5000):
        return False
    if max_year is None:
        return True
    lu = plugin.get("last_updated", "")
    m = re.match(r"(\d{4})-", lu)
    if not m:
        return False
    return int(m.group(1)) <= max_year


def download_and_scan(slug, version, scanner_path):
    """Download a plugin zip, extract, grep for unauth-AJAX + raw-SQL overlap."""
    url = DOWNLOAD.format(slug=slug, version=version)
    tmp = tempfile.mkdtemp(prefix=f"wpd_{slug}_")
    zpath = os.path.join(tmp, f"{slug}.zip")
    try:
        req = Request(url, headers={"User-Agent": "wp-plugin-security-scanner/1.0"})
        with urlopen(req, timeout=60) as r, open(zpath, "wb") as f:
            f.write(r.read())
        with zipfile.ZipFile(zpath) as z:
            z.extractall(tmp)
    except Exception as e:
        return {"slug": slug, "error": f"download/extract: {e}"}

    root = os.path.join(tmp, slug)
    php_files = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f.endswith(".php"):
                php_files.append(os.path.join(dp, f))

    # flags: does any PHP file register wp_ajax_nopriv_ AND have a raw $wpdb call?
    has_nopriv = False
    raw_sql_hits = []
    nopriv_re = re.compile(r"wp_ajax_nopriv_\s*['\"]?\w+['\"]?\s*[,)]")
    sql_re = re.compile(r"\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(")
    for pf in php_files:
        try:
            with open(pf, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
        except Exception:
            continue
        if nopriv_re.search(txt):
            has_nopriv = True
        for m in sql_re.finditer(txt):
            # is this call wrapped in prepare? crude check: same line no prepare nearby
            ln = txt[:m.start()].count("\n") + 1
            line = txt.splitlines()[ln - 1] if ln - 1 < len(txt.splitlines()) else ""
            if "prepare" not in line and "$" in line:
                # exclude freemius/sdk vendor dirs
                if "/freemius/" not in pf.replace("\\", "/") and "/vendor/" not in pf.replace("\\", "/"):
                    raw_sql_hits.append({"file": pf.replace(root, ""), "line": ln, "code": line.strip()[:120]})

    return {
        "slug": slug,
        "version": version,
        "php_files": len(php_files),
        "has_unauth_ajax": has_nopriv,
        "raw_sql_count": len(raw_sql_hits),
        "raw_sql_hits": raw_sql_hits[:10],
    }


def main():
    p = argparse.ArgumentParser(description="WordPress plugin discovery for security auditing")
    p.add_argument("-s", "--searches", nargs="*", default=DEFAULT_SEARCHES, help="search keywords")
    p.add_argument("-n", "--per-search", type=int, default=20, help="plugins to pull per search keyword")
    p.add_argument("--pages", type=int, default=3, help="pages to pull per search keyword (each page = per-search)")
    p.add_argument("--max-year", type=int, default=None, help="optional: require last_updated year <= this (abandoned filter)")
    p.add_argument("--scan", action="store_true", help="download + static-scan each candidate")
    args = p.parse_args()

    candidates = []
    seen = set()
    for kw in args.searches:
        for page in range(1, args.pages + 1):
            try:
                data = query_plugins(kw, args.per_search, page)
            except Exception as e:
                print(f"[!] search '{kw}' page {page} failed: {e}", file=sys.stderr)
                break
            plugins = data.get("plugins", [])
            if not plugins:
                break
            for pl in plugins:
                slug = pl.get("slug")
                if slug in seen:
                    continue
                seen.add(slug)
                if looks_abandoned(pl, args.max_year):
                    candidates.append({
                        "slug": slug,
                        "name": pl.get("name"),
                        "version": pl.get("version"),
                        "active_installs": pl.get("active_installs"),
                        "last_updated": pl.get("last_updated"),
                    })
        print(f"[*] '{kw}': candidates so far: {len(candidates)}", file=sys.stderr)

    print(f"\n[+] {len(candidates)} abandoned/niche candidates found:\n", file=sys.stderr)
    out = []
    for c in candidates:
        if args.scan:
            print(f"[*] scanning {c['slug']}...", file=sys.stderr)
            try:
                res = download_and_scan(c["slug"], c["version"], None)
                res["name"] = c["name"]
                res["active_installs"] = c["active_installs"]
                res["last_updated"] = c["last_updated"]
                out.append(res)
            except Exception as e:
                out.append({"slug": c["slug"], "error": str(e)})
        else:
            out.append(c)

    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
