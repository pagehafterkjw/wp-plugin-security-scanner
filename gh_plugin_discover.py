#!/usr/bin/env python3
"""
Discover WordPress plugins hosted independently on GitHub (not on the
wordpress.org official repo) that register unauthenticated AJAX handlers —
the high-signal surface for unauth SQLi/XSS.

Official wordpress.org plugins are heavily sanitised (Wordfence/Patchstack
scan them constantly, plus review pressure). Independently hosted plugins
on GitHub get far less security attention: many are commercial/portfolio
plugins whose authors published the full source, with no upstream review.

This script is the discovery stage of the pipeline for that surface:
  1. query the GitHub Search API for small PHP repos tagged wordpress-plugin
     (stars<5 => little scrutiny, more likely unaudited)
  2. download each repo tarball (no .git history => faster than clone)
  3. grep the extracted source for wp_ajax_nopriv_ registrations
  4. emit a JSON list of {repo, slug-ish, nopriv_count} for the batch auditor

Auth: works anonymously (public GitHub API, 60 req/hr). If GH_TOKEN is set
in the env it is used to lift the rate limit. Only audits source you are
authorized to test (public repos under their own license) — see disclaimer.

Output on stdout: JSON array. Progress on stderr.
"""

import argparse
import io
import json
import os
import re
import sys
import tarfile
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://api.github.com"
NOPRIV_RE = re.compile(r"wp_ajax_nopriv_[\w-]+")


def gh_get(path, token=None):
    """GET a GitHub API path, return parsed JSON. Handles rate limit notes."""
    url = path if path.startswith("http") else API + path
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "wp-plugin-security-scanner/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    with urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def search_repos(query, per_page, token, page=1):
    q = quote(query)
    path = f"/search/repositories?q={q}&sort=updated&per_page={per_page}&page={page}"
    return gh_get(path, token)


def download_tarball(url, token, dest_dir):
    headers = {"User-Agent": "wp-plugin-security-scanner/1.0",
               "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    with urlopen(req, timeout=60) as r:
        data = r.read()
    bio = io.BytesIO(data)
    with tarfile.open(fileobj=bio, mode="r:gz") as tar:
        # filter='data' (Py3.12+) strips symlinks / path-escape entries that
        # would otherwise raise "outside the destination" on some repos.
        try:
            tar.extractall(dest_dir, filter="data")
        except TypeError:
            tar.extractall(dest_dir)  # older Python without filter kwarg


def count_nopriv(root):
    """Walk root, return list of (relfile, [nopriv action names])."""
    hits = []
    for dp, dn, fn in os.walk(root):
        # skip vendor/test/example noise
        rel = os.path.relpath(dp, root).replace("\\", "/")
        if any(seg in rel.lower() for seg in ("/vendor/", "/node_modules/",
              "/tests/", "/test/", "/__tests__/", "/freemius/")):
            continue
        for f in fn:
            if not f.endswith(".php"):
                continue
            fp = os.path.join(dp, f)
            try:
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    txt = fh.read()
            except Exception:
                continue
            actions = NOPRIV_RE.findall(txt)
            if actions:
                hits.append((os.path.relpath(fp, root), actions))
    return hits


def main():
    ap = argparse.ArgumentParser(
        description="Discover GitHub-hosted WP plugins with unauth AJAX handlers")
    ap.add_argument("--query", default="topic:wordpress-plugin stars:<5 language:PHP",
                    help="GitHub search query (default: small wp-plugin repos)")
    ap.add_argument("-n", "--per-page", type=int, default=30,
                    help="repos to fetch per API page")
    ap.add_argument("--pages", type=int, default=2, help="API pages to walk")
    ap.add_argument("--token", default=os.environ.get("GH_TOKEN"),
                    help="GitHub token (default: $GH_TOKEN, anon ok for small runs)")
    args = ap.parse_args()

    out = []
    seen = set()
    for page in range(1, args.pages + 1):
        try:
            res = search_repos(args.query, args.per_page, args.token, page)
        except Exception as e:
            print(f"[!] API page {page} failed: {e}", file=sys.stderr)
            break
        items = res.get("items", [])
        print(f"[*] page {page}: {len(items)} repos (total {res.get('total_count')})",
              file=sys.stderr)
        for repo in items:
            full = repo["full_name"]
            if full in seen:
                continue
            seen.add(full)
            # Search API does not return tarball_url; build it from default_branch.
            # Use codeload.github.com directly: it does NOT count against the
            # REST API rate limit (only /search does), so one search page lets us
            # pull many tarballs cheaply.
            ref = repo.get("default_branch") or "main"
            tarball = f"https://codeload.github.com/{full}/tar.gz/refs/heads/{ref}"
            tmp = tempfile.mkdtemp(prefix=f"gh_{repo['name'][:20]}_")
            try:
                download_tarball(tarball, args.token, tmp)
            except Exception as e:
                print(f"    {full}: tarball failed: {e}", file=sys.stderr)
                continue
            # extracted dir is the only subdir of tmp
            subs = [d for d in os.listdir(tmp)
                    if os.path.isdir(os.path.join(tmp, d))]
            root = os.path.join(tmp, subs[0]) if subs else tmp
            hits = count_nopriv(root)
            n = sum(len(a) for _, a in hits)
            if n > 0:
                out.append({
                    "repo": full,
                    "url": repo["html_url"],
                    "stars": repo["stargazers_count"],
                    "pushed": repo.get("pushed_at"),
                    "nopriv_count": n,
                    "nopriv_files": [{"file": f, "actions": a} for f, a in hits],
                })
                print(f"    [+] {full}: {n} nopriv actions in {len(hits)} file(s)",
                      file=sys.stderr)
            else:
                print(f"    [-] {full}: no nopriv", file=sys.stderr)

    print(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"\n[done] repos seen {len(seen)}, with nopriv {len(out)}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
