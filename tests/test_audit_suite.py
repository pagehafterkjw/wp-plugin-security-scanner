#!/usr/bin/env python3
"""
Self-test for the scanner audit suite against an intentionally-vulnerable
fixture plugin. Confirms each scanner detects the pattern it is supposed to,
and that the safe negative-control handler is NOT flagged.

Run:  python tests/test_audit_suite.py
Exit 0 only if every assertion passes.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "vulnerable-plugin")
PY = sys.executable


def run(script, *args):
    """Run a scanner script with --only-* flags, return parsed JSON list."""
    out = subprocess.run(
        [PY, os.path.join(ROOT, script), "-p", FIXTURE, *args],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(f"[!] {script} {' '.join(args)} exited {out.returncode}", file=sys.stderr)
        print(out.stderr, file=sys.stderr)
    return json.loads(out.stdout) if out.stdout.strip() else []


def handlers_named(results):
    return {r["handler"] for r in results}


def main():
    failures = []

    # --- wp_unauth_audit: SQLi mode must flag vtf_get_orders, not vtf_safe_lookup
    sqli = handlers_named(run("wp_unauth_audit.py", "--only-interesting"))
    if "vtf_get_orders" not in sqli:
        failures.append("SQLi: vtf_get_orders not flagged")
    if "vtf_safe_lookup" in sqli:
        failures.append("SQLi: vtf_safe_lookup wrongly flagged (negative control)")

    # --- wp_unauth_audit: XSS mode must flag vtf_preview
    xss = handlers_named(run("wp_unauth_audit.py", "--only-interesting", "--xss"))
    if "vtf_preview" not in xss:
        failures.append("XSS: vtf_preview not flagged")

    # --- wp_rest_audit: must find the public + tainted REST route
    rest = run("wp_rest_audit.py", "--only-unauth")
    public = [r for r in rest if r.get("permission_callback") == "__return_true"]
    tainted = [r for r in rest if r.get("taint")]
    if not any("vtf/v1/lookup" in r.get("route", "") for r in public):
        failures.append("REST: vtf/v1/lookup not detected as public (__return_true)")
    if not any("vtf/v1/lookup" in r.get("route", "") for r in tainted):
        failures.append("REST: vtf/v1/lookup not detected as tainted (raw sql)")

    # --- report
    print("=== scanner self-test ===")
    print(f"  SQLi flagged handlers : {sorted(sqli)}")
    print(f"  XSS  flagged handlers : {sorted(xss)}")
    print(f"  REST public routes    : {sorted(r['route'] for r in public)}")
    print(f"  REST tainted routes   : {sorted(r['route'] for r in tainted)}")
    print()
    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("PASS: all assertions hold")
    sys.exit(0)


if __name__ == "__main__":
    main()
