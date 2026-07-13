#!/usr/bin/env python3
"""
WordPress Plugin Source Code Security Scanner
Statically scans PHP plugin source for high-risk vulnerability patterns.

For auditing plugins you own or are authorized to test.
"""

import os
import re
import argparse
from pathlib import Path

# Pattern definitions: (name, regex, severity, description)
PATTERNS = [
    (
        "SQLi - direct concatenation of user input",
        r'\$wpdb->(query|get_results|get_var|get_row|prepare)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
        "High",
        "SQL query concatenates user input directly, not parameterized",
    ),
    (
        "SQLi - query string built with variable concatenation",
        r'(?=.*wpdb->(prefix|query|get_results|get_var|get_row))(?=.*["\'].*\.\s*\$).*',
        "High",
        "A query line that references wpdb and concatenates a variable into a string; confirm the variable is prepared/escaped, not raw",
    ),
    (
        "Unauthenticated AJAX",
        r'add_action\s*\(\s*["\']wp_ajax_nopriv_',
        "High",
        "Registers an unauthenticated AJAX action, callable without login",
    ),
    (
        "XSS - unescaped output",
        r'echo\s+\$_(GET|POST|REQUEST)',
        "Medium",
        "Outputs user input directly, no esc_html",
    ),
    (
        "Deserialization",
        r'unserialize\s*\(\s*\$_(GET|POST|REQUEST)|unserialize\s*\(\s*\$',
        "High",
        "Deserializes user input, possible object injection",
    ),
    (
        "Command execution",
        r'\b(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$',
        "High",
        "Command execution on a variable, confirm the variable source",
    ),
    (
        "File upload - no validation",
        r'move_uploaded_file\s*\(',
        "Medium",
        "File upload, confirm whether the file type is validated",
    ),
    (
        "SQL backup leak",
        r'\.(sql|bak)\b',
        "Low",
        "Possible database backup file, confirm it is not publicly accessible",
    ),
]


def scan_file(filepath):
    """Scan a single PHP file, return a list of findings."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for name, pattern, severity, desc in PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append({
                    "file": filepath,
                    "line": i,
                    "risk": severity,
                    "type": name,
                    "desc": desc,
                    "code": line.strip()[:120],
                })
    return findings


def main():
    p = argparse.ArgumentParser(description="WordPress plugin source code security scanner")
    p.add_argument("-p", "--path", required=True, help="plugin directory path")
    p.add_argument("--risk", default="all", help="show only one severity (High/Medium/Low/all)")
    args = p.parse_args()

    plugin_dir = Path(args.path)
    if not plugin_dir.is_dir():
        print(f"[-] path does not exist or is not a directory: {plugin_dir}")
        return

    all_findings = []
    php_files = list(plugin_dir.rglob("*.php"))
    print(f"[*] scanning {len(php_files)} PHP files in {plugin_dir}")

    for f in php_files:
        all_findings.extend(scan_file(str(f)))

    # Filter by severity
    if args.risk != "all":
        all_findings = [x for x in all_findings if x["risk"] == args.risk]

    if not all_findings:
        print("[+] no high-risk patterns found")
        return

    print(f"\n[+] found {len(all_findings)} potential issues:\n")
    for fnd in all_findings:
        print(f"[{fnd['risk']}] {fnd['type']}")
        print(f"  file: {fnd['file']}:{fnd['line']}")
        print(f"  note: {fnd['desc']}")
        print(f"  code: {fnd['code']}")
        print()


if __name__ == "__main__":
    main()
