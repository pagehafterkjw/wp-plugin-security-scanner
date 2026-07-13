#!/usr/bin/env python3
"""
Unauthenticated-AJAX function-body auditor for WordPress plugins.

Most "has unauth ajax + has raw sql" hits are false positives: the handler
registers as nopriv_ but checks current_user_can() / nonce inside, or the SQL
is wrapped in $wpdb->prepare() on another line. This script does a function-
body-level pass instead:

  1. find every wp_ajax_nopriv_ registration, extract the handler function name
  2. locate that function's body (brace matching, strings/comments stripped)
  3. inside the body, check for:
       - permission guard   : current_user_can / check_ajax_referer / wp_verify_nonce
       - user input         : $_POST / $_GET / $_REQUEST
       - raw sql            : $wpdb->query/get_results/get_var/get_row/get_col
                              on a line with no prepare() nearby
  4. flag handlers that have user input + raw sql AND no permission guard

Those are the only ones worth reading by hand. The rest are safe or guarded.

Defensive use: audit plugins for responsible disclosure.
"""

import argparse
import json
import os
import re
import sys

# Match add_action( 'wp_ajax_nopriv_<name>', <handler> ) and capture the handler.
# Handler can be: 'func'  /  array( $this, 'func' )  /  [ $this, 'func' ].
# Strategy: capture everything from the nopriv action name up to the closing
# ')' or end-of-statement, then pull the LAST quoted identifier out of that
# span (that is always the handler name in all three forms).
NOPRIV_LINE_RE = re.compile(
    r"wp_ajax_nopriv_[\w-]+"            # the nopriv action name
    r".{0,80}?"                         # up to the handler (non-greedy, bounded)
    r"[\"']([A-Za-z_]\w*)[\"']"         # the handler name (last quote on the line)
)
QUOTED_IDENT_RE = re.compile(r"[\"']([A-Za-z_]\w*)[\"']")


def find_nopriv_handlers(txt):
    """Yield (handler_name) for every wp_ajax_nopriv_ registration in txt.

    The action name may or may not have its own quotes inside the captured span
    (depends on where wp_ajax_nopriv_ sits), so we just take the LAST quoted
    identifier on the line as the handler."""
    out = []
    for line in txt.splitlines():
        if "wp_ajax_nopriv_" not in line:
            continue
        idents = QUOTED_IDENT_RE.findall(line)
        if idents:
            out.append(idents[-1])  # handler is the last quoted identifier
    return out
FUNC_DEF_RE_TEMPLATE = r"function\s+{name}\s*\("


def strip_strings_and_comments(src):
    """Replace string literals and comments with spaces so brace counting and
    keyword scanning aren't fooled by code inside strings."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        # line comment //
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # block comment /* */
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n - 1 and not (src[i] == "*" and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
            continue
        # hash comment
        if c == "#":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # single-quote string
        if c == "'":
            out.append(" ")
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                if src[i] == "'":
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        # double-quote string
        if c == '"':
            out.append(" ")
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                if src[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def extract_function_body(stripped_src, func_name):
    """Return the body text (between the first { and its matching }) of the
    function named func_name, or None. Operates on string/comment-stripped src."""
    pat = re.compile(FUNC_DEF_RE_TEMPLATE.format(name=re.escape(func_name)))
    m = pat.search(stripped_src)
    if not m:
        return None
    # find first { after the function signature
    brace_open = stripped_src.find("{", m.end())
    if brace_open == -1:
        return None
    depth = 0
    i = brace_open
    n = len(stripped_src)
    while i < n:
        ch = stripped_src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return stripped_src[brace_open + 1:i]
        i += 1
    return None  # unbalanced


GUARD_RE = re.compile(r"current_user_can\s*\(|check_ajax_referer\s*\(|wp_verify_nonce\s*\(|is_user_logged_in\s*\(")
INPUT_RE = re.compile(r"\$_(POST|GET|REQUEST)\b")
SQL_RE = re.compile(r"\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(")


def analyze_handler(body):
    """Classify a handler body."""
    has_guard = bool(GUARD_RE.search(body))
    has_input = bool(INPUT_RE.search(body))
    # raw sql: per-line, exclude lines that also call prepare on the same line
    raw_sql_lines = []
    for ln in body.splitlines():
        if SQL_RE.search(ln) and "prepare" not in ln:
            # keep the snippet, trimmed
            s = ln.strip()
            if s:
                raw_sql_lines.append(s[:140])
    return {
        "has_guard": has_guard,
        "has_input": has_input,
        "raw_sql": raw_sql_lines,
    }


def audit_plugin(root):
    """Audit one plugin directory. Returns list of handler findings."""
    # gather handler names from all php files
    handlers = {}  # name -> file
    php_files = []
    for dp, dn, fn in os.walk(root):
        rel = os.path.relpath(dp, root).replace("\\", "/")
        if "/freemius/" in rel + "/" or "/vendor/" in rel + "/" or "/node_modules/" in rel + "/":
            continue
        for f in fn:
            if f.endswith(".php"):
                php_files.append(os.path.join(dp, f))

    for pf in php_files:
        try:
            with open(pf, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
        except Exception:
            continue
        for h in find_nopriv_handlers(txt):
            handlers.setdefault(h, pf)

    results = []
    for hname, hfile in handlers.items():
        try:
            with open(hfile, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
        except Exception:
            continue
        stripped = strip_strings_and_comments(txt)
        body = extract_function_body(stripped, hname)
        if body is None:
            # handler may be a method defined elsewhere; search all files
            for pf2 in php_files:
                try:
                    with open(pf2, "r", encoding="utf-8", errors="ignore") as fh:
                        t2 = fh.read()
                except Exception:
                    continue
                s2 = strip_strings_and_comments(t2)
                b2 = extract_function_body(s2, hname)
                if b2 is not None:
                    body = b2
                    hfile = pf2
                    break
        if body is None:
            results.append({"handler": hname, "file": os.path.relpath(hfile, root), "note": "body not found"})
            continue
        cls = analyze_handler(body)
        results.append({
            "handler": hname,
            "file": os.path.relpath(hfile, root),
            "has_guard": cls["has_guard"],
            "has_input": cls["has_input"],
            "raw_sql": cls["raw_sql"],
            "interesting": (not cls["has_guard"]) and cls["has_input"] and len(cls["raw_sql"]) > 0,
        })
    return results


def main():
    p = argparse.ArgumentParser(description="Audit unauthenticated AJAX handlers in a WordPress plugin")
    p.add_argument("-p", "--path", required=True, help="plugin directory (extracted)")
    p.add_argument("--only-interesting", action="store_true", help="print only flagged handlers")
    args = p.parse_args()

    root = args.path
    if not os.path.isdir(root):
        print(f"[-] not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    res = audit_plugin(root)
    if args.only_interesting:
        res = [r for r in res if r.get("interesting")]

    interesting = [r for r in res if r.get("interesting")]
    print(f"[+] {len(res)} unauth handlers, {len(interesting)} flagged (no guard + input + raw sql)", file=sys.stderr)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
