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

# XSS: an assignment that pulls user input straight into a variable, e.g.
#   $msg = $_POST['msg'];   $msg = sanitize_text_field($_POST['msg']) is safe.
# We capture the variable name so we can check whether it is later echoed raw.
USER_INPUT_ASSIGN_RE = re.compile(
    r"\$(\w+)\s*=\s*"
    r"(?!(?:absint|intval|sanitize_text_field|sanitize_email|sanitize_key|"
    r"sanitize_title|sanitize_file_name|wp_kses|wp_kses_post|esc_html|"
    r"esc_attr|esc_url|esc_textarea|esc_js)\s*\()"
    r".*?\$_(POST|GET|REQUEST)\s*\["
)
ESCAPE_RE = re.compile(
    r"\b(absint|intval|sanitize_text_field|sanitize_email|sanitize_key|"
    r"sanitize_title|wp_kses|wp_kses_post|esc_html|esc_attr|esc_url|"
    r"esc_textarea|esc_js)\s*\("
)
# raw output of a variable: an echo/print line that mentions a variable at all.
# echo $var / echo '<div>'.$var / echo "text $var" / print $var all count.
# wp_send_json($var) is NOT an XSS sink (it JSON-encodes) — skip it.
RAW_OUTPUT_RE = re.compile(r"\b(?:echo|print)\b(?!\s*_)")  # echo / print, not echo_ / print_


def analyze_handler(body):
    """Classify a handler body for SQLi and XSS candidate patterns."""
    has_guard = bool(GUARD_RE.search(body))
    has_input = bool(INPUT_RE.search(body))

    # raw sql: per-line, exclude lines that also call prepare on the same line
    raw_sql_lines = []
    for ln in body.splitlines():
        if SQL_RE.search(ln) and "prepare" not in ln:
            s = ln.strip()
            if s:
                raw_sql_lines.append(s[:140])

    # XSS: find variables assigned directly from user input (no escaping fn),
    # then check whether any of them is echoed raw somewhere in the body.
    # Two false-positive guards (note: body is string/comment-stripped, so a
    # quoted function name like 'sanitize_text_field' appears as blanks):
    #   - $v = get_option(...)            : option values are stored data, not
    #     live user input; even if $_POST appears deep inside the key argument
    #     after sanitize_text_field, the variable holds DB content, not a raw
    #     echo sink of request data.
    #   - $v = array_map( <blank>, $_POST[..] ) : the first arg was a quoted
    #     callable (stripped to blanks) applied to every element of the request
    #     array — the whole array is sanitized at the door; downstream echoes
    #     are safe.
    tainted_vars = set()
    for m in USER_INPUT_ASSIGN_RE.finditer(body):
        var = m.group(1)
        line = m.group(0)
        if re.search(r"get_option\s*\(", line):
            continue
        if re.search(r"array_map\s*\(\s+,\s*\$_(?:POST|GET|REQUEST)\s*\[", line):
            continue
        tainted_vars.add(var)
    xss_lines = []
    if tainted_vars:
        for ln in body.splitlines():
            if not RAW_OUTPUT_RE.search(ln):
                continue
            # does this echo/print line mention any tainted variable?
            if not re.search(r"\$(" + "|".join(re.escape(v) for v in tainted_vars) + r")\b", ln):
                continue
            # is there an escape call wrapping the output on this line?
            if not ESCAPE_RE.search(ln):
                xss_lines.append(ln.strip()[:140])

    return {
        "has_guard": has_guard,
        "has_input": has_input,
        "raw_sql": raw_sql_lines,
        "xss": xss_lines,
        "interesting": (not has_guard)
        and has_input
        and (len(raw_sql_lines) > 0 or len(xss_lines) > 0),
        "xss_interesting": (not has_guard) and has_input and len(xss_lines) > 0,
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
            "xss": cls["xss"],
            "interesting": cls["interesting"],
            "xss_interesting": cls["xss_interesting"],
        })
    return results


def main():
    p = argparse.ArgumentParser(description="Audit unauthenticated AJAX handlers in a WordPress plugin")
    p.add_argument("-p", "--path", required=True, help="plugin directory (extracted)")
    p.add_argument("--only-interesting", action="store_true", help="print only flagged handlers")
    p.add_argument("--xss", action="store_true", help="flag XSS candidates (raw echo of unescaped user input)")
    args = p.parse_args()

    root = args.path
    if not os.path.isdir(root):
        print(f"[-] not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    res = audit_plugin(root)
    if args.only_interesting:
        if args.xss:
            res = [r for r in res if r.get("xss_interesting")]
        else:
            res = [r for r in res if r.get("interesting")]

    sqli_n = len([r for r in res if r.get("interesting")])
    xss_n = len([r for r in res if r.get("xss_interesting")])
    print(f"[+] {len(res)} unauth handlers, {sqli_n} sqli-flagged, {xss_n} xss-flagged", file=sys.stderr)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
