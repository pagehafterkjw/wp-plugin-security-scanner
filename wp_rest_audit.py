#!/usr/bin/env python3
"""
Unauthenticated REST API auditor for WordPress plugins.

Modern WP plugins expose functionality via register_rest_route() far more than
via wp_ajax_nopriv_ — and many developers set permission_callback to
__return_true (or omit it, or wire it to is_user_logged_in) without realising
that opens the route to anonymous callers. wp_unauth_audit.py only covers the
AJAX surface; this module covers the REST surface.

For each register_rest_route() call it extracts:
  - namespace + path           -> the full route, e.g. "polski/v1/consent"
  - methods                    -> GET/POST/...
  - callback                   -> the handler (function name or [obj,'method'])
  - permission_callback        -> __return_true / is_user_logged_in / a method
                                  / missing

A route is flagged UNAUTH when its permission_callback is:
  - '__return_true'                (explicitly public)
  - 'is_user_logged_in'            (blocks logged-out — but counts as a guard,
                                    NOT unauth; we still note it)
  - missing entirely               (WP 5.5+ throws a deprecation but still
                                    defaults to current_user_can('edit_posts');
                                    older plugins may run open — flag for review)
For unauth routes the handler body is then checked for the same SQLi/XSS
taint patterns as wp_unauth_audit (user input + raw sql / raw echo, no guard).

Defensive use: surface REST routes that need manual review for responsible
disclosure.
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_unauth_audit as ajax  # reuse strip + body extraction + taint rules

# register_rest_route( 'ns/v1', '/path/(?P<id>\d+)', $args )
# We capture the namespace, the path, and the args span (up to the matching
# close paren of the call). Because args are usually an array literal spanning
# many lines, we grab the call's arguments with a balanced-paren scan rather
# than a single regex.
ROUTE_CALL_RE = re.compile(r"register_rest_route\s*\(\s*")


def _extract_call_args(src, start):
    """Given src and the index right after `register_rest_route(`, return the
    raw text of all arguments up to the matching close paren (balanced).

    Tracks string/comment state so parentheses *inside* string literals or
    comments (e.g. inside '/checkboxes/(?P<id>[a-z0-9_]+)') do not corrupt
    the depth count. Returns the raw span (strings intact, so _arg_callable
    can still read 'adminPermissionCheck' out of [$this, 'method'])."""
    depth = 1
    i = start
    n = len(src)
    in_str = None  # '"' / "'" / None
    while i < n and depth > 0:
        c = src[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        # not in a string
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i < n - 1 and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == '"' or c == "'":
            in_str = c
            i += 1
            continue
        if c == "(" or c == "[" or c == "{":
            depth += 1
        elif c == ")" or c == "]" or c == "}":
            depth -= 1
            if depth == 0:
                return src[start:i]
        i += 1
    return src[start:i] if depth <= 0 else None


# pull a quoted string value for a key like  'permission_callback' => ...
def _arg_string(args_span, key):
    pat = re.compile(
        r"['\"]" + re.escape(key) + r"['\"]\s*=>\s*['\"]([A-Za-z_][\w\:\\]*)['\"]"
    )
    m = pat.search(args_span)
    return m.group(1) if m else None


# pull a callable value like  'callback' => [ $this, 'method' ]  or  'callback' => 'func'
def _arg_callable(args_span, key):
    # array( $this, 'method' )  /  [ $this, 'method' ]
    m = re.search(
        r"['\"]" + re.escape(key) + r"['\"]\s*=>\s*"
        r"(?:array\s*\(\s*\$\w+\s*,\s*|\[\s*\$\w+\s*,\s*)"
        r"['\"]([A-Za-z_]\w*)['\"]",
        args_span,
    )
    if m:
        return m.group(1)
    # bare 'func'
    m2 = re.search(
        r"['\"]" + re.escape(key) + r"['\"]\s*=>\s*['\"]([A-Za-z_]\w*)['\"]",
        args_span,
    )
    return m2.group(1) if m2 else None


def _arg_methods(args_span):
    m = re.search(r"['\"]methods['\"]\s*=>\s*['\"]?([A-Z_]+)", args_span)
    return m.group(1) if m else "?"


def find_rest_routes(stripped_src, raw_src):
    """Yield dicts describing each register_rest_route call in stripped_src.

    We need the *raw* src for namespace/path quoting (strip blanks them),
    but operate positionally on stripped_src for the balanced scan. To keep it
    simple we run the scan on raw_src directly — strings inside the route args
    (namespace, path, callback names) are exactly what we want to read, so not
    stripping is fine here; the taint analysis on the handler body later uses
    the stripped form via ajax.strip_strings_and_comments.
    """
    out = []
    for m in ROUTE_CALL_RE.finditer(raw_src):
        args = _extract_call_args(raw_src, m.end())
        if not args:
            continue
        # namespace may be a variable ($this->namespace), so it is not always a
        # quoted string. The path is always a quoted string starting with '/'.
        # Take the first quoted string that starts with '/' as the path; take
        # the first quoted string overall as the namespace (best-effort, may be
        # the path itself when namespace is a variable — that is fine for
        # display).
        strs = re.findall(r"['\"]([^'\"]+)['\"]", args[:300])
        path = next((s for s in strs if s.startswith("/")), strs[0] if strs else "?")
        ns = strs[0] if strs and strs[0].startswith("/") else (strs[0] if strs else "")
        # permission_callback may be a bare string ('__return_true') OR an
        # array callable ([$this, 'adminPermissionCheck']). Try both.
        perm = _arg_string(args, "permission_callback")
        if perm is None:
            perm = _arg_callable(args, "permission_callback")
        cb = _arg_callable(args, "callback")
        if cb is None:
            cb = _arg_string(args, "callback")
        methods = _arg_methods(args)
        out.append({
            "namespace": ns,
            "path": path,
            "route": f"{ns}{path}" if ns and not ns.startswith("/") else path,
            "methods": methods,
            "callback": cb,
            "permission_callback": perm,
        })
    return out


def classify_perm(perm):
    """Return (is_unauth, note)."""
    if perm is None:
        return True, "permission_callback MISSING (defaults to edit_posts on 5.5+, review)"
    if perm in ("__return_true", "__return_true"):
        return True, "permission_callback = __return_true (public)"
    low = perm.lower().replace("\\", "").replace("::", "->")
    if "is_user_logged_in" in low:
        return False, "permission_callback = is_user_logged_in (blocks anon — guarded)"
    if "current_user_can" in low:
        return False, "permission_callback = current_user_can (guarded)"
    return None, f"permission_callback = {perm} (custom — review the method)"


def audit_plugin(root):
    """Audit one plugin directory for unauth REST routes + taint."""
    results = []
    php_files = []
    for dp, dn, fn in os.walk(root):
        rel = os.path.relpath(dp, root).replace("\\", "/")
        if any(seg in rel + "/" for seg in ("/freemius/", "/vendor/",
              "/node_modules/", "/tests/", "/test/")):
            continue
        for f in fn:
            if f.endswith(".php"):
                php_files.append(os.path.join(dp, f))

    # map of all stripped file texts for handler lookup
    file_stripped = {}
    for pf in php_files:
        try:
            with open(pf, encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
        except Exception:
            continue
        file_stripped[pf] = (txt, ajax.strip_strings_and_comments(txt))

    for pf, (raw, stripped) in file_stripped.items():
        for route in find_rest_routes(stripped, raw):
            is_unauth, note = classify_perm(route["permission_callback"])
            entry = {
                "route": route["route"],
                "methods": route["methods"],
                "callback": route["callback"],
                "permission_callback": route["permission_callback"],
                "perm_note": note,
                "file": os.path.relpath(pf, root),
                "unauth": is_unauth,
            }
            cb = route["callback"]
            if cb:
                # find callback body across files
                body = None
                for pf2, (raw2, s2) in file_stripped.items():
                    b2 = ajax.extract_function_body(s2, cb)
                    if b2 is not None:
                        body = b2
                        break
                if body:
                    cls = ajax.analyze_handler(body)
                    entry["has_guard"] = cls["has_guard"]
                    entry["raw_sql"] = cls["raw_sql"]
                    entry["xss"] = cls["xss"]
                    entry["taint"] = bool(cls["raw_sql"] or cls["xss"])
                else:
                    entry["taint"] = None
                    entry["body_note"] = "callback body not found"
            results.append(entry)
    return results


def main():
    p = argparse.ArgumentParser(
        description="Audit unauthenticated REST routes in a WordPress plugin")
    p.add_argument("-p", "--path", required=True, help="plugin directory (extracted)")
    p.add_argument("--only-unauth", action="store_true",
                   help="print only routes flagged as unauthenticated")
    p.add_argument("--only-taint", action="store_true",
                   help="print only unauth routes whose handler has SQLi/XSS taint")
    args = p.parse_args()

    if not os.path.isdir(args.path):
        print(f"[-] not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    res = audit_plugin(args.path)
    unauth = [r for r in res if r["unauth"]]
    taint = [r for r in res if r["unauth"] and r.get("taint")]

    print(f"[+] {len(res)} REST routes, {len(unauth)} unauth, "
          f"{len(taint)} unauth+taointed", file=sys.stderr)

    if args.only_taint:
        res = taint
    elif args.only_unauth:
        res = unauth
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
