# WordPress Plugin Source Code Security Scanner

> Statically scans WordPress plugin source code for high-risk vulnerability patterns.
> Defensive use: audit plugins you own or are authorized to test, to surface issues before they ship.

## What it detects

This is the file-level grep pass (`wp_plugin_scanner.py`). It flags these patterns:

- **SQL injection** — direct concatenation of `$_GET/$_POST/$_REQUEST/$_COOKIE` into a `$wpdb->query/get_results/get_var/get_row` call. The pattern also matches `prepare` (which is itself safe), so any hit on `prepare` is a false positive to dismiss by hand.
- **SQL injection (variable concatenation)** — a query line that references `$wpdb` and concatenates a variable into the string. Needs a human to confirm the variable is prepared/escaped, not raw.
- **Unauthenticated AJAX** — `wp_ajax_nopriv_*` action registrations (callable without login, high risk)
- **XSS** — unescaped `echo $_GET/$_POST`
- **Deserialization** — `unserialize()` on user input (or any `$variable` — the second match is broad on purpose, expect false positives to dismiss)
- **Command execution** — `eval/system/exec/shell_exec/passthru/popen/proc_open` on a variable
- **File upload** — `move_uploaded_file` (confirm whether the file type is validated)
- **SQL backup leak** — `.sql`/`.bak` files left in the tree (confirm they are not publicly served)

This pass is intentionally simple — it over-flags and a human dismisses the safe hits. The function-body pass below (`wp_unauth_audit.py`) is where the false positives get suppressed automatically.

## Usage

```bash
python wp_plugin_scanner.py -p /path/to/plugin-folder
```

For each finding it prints: file, line number, code snippet, risk type.

You can filter by severity:

```bash
python wp_plugin_scanner.py -p /path/to/plugin-folder --risk High
```

## Discovery

`wp_plugin_discover.py` pulls plugin lists from the wordpress.org plugins API,
filters to abandoned or stale plugins (last updated beyond a year threshold —
high attack surface, low scrutiny), downloads the source, and flags candidates
where an unauthenticated AJAX handler coexists with a raw SQL call. It uses
its own inline patterns for that overlap rather than calling
`wp_plugin_scanner.py`, since it only needs the two-signal filter.

```bash
python wp_plugin_discover.py -s "contact form" "booking" -n 24 --pages 2 --scan
```

Outputs JSON, one entry per plugin: whether it registers `wp_ajax_nopriv_*`,
how many raw `$wpdb->query/get_results/...` calls it has, and the matching lines.

### GitHub-hosted plugins

The wordpress.org official repo is heavily audited (Wordfence/Patchstack scan
it continuously, plus review pressure), so unauth SQLi/XSS there is largely
exhausted. Independently hosted plugins on GitHub get far less security
attention — many are commercial/portfolio plugins published in full with no
upstream review. `gh_plugin_discover.py` targets that surface:

```bash
python gh_plugin_discover.py -n 30 --pages 3
```

It queries the GitHub Search API for small PHP repos tagged `wordpress-plugin`
(`stars<5` ⇒ little scrutiny), downloads each tarball via codeload (free,
does not count against the API rate limit), and emits a JSON list of repos
that register `wp_ajax_nopriv_*` handlers — the high-signal input for the
batch auditor. Works anonymously; set `GH_TOKEN` to lift the rate limit.

## Function-body audit

The file-level pass over-counts: most `nopriv_` handlers check
`current_user_can()` / nonce inside, and most raw SQL is wrapped in
`$wpdb->prepare()` on another line. `wp_unauth_audit.py` does a function-body
pass instead — it extracts each `wp_ajax_nopriv_*` handler's body (brace-matched,
strings/comments stripped) and flags only handlers that have user input + a raw
SQL call AND no permission guard in the body.

```bash
python wp_unauth_audit.py -p /path/to/plugin-folder --only-interesting
```

Pass `--xss` to flag XSS candidates instead: handlers with no permission guard
that assign user input to a variable and `echo`/`print` it without an escaping
function (`esc_html` / `esc_attr` / `wp_kses` / `sanitize_*`).

```bash
python wp_unauth_audit.py -p /path/to/plugin-folder --only-interesting --xss
```

`wp_batch_audit.py` runs that audit across a JSON list of `{slug, version}`
(discover output) and prints only plugins with at least one flagged handler.
Pass `--xss` to switch the sink.

## Self-test

`tests/test_audit_suite.py` runs `wp_unauth_audit.py` and `wp_rest_audit.py`
against an intentionally vulnerable fixture plugin
(`tests/fixtures/vulnerable-plugin/`) and asserts each one detects the pattern
it should — unauth SQLi, reflected XSS, and an unauthenticated
(`__return_true`) REST route with tainted SQL — while a safe negative-control
handler (absint + prepare + capability check) is NOT flagged.

`wp_plugin_scanner.py` is the file-level grep pass and is not exercised by this
suite; it has no state to regress, so the fixture only covers the two auditors
that suppress false positives.

```bash
python tests/test_audit_suite.py
```

Exit 0 only if every assertion holds. This is the regression baseline: any
change to a detector that drops a real pattern or starts flagging the safe
handler fails the test.

## Background

This scanner is a tool I use in my own WordPress plugin security audits to
quickly locate code points that need manual review. The detectors are tuned
against real plugin source to suppress the two dominant false-positive
classes — option-sourced variables and entry-level `array_map` sanitization —
documented in the commit history.

## Related

- My CVE disclosures: [wp-cve-disclosures](https://github.com/pagehafterkjw/wp-cve-disclosures)
- My nuclei detection templates: [wp-nuclei-templates](https://github.com/pagehafterkjw/wp-nuclei-templates)

## Disclaimer

For auditing plugin source code you own or are authorized to test only.
