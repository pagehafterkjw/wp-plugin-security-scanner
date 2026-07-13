# WordPress Plugin Source Code Security Scanner

> Statically scans WordPress plugin source code for high-risk vulnerability patterns.
> Defensive use: audit plugins you own or are authorized to test, to surface issues before they ship.

## What it detects

- **SQL injection** — direct concatenation of `$_GET/$_POST/$_REQUEST` into `$wpdb->query/get_results/get_var`
- **Unauthenticated AJAX** — `wp_ajax_nopriv_*` action registrations (callable without login, high risk)
- **XSS** — unescaped `echo $_GET/$_POST`
- **Deserialization** — `unserialize()` on user input
- **Command execution** — `eval/system/exec/shell_exec` on a variable
- **File upload** — `move_uploaded_file` without type validation

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
filters to small/niche installs (high attack surface, low scrutiny), downloads
the source, and flags candidates where an unauthenticated AJAX handler coexists
with a raw SQL call.

```bash
python wp_plugin_discover.py -s "contact form" "booking" -n 24 --pages 2 --scan
```

Outputs JSON, one entry per plugin: whether it registers `wp_ajax_nopriv_*`,
how many raw `$wpdb->query/get_results/...` calls it has, and the matching lines.

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

`wp_batch_audit.py` runs that audit across a JSON list of `{slug, version}`
(discover output) and prints only plugins with at least one flagged handler.

## Background

This scanner is a tool I use in my own WordPress plugin security audits to quickly locate code points that need manual review. Combined with manual review it helps find real issues efficiently — most of the CVEs I report were first triaged with this script.

## Related

- My CVE disclosures: [wp-cve-disclosures](https://github.com/LL-V/wp-cve-disclosures)
- My nuclei detection templates: [wp-nuclei-templates](https://github.com/LL-V/wp-nuclei-templates)

## Disclaimer

For auditing plugin source code you own or are authorized to test only.
