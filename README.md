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

## Background

This scanner is a tool I use in my own WordPress plugin security audits to quickly locate code points that need manual review. Combined with manual review it helps find real issues efficiently — most of the CVEs I report were first triaged with this script.

## Related

- My CVE disclosures: [wp-cve-disclosures](https://github.com/LL-V/wp-cve-disclosures)
- My nuclei detection templates: [wp-nuclei-templates](https://github.com/LL-V/wp-nuclei-templates)

## Disclaimer

For auditing plugin source code you own or are authorized to test only.
