# WP Security Scanner

A dependency-free WordPress plugin that audits your install for common security
misconfigurations and shows exactly how to fix each one.

## What it checks

| Check | Severity when failing |
|---|---|
| `WP_DEBUG_DISPLAY` enabled (errors shown to visitors) | Critical |
| `.git` directory inside the web root | Critical |
| Core update pending | Critical |
| `WP_DEBUG` on without `WP_DEBUG_LOG` | Warning |
| Theme/plugin file editor enabled (`DISALLOW_FILE_EDIT`) | Warning |
| XML-RPC enabled | Warning |
| `wp-content/debug.log` publicly readable | Warning |
| Admin not served over HTTPS | Warning |
| Plugin/theme/translation updates pending | Warning |
| `readme.html` / `license.txt` exposing the WP version | Info |
| Default `wp_` database prefix | Info |
| `FORCE_SSL_ADMIN` not set | Info |
| `<meta name="generator">` version disclosure | Info |

## Features

- **Tools → Security Scan** admin page with severity, detail and fix hint per finding
- **Dismiss** findings you accept (stored per-site, nonce-protected)
- **Admin notice** when critical issues are unresolved
- **Weekly cron re-scan** — emails the site admin only when the critical count grows
- Uninstall removes all options and the cron event — no leftovers

## Hooks

- `wpss_checks` — filter to add your own checks (append `[severity, title, detail, fix]` arrays)

## Install

Copy the `wp-security-scanner` folder into `wp-content/plugins/` and activate it in
wp-admin. Requires PHP 7.4+.

MIT licensed.
