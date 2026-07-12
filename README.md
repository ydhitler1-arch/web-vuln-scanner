# VulnScan — Lightweight Web Vulnerability Scanner

A modular, Python-based web vulnerability scanner that discovers, crawls a target website and runs pluggable security checks against discovered attack surface.

## Features

### Scan modules

| Module | What it checks |
|---|---|
| **XSS** | Reflected XSS via URL param + form field injection (canary-first optimization) |
| **SQLi** | Error-based SQL injection with signatures for MySQL, PostgreSQL, MSSQL, SQLite, Oracle |
| **CSRF** | Missing CSRF tokens on POST forms, wildcard/reflective CORS policies |
| **Open Redirect** | Unvalidated redirects via URL params and form fields |
| **Path Traversal / LFI** | `../` traversal in params, forms, and path segments, verified by leaked `/etc/passwd` or `win.ini` content |
| **Headers** | 6 security headers, insecure cookie flags, HTTPS enforcement, server disclosure |
| **Privacy** | *(passive, no attack traffic)* third-party trackers, analytics/ad IDs, first/third-party cookies, missing privacy headers |

### Reconnaissance (runs before crawling, on by default)

| Phase | What it does |
|---|---|
| **Directory probing** | Probes common paths across multiple categories; discovered endpoints are fed to the crawler as extra seeds |
| **Subdomain scan** | Checks common subdomain prefixes and reports live hosts (status, server, title) |
| **Tech fingerprinting** | Fingerprints the server's technology stack from headers and response body |

Skip either recon phase with `--skip-discovery` / `--skip-subdomains`; tune concurrency with `--workers`.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run full scan
python main.py https://yourtarget.com

# Run specific modules only
python main.py https://yourtarget.com --modules xss sqli

# Skip the recon phases to go straight to crawl + scan
python main.py https://yourtarget.com --skip-discovery --skip-subdomains

# Render JavaScript so SPAs (React/Vue/Angular) become crawlable
# (one-time: pip install playwright && playwright install chromium)
python main.py https://yourtarget.com --render-js

# Limit crawl depth, increase timeout, raise recon concurrency
python main.py https://yourtarget.com --max-pages 50 --timeout 15 --workers 40

# With authentication cookie
python main.py https://yourtarget.com --cookie "session=abc123"

# Custom headers
python main.py https://yourtarget.com --header "Authorization: Bearer TOKEN"

# Verbose logging + custom output directory
python main.py https://yourtarget.com -v --output ./reports
```

## Architecture

```
main.py              ← CLI entry point (discover → crawl → scan → report)
scanner/
  __init__.py
  crawler.py         ← BFS crawler (pages, forms, links, API endpoints)
  discovery.py       ← directory probing, subdomain scan, tech fingerprint
  modules.py         ← 6 pluggable scanner modules + registry
  reporter.py        ← JSON + TXT + HTML report generator
```

### Execution Flow

1. **Discover** *(default; skippable)* — Directory probing, subdomain enumeration, and tech fingerprinting; discovered endpoints seed the crawler
2. **Crawl** — BFS from seed URL, discovers pages/forms/links/API endpoints/params
3. **Scan** — Each selected module runs against the crawl results
4. **Report** — Findings aggregated into `report.json` + `report.txt` + `report.html`

## Output

- `report.json` — Machine-readable, CI/CD-friendly (non-zero exit on CRITICAL/HIGH)
- `report.txt` — Human-readable with severity icons and remediation guidance
- `report.html` — Self-contained styled report (light/dark, no external assets) for sharing

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `target` | *(prompted if omitted)* | Target URL |
| `--modules` | all | Space-separated list: `xss sqli csrf open_redirect path_traversal headers privacy` |
| `--max-pages` | 100 | Max pages to crawl |
| `--timeout` | 10 | HTTP request timeout (seconds) |
| `--workers` | 20 | Concurrent requests for the discovery/subdomain phases |
| `--output` | `.` | Output directory for reports |
| `--cookie` | — | Session cookie (`name=value`) |
| `--header` | — | Custom header (`Name: Value`), repeatable |
| `--skip-discovery` | off | Skip the directory/path discovery phase |
| `--skip-subdomains` | off | Skip subdomain enumeration |
| `--render-js` | off | Render pages with headless Chromium so JS/SPA content is crawlable (needs Playwright) |
| `-v`, `--verbose` | off | Verbose/debug logging |

## Disclaimer

This tool is intended for **authorized security testing only**. Always get written permission before scanning targets you don't own. Unauthorized scanning may violate laws and regulations.
