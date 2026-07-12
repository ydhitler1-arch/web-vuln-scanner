#!/usr/bin/env python3
"""
VulnScan -- Lightweight Web Vulnerability Scanner (v2.0)
========================================================

Usage:
    python main.py <target_url> [options]

Examples:
    python main.py https://example.com
    python main.py https://example.com --modules xss sqli --max-pages 50
    python main.py https://example.com --output ./results --timeout 15 -v
    python main.py https://example.com --skip-discovery --skip-subdomains
"""

import os
import sys
import time
import logging
import argparse

# Fix Windows console encoding before any output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
from requests.adapters import HTTPAdapter
from colorama import init, Fore, Style

from scanner.crawler import Crawler
from scanner.modules import MODULE_REGISTRY, ALL_MODULE_NAMES, get_module
from scanner.reporter import Reporter
from scanner.discovery import DirectoryProber, SubdomainScanner, TechFingerprinter

# Initialize colorama for Windows support
init(autoreset=True)


BANNER = f"""
{Fore.RED} __      __    _       ___
 \\ \\    / /  _| |_ __ / __|  ___  __ _  _ _
  \\ \\/\\/ / || | | '_ \\\\__ \\ / __| / _` || ' \\
   \\_/\\_/ \\_,_|_| .__/|___/ \\___| \\__,_||_||_|
                 |_|{Style.RESET_ALL}
{Fore.CYAN}  Lightweight Web Vulnerability Scanner v2.0{Style.RESET_ALL}
{Fore.WHITE}  --------------------------------------------{Style.RESET_ALL}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScan -- Lightweight Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com
  python main.py https://example.com --modules xss sqli
  python main.py https://example.com --max-pages 50 --timeout 15
  python main.py https://example.com --output ./reports -v
  python main.py https://example.com --skip-discovery
  python main.py https://example.com --skip-subdomains
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",          # makes it optional — prompt handled in main()
        default=None,
        help="Target URL to scan (e.g., https://example.com)",
    )
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=ALL_MODULE_NAMES,
        default=ALL_MODULE_NAMES,
        help=f"Modules to run (default: all). Choices: {', '.join(ALL_MODULE_NAMES)}",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum pages to crawl (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent requests for discovery/subdomain phases (default: 20)",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--cookie",
        help="Session cookie to use (format: 'name=value')",
    )
    parser.add_argument(
        "--header",
        action="append",
        help="Custom header (format: 'Name: Value'). Can be repeated.",
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Skip the directory/path discovery phase",
    )
    parser.add_argument(
        "--skip-subdomains",
        action="store_true",
        help="Skip subdomain enumeration",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    return parser.parse_args()


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=(
            f"{Fore.BLUE}%(asctime)s{Style.RESET_ALL} "
            f"[%(levelname)s] %(name)s: %(message)s"
        ),
        datefmt="%H:%M:%S",
    )


def build_session(args):
    """Create a requests session with any custom auth/headers."""
    session = requests.Session()

    # Size the connection pool to the worker count so the concurrent
    # discovery/subdomain phases reuse pooled connections instead of
    # constantly creating and discarding them ("Connection pool is full").
    adapter = HTTPAdapter(
        pool_connections=args.workers,
        pool_maxsize=args.workers,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36 VulnScan/1.0"
        ),
    })

    if args.cookie:
        name, _, value = args.cookie.partition("=")
        session.cookies.set(name.strip(), value.strip())

    if args.header:
        for h in args.header:
            name, _, value = h.partition(":")
            session.headers[name.strip()] = value.strip()

    return session


def print_phase(phase_num, phase_name, detail=""):
    """Print a phase header."""
    print(f"\n{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[Phase {phase_num}] {phase_name}{Style.RESET_ALL}")
    if detail:
        print(f"    {Fore.WHITE}{detail}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}\n")


def print_kv(key, value, indent=2):
    """Print a key-value pair."""
    spaces = " " * indent
    print(f"{spaces}{Fore.CYAN}{key}:{Style.RESET_ALL} {value}")


def main():
    print(BANNER)
    args = parse_args()
    setup_logging(args.verbose)

    logger = logging.getLogger("vulnscan")

    # ── Prompt for target if not supplied on the command line ──
    target = args.target
    if not target:
        try:
            target = input(f"  {Fore.CYAN}Enter target URL:{Style.RESET_ALL} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {Fore.RED}Aborted.{Style.RESET_ALL}")
            sys.exit(0)

        if not target:
            print(f"  {Fore.RED}No target provided. Exiting.{Style.RESET_ALL}")
            sys.exit(1)

    # Validate / normalise URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"  {Fore.WHITE}Target:{Style.RESET_ALL}    {Fore.YELLOW}{target}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Modules:{Style.RESET_ALL}   {Fore.YELLOW}{', '.join(args.modules)}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Max pages:{Style.RESET_ALL} {Fore.YELLOW}{args.max_pages}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Discovery:{Style.RESET_ALL} {Fore.YELLOW}{'skip' if args.skip_discovery else 'enabled'}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Subdomains:{Style.RESET_ALL}{Fore.YELLOW} {'skip' if args.skip_subdomains else 'enabled'}{Style.RESET_ALL}")
    print()

    session = build_session(args)
    start_time = time.time()
    extra_seeds = []

    # ── Phase 0: Discovery ──────────────────────────────────
    discovery_summary = {}
    subdomain_results = []
    tech_results = {}

    if not args.skip_discovery:
        print_phase(0, "DISCOVERY", "Probing common paths, fingerprinting tech stack")

        # Directory probing
        print(f"  {Fore.MAGENTA}> Directory probing...{Style.RESET_ALL}")
        prober = DirectoryProber(target, session=session, timeout=args.timeout, max_workers=args.workers)
        discovery_results = prober.probe()
        discovery_summary = prober.summary()

        for category, hits in discovery_results.items():
            count = len(hits)
            statuses = {}
            for h in hits:
                s = h.get("status", "?")
                statuses[s] = statuses.get(s, 0) + 1
            status_str = ", ".join(f"{s}:{c}" for s, c in sorted(statuses.items()))
            print(f"    {Fore.CYAN}{category}:{Style.RESET_ALL} {count} found ({status_str})")

        # Add discovered URLs as extra seeds for the crawler
        extra_seeds = prober.get_all_urls()
        injectable = prober.get_injectable_urls()
        print(f"\n  {Fore.WHITE}Total discovered:{Style.RESET_ALL} {discovery_summary.get('total_discovered', 0)} endpoints")
        print(f"  {Fore.WHITE}Injectable URLs:{Style.RESET_ALL}  {len(injectable)}")
        print(f"  {Fore.WHITE}Extra seeds:{Style.RESET_ALL}      {len(extra_seeds)} URLs fed to crawler")

        # Technology fingerprinting
        print(f"\n  {Fore.MAGENTA}> Technology fingerprinting...{Style.RESET_ALL}")
        fingerprinter = TechFingerprinter(session=session, timeout=args.timeout)
        tech_results = fingerprinter.fingerprint(target)

        if tech_results:
            for tech_name, info in tech_results.items():
                print(f"    {Fore.YELLOW}[+]{Style.RESET_ALL} {tech_name}: {info['details']}")
                logger.debug(f"    Evidence: {info['evidence']}")
        else:
            print(f"    {Fore.WHITE}No specific technologies detected{Style.RESET_ALL}")

    # ── Phase 0.5: Subdomain Scan ───────────────────────────
    if not args.skip_subdomains:
        print_phase("0.5", "SUBDOMAIN SCAN", "Checking common subdomain prefixes")

        sub_scanner = SubdomainScanner(target, session=session, timeout=3, max_workers=args.workers)
        subdomain_results = sub_scanner.scan()

        if subdomain_results:
            for sub in subdomain_results:
                title = sub.get("title", "")[:50]
                server = sub.get("server", "")
                print(
                    f"    {Fore.YELLOW}[LIVE]{Style.RESET_ALL} {sub['subdomain']} "
                    f"({sub['status']}) "
                    f"{Fore.WHITE}{server}{Style.RESET_ALL} "
                    f"{Fore.CYAN}{title}{Style.RESET_ALL}"
                )
        else:
            print(f"    {Fore.WHITE}No live subdomains found{Style.RESET_ALL}")

    # ── Phase 1: Crawl ──────────────────────────────────────
    print_phase(1, "CRAWLING", f"Discovering attack surface from {target}")
    crawl_start = time.time()

    crawler = Crawler(
        seed_url=target,
        max_pages=args.max_pages,
        session=session,
        timeout=args.timeout,
        extra_seeds=extra_seeds,
    )
    crawl_result = crawler.crawl()

    # Store tech info in crawl result for the reporter
    crawl_result.technologies = tech_results

    crawl_time = time.time() - crawl_start
    summary = crawl_result.summary()

    print_kv("Pages crawled", summary['pages_crawled'])
    print_kv("Forms found", summary['forms_found'])
    print_kv("Links discovered", summary['links_discovered'])
    print_kv("API endpoints", summary['api_endpoints'])
    print_kv("Parameterized URLs", summary['parameterized_urls'])
    print_kv("Path parameters", summary['path_parameters'])
    print_kv("Crawl time", f"{crawl_time:.1f}s")

    # Distinguish "nothing to scan" from "scanned and clean". A zero-page
    # crawl usually means the target blocked us, redirected to a consent/login
    # wall, or renders its content with JavaScript we can't see.
    crawl_failed = summary['pages_crawled'] == 0
    if crawl_failed:
        print(
            f"\n  {Fore.RED}[!] Crawl reached 0 pages.{Style.RESET_ALL} "
            f"{Fore.WHITE}The target may be blocking automated requests, "
            f"redirecting to a login/consent page, or rendering content via "
            f"JavaScript. Scan results below are NOT a clean bill of health.{Style.RESET_ALL}"
        )

    # ── Phase 2: Scan ───────────────────────────────────────
    print_phase(2, "SCANNING", f"Running {len(args.modules)} module(s)")

    reporter = Reporter(
        target_url=target,
        crawl_summary=summary,
    )

    # Add discovery metadata to report
    if crawl_failed:
        reporter.extra_metadata["crawl_warning"] = (
            "Crawl reached 0 pages — target may block automation, require "
            "auth/consent, or render via JavaScript. Absence of findings does "
            "NOT indicate the target is secure."
        )
    if discovery_summary:
        reporter.extra_metadata["discovery"] = discovery_summary
    if subdomain_results:
        reporter.extra_metadata["subdomains"] = [
            {"subdomain": s["subdomain"], "status": s["status"]}
            for s in subdomain_results
        ]
    if tech_results:
        reporter.extra_metadata["technologies"] = {
            name: info["details"] for name, info in tech_results.items()
        }

    for module_name in args.modules:
        print(f"  {Fore.MAGENTA}> Running module:{Style.RESET_ALL} {module_name}")

        module = get_module(module_name, session=session, timeout=args.timeout)
        findings = module.scan(crawl_result)
        reporter.add_findings(findings)
        reporter.register_module(module_name)

        # Per-module mini summary
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        if findings:
            parts = [f"{sev}: {cnt}" for sev, cnt in sorted(severity_counts.items())]
            print(f"    {Fore.YELLOW}-> {len(findings)} finding(s): {', '.join(parts)}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}-> Clean [OK]{Style.RESET_ALL}")

    # ── Phase 3: Report ─────────────────────────────────────
    print_phase(3, "REPORTING", "Generating reports")

    os.makedirs(args.output, exist_ok=True)

    json_path = os.path.join(args.output, "report.json")
    txt_path = os.path.join(args.output, "report.txt")
    html_path = os.path.join(args.output, "report.html")

    reporter.generate_json(json_path)
    reporter.generate_text(txt_path)
    reporter.generate_html(html_path)

    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} JSON report: {Fore.CYAN}{json_path}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} Text report: {Fore.CYAN}{txt_path}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} HTML report: {Fore.CYAN}{html_path}{Style.RESET_ALL}")

    # Print summary
    reporter.print_summary()

    total_time = time.time() - start_time
    print(f"  {Fore.WHITE}Total scan time: {total_time:.1f}s{Style.RESET_ALL}")
    print()

    # Exit code: non-zero if CRITICAL or HIGH findinghs
    critical_high = sum(
        1 for f in reporter.findings
        if f.severity in ("CRITICAL", "HIGH")
    )
    if critical_high > 0:
        print(
            f"  {Fore.RED}[!] {critical_high} CRITICAL/HIGH finding(s) detected!{Style.RESET_ALL}"
        )
        sys.exit(1)
    else:
        print(f"  {Fore.GREEN}[OK] No critical/high severity findings.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()