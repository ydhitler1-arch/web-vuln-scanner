"""
Reporter
========
Aggregates scanner findings into structured JSON and
human-readable text reports.
"""

import json
import logging
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger("vulnscan.reporter")


# Severity ordering for sorting
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding:
    """Represents a single vulnerability finding."""

    def __init__(self, module, severity, title, description,
                 url, evidence=None, remediation=None):
        self.module = module
        self.severity = severity      # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.url = url
        self.evidence = evidence or ""
        self.remediation = remediation or ""
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


class Reporter:
    """
    Collects findings from all scanner modules and generates reports.

    Supports:
    - JSON output (machine-readable, for pipelines)
    - TXT output (human-readable, for quick review)
    """

    def __init__(self, target_url, crawl_summary=None):
        self.target_url = target_url
        self.crawl_summary = crawl_summary or {}
        self.findings = []
        self.scan_start = datetime.now(timezone.utc)
        self.modules_run = []
        self.extra_metadata = {}   # populated by main.py (discovery, subdomains, tech)

    def add_finding(self, finding):
        """Add a Finding to the report."""
        self.findings.append(finding)

    def add_findings(self, findings):
        """Add multiple findings at once."""
        self.findings.extend(findings)

    def register_module(self, module_name):
        """Record that a module was executed."""
        self.modules_run.append(module_name)

    def _build_report_data(self):
        """Build the full report data structure."""
        scan_end = datetime.now(timezone.utc)

        # Group findings by severity
        by_severity = defaultdict(list)
        for f in self.findings:
            by_severity[f.severity].append(f.to_dict())

        # Group findings by module
        by_module = defaultdict(list)
        for f in self.findings:
            by_module[f.module].append(f.to_dict())

        # Severity counts
        severity_counts = {
            sev: len(by_severity.get(sev, []))
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        }

        return {
            "scan_metadata": {
                "target": self.target_url,
                "scan_start": self.scan_start.isoformat(),
                "scan_end": scan_end.isoformat(),
                "duration_seconds": (scan_end - self.scan_start).total_seconds(),
                "modules_run": self.modules_run,
                "vulnscan_version": "1.0.0",
                **self.extra_metadata,         # discovery, subdomains, technologies
            },
            "crawl_summary": self.crawl_summary,
            "summary": {
                "total_findings": len(self.findings),
                "severity_counts": severity_counts,
            },
            "findings_by_severity": dict(by_severity),
            "findings_by_module": dict(by_module),
            "all_findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda x: SEVERITY_ORDER.get(x.severity, 99)
            )],
        }

    def generate_json(self, output_path="report.json"):
        """Write findings to a JSON file."""
        data = self._build_report_data()

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report written to: {output_path}")
        return output_path

    def generate_text(self, output_path="report.txt"):
        """Write a human-readable text report."""
        data = self._build_report_data()
        lines = []

        # Header
        lines.append("=" * 72)
        lines.append("  VULNSCAN — Web Vulnerability Scan Report")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Target:     {data['scan_metadata']['target']}")
        lines.append(f"  Started:    {data['scan_metadata']['scan_start']}")
        lines.append(f"  Finished:   {data['scan_metadata']['scan_end']}")
        lines.append(f"  Duration:   {data['scan_metadata']['duration_seconds']:.1f}s")
        lines.append(f"  Modules:    {', '.join(data['scan_metadata']['modules_run'])}")
        lines.append("")

        # Crawl summary
        if data["crawl_summary"]:
            lines.append("-" * 72)
            lines.append("  CRAWL SUMMARY")
            lines.append("-" * 72)
            for key, val in data["crawl_summary"].items():
                lines.append(f"    {key:.<30} {val}")
            lines.append("")

        # Severity summary
        lines.append("-" * 72)
        lines.append("  FINDINGS SUMMARY")
        lines.append("-" * 72)
        lines.append(f"    Total findings: {data['summary']['total_findings']}")
        lines.append("")

        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🔵",
            "INFO":     "⚪",
        }
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = data["summary"]["severity_counts"][sev]
            icon = severity_icons.get(sev, "  ")
            lines.append(f"    {icon} {sev:<10} {count}")
        lines.append("")

        # Detailed findings
        if data["all_findings"]:
            lines.append("-" * 72)
            lines.append("  DETAILED FINDINGS")
            lines.append("-" * 72)
            lines.append("")

            for i, finding in enumerate(data["all_findings"], 1):
                sev = finding["severity"]
                icon = severity_icons.get(sev, "  ")
                lines.append(f"  [{i}] {icon} [{sev}] {finding['title']}")
                lines.append(f"      Module:      {finding['module']}")
                lines.append(f"      URL:         {finding['url']}")
                lines.append(f"      Description: {finding['description']}")
                if finding["evidence"]:
                    lines.append(f"      Evidence:    {finding['evidence']}")
                if finding["remediation"]:
                    lines.append(f"      Fix:         {finding['remediation']}")
                lines.append("")
        elif data["scan_metadata"].get("crawl_warning"):
            lines.append("")
            lines.append("  ⚠️  No findings — but the crawl reached 0 pages.")
            lines.append(f"     {data['scan_metadata']['crawl_warning']}")
            lines.append("")
        else:
            lines.append("")
            lines.append("  ✅ No vulnerabilities found!")
            lines.append("")

        lines.append("=" * 72)
        lines.append("  End of Report")
        lines.append("=" * 72)

        report_text = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        logger.info(f"Text report written to: {output_path}")
        return output_path

    def generate_html(self, output_path="report.html"):
        """Write a self-contained, styled HTML report (no external assets)."""
        import html as _html

        data = self._build_report_data()
        meta = data["scan_metadata"]
        counts = data["summary"]["severity_counts"]

        sev_color = {
            "CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
            "LOW": "#2563eb", "INFO": "#6b7280",
        }

        def esc(v):
            return _html.escape(str(v))

        # Summary chips
        chips = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            chips.append(
                f'<div class="chip" style="border-color:{sev_color[sev]}">'
                f'<span class="chip-count" style="color:{sev_color[sev]}">{counts[sev]}</span>'
                f'<span class="chip-label">{sev}</span></div>'
            )

        # Finding cards
        cards = []
        for i, f in enumerate(data["all_findings"], 1):
            sev = f["severity"]
            color = sev_color.get(sev, "#6b7280")
            rows = [
                ("Module", esc(f["module"])),
                ("URL", f'<a href="{esc(f["url"])}">{esc(f["url"])}</a>'),
                ("Description", esc(f["description"])),
            ]
            if f["evidence"]:
                rows.append(("Evidence", f'<code>{esc(f["evidence"])}</code>'))
            if f["remediation"]:
                rows.append(("Remediation", esc(f["remediation"])))
            row_html = "".join(
                f'<tr><th>{k}</th><td>{v}</td></tr>' for k, v in rows
            )
            cards.append(
                f'<div class="finding" style="border-left-color:{color}">'
                f'<div class="finding-head">'
                f'<span class="sev-badge" style="background:{color}">{sev}</span>'
                f'<span class="finding-title">#{i} &nbsp;{esc(f["title"])}</span></div>'
                f'<table class="finding-table">{row_html}</table></div>'
            )

        if not cards:
            if meta.get("crawl_warning"):
                cards.append(
                    f'<div class="empty warn">⚠️ No findings — but the crawl reached '
                    f'0 pages.<br><small>{esc(meta["crawl_warning"])}</small></div>'
                )
            else:
                cards.append('<div class="empty ok">✅ No vulnerabilities found.</div>')

        # Crawl summary rows
        crawl_rows = "".join(
            f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>'
            for k, v in data["crawl_summary"].items()
        )

        # Optional metadata (technologies, subdomains)
        tech = meta.get("technologies") or {}
        tech_html = ""
        if tech:
            items = "".join(f'<span class="tag">{esc(n)}</span>' for n in tech)
            tech_html = f'<div class="meta-block"><h3>Technologies</h3>{items}</div>'

        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnScan Report — {esc(meta['target'])}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    margin: 0; background: #0f172a; color: #e2e8f0; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
  header {{ border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ margin: 0 0 4px; font-size: 1.5rem; }}
  .muted {{ color: #94a3b8; font-size: .9rem; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
  .chip {{ border: 2px solid; border-radius: 10px; padding: 10px 16px; min-width: 92px;
    text-align: center; background: #1e293b; }}
  .chip-count {{ display: block; font-size: 1.8rem; font-weight: 700; }}
  .chip-label {{ font-size: .72rem; letter-spacing: .06em; color: #94a3b8; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid #334155; padding-bottom: 6px;
    margin-top: 32px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  .finding {{ background: #1e293b; border-left: 5px solid; border-radius: 8px;
    padding: 14px 18px; margin: 14px 0; overflow-x: auto; }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
  .sev-badge {{ color: #fff; font-size: .7rem; font-weight: 700; padding: 3px 9px;
    border-radius: 20px; letter-spacing: .05em; }}
  .finding-title {{ font-weight: 600; }}
  .finding-table th {{ text-align: left; color: #94a3b8; font-weight: 500;
    padding: 4px 12px 4px 0; vertical-align: top; white-space: nowrap; width: 120px; }}
  .finding-table td {{ padding: 4px 0; word-break: break-word; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px;
    font-size: .85rem; display: inline-block; }}
  a {{ color: #60a5fa; }}
  .meta-table th {{ text-align: left; color: #94a3b8; font-weight: 500; padding: 3px 12px 3px 0; }}
  .tag {{ display: inline-block; background: #334155; border-radius: 6px;
    padding: 3px 10px; margin: 3px; font-size: .82rem; }}
  .empty {{ padding: 28px; text-align: center; border-radius: 8px; background: #1e293b;
    font-size: 1.05rem; }}
  .empty.warn {{ border: 1px solid #ca8a04; }}
  footer {{ margin-top: 40px; color: #64748b; font-size: .8rem; text-align: center; }}
  @media (prefers-color-scheme: light) {{
    body {{ background: #f8fafc; color: #0f172a; }}
    .chip, .finding, .empty {{ background: #fff; }}
    .muted, .finding-table th, .meta-table th, .chip-label {{ color: #475569; }}
    code {{ background: #f1f5f9; }} a {{ color: #2563eb; }}
    header {{ border-color: #cbd5e1; }} .tag {{ background: #e2e8f0; }}
  }}
</style></head><body><div class="wrap">
<header>
  <h1>🛡️ VulnScan Report</h1>
  <div class="muted">Target: <strong>{esc(meta['target'])}</strong></div>
  <div class="muted">Scanned: {esc(meta['scan_start'])} &middot;
    Duration: {meta['duration_seconds']:.1f}s &middot;
    Modules: {esc(', '.join(meta['modules_run']))}</div>
</header>

<div class="chips">{''.join(chips)}</div>
<div class="muted">Total findings: <strong>{data['summary']['total_findings']}</strong></div>

{tech_html}

<h2>Findings</h2>
{''.join(cards)}

<h2>Crawl Summary</h2>
<table class="meta-table">{crawl_rows}</table>

<footer>Generated by VulnScan v{esc(meta.get('vulnscan_version','1.0.0'))} &middot;
  For authorized security testing only.</footer>
</div></body></html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)

        logger.info(f"HTML report written to: {output_path}")
        return output_path

    def print_summary(self):
        """Print a quick summary to stdout."""
        data = self._build_report_data()
        counts = data["summary"]["severity_counts"]

        print("\n" + "=" * 50)
        print("  SCAN COMPLETE")
        print("=" * 50)
        print(f"  Total findings: {data['summary']['total_findings']}")
        print()

        severity_colors = {
            "CRITICAL": "\033[91m",  # red
            "HIGH":     "\033[93m",  # yellow
            "MEDIUM":   "\033[33m",  # dark yellow
            "LOW":      "\033[94m",  # blue
            "INFO":     "\033[37m",  # gray
        }
        reset = "\033[0m"

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            color = severity_colors.get(sev, "")
            count = counts[sev]
            bar = "█" * count + "░" * max(0, 10 - count)
            print(f"  {color}{sev:<10}{reset} {bar} {count}")

        print()