"""
Scanner Modules
===============
Pluggable vulnerability checkers. Each module implements a `scan()` method
that accepts a CrawlResult and a requests.Session and returns a list of Findings.

Modules:
    - XSSScanner           — reflected XSS via param/form injection
    - SQLiScanner          — SQL injection via error-based detection
    - CSRFScanner          — missing CSRF tokens + CORS misconfiguration
    - OpenRedirectScanner  — unvalidated redirect parameters
    - PathTraversalScanner — path traversal / local file inclusion (LFI)
    - HeaderScanner        — missing security headers, insecure cookies, HTTP usage
"""

import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

import requests

from .reporter import Finding

logger = logging.getLogger("vulnscan.modules")


# ─────────────────────────────────────────────────────────────
#  Base Module
# ─────────────────────────────────────────────────────────────

class BaseModule:
    """Abstract base for all scanner modules."""

    name = "base"
    description = "Base scanner module"

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []

    def scan(self, crawl_result):
        """Override in subclasses. Returns list of Finding objects."""
        raise NotImplementedError

    def _make_finding(self, severity, title, description, url,
                      evidence="", remediation=""):
        return Finding(
            module=self.name,
            severity=severity,
            title=title,
            description=description,
            url=url,
            evidence=evidence,
            remediation=remediation,
        )

    def _safe_get(self, url, **kwargs):
        """GET with error handling."""
        try:
            return self.session.get(
                url, timeout=self.timeout, allow_redirects=False, **kwargs
            )
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _safe_post(self, url, data=None, **kwargs):
        """POST with error handling."""
        try:
            return self.session.post(
                url, data=data, timeout=self.timeout,
                allow_redirects=False, **kwargs
            )
        except requests.RequestException as e:
            logger.debug(f"POST failed for {url}: {e}")
            return None

    @staticmethod
    def _build_path_param_url(pp, value):
        """
        Build a URL with a detected path segment replaced by `value`.

        `pp` is a path-parameter dict from the crawler:
        {url, param_index, param_value, segments, ...}.
        """
        segments = list(pp["segments"])
        segments[pp["param_index"]] = quote(str(value), safe="")
        parsed = urlparse(pp["url"])
        return urlunparse(parsed._replace(path="/".join(segments)))


# ─────────────────────────────────────────────────────────────
#  XSS Scanner
# ─────────────────────────────────────────────────────────────

class XSSScanner(BaseModule):
    """
    Reflected XSS detection.

    Injects canary payloads into:
      - URL query parameters
      - HTML form fields (both GET and POST)

    Checks if the payload is reflected unencoded in the response body.
    """

    name = "xss"
    description = "Reflected Cross-Site Scripting (XSS) detection"

    # Payloads designed to detect reflection — not to exploit
    PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
        '"><svg/onload=confirm(1)>',
    ]

    # Server-side template injection probes: (payload, evaluated_marker).
    # We inject an arithmetic expression and look for the *computed* result,
    # so a literal reflection of the payload does not count as a hit.
    # 31337*7 = 219359 — an unlikely-to-appear-naturally marker keeps
    # false positives low (unlike "49", which shows up on real pages).
    TEMPLATE_PROBES = [
        ("{{31337*7}}", "219359"),
        ("${31337*7}", "219359"),
        ("#{31337*7}", "219359"),
        ("<%= 31337*7 %>", "219359"),
    ]

    # Unique canary to check reflection without false positives
    CANARY = "vSc4nX55"

    def scan(self, crawl_result):
        self.findings = []
        logger.info(f"[XSS] Scanning {len(crawl_result.params)} parameterized URLs")

        # 1) Test URL query parameters
        for url, params in crawl_result.params.items():
            self._test_url_params(url, params)

        # 2) Test forms
        logger.info(f"[XSS] Scanning {len(crawl_result.forms)} forms")
        for form in crawl_result.forms:
            self._test_form(form)

        # 3) Test path-based parameters (e.g. /user/123/profile)
        logger.info(f"[XSS] Scanning {len(crawl_result.path_params)} path parameters")
        for pp in crawl_result.path_params:
            self._test_path_param(pp)

        logger.info(f"[XSS] Done. {len(self.findings)} findings.")
        return self.findings

    def _detect(self, fetch, where, url, evidence_suffix=""):
        """
        Drive reflection + template-injection detection through a
        ``fetch(value) -> response`` callable. Appends at most one finding
        for this injection point and returns True if a hit was recorded.
        """
        # Gate: only spend payloads where a harmless canary reflects at all.
        resp = fetch(self.CANARY)
        if resp is None or self.CANARY not in resp.text:
            return False

        # Reflected XSS
        for payload in self.PAYLOADS:
            resp = fetch(payload)
            if resp is not None and payload in resp.text:
                self.findings.append(self._make_finding(
                    severity="HIGH",
                    title=f"Reflected XSS in {where}",
                    description=(
                        f"Input via {where} is reflected in the response "
                        f"without proper encoding/sanitization."
                    ),
                    url=url,
                    evidence=f"Payload: {payload}{evidence_suffix}",
                    remediation=(
                        "Encode all user input before rendering in HTML. "
                        "Use context-aware output encoding. Implement CSP headers."
                    ),
                ))
                return True

        # Server-side template injection (evaluated result, not literal echo)
        for payload, marker in self.TEMPLATE_PROBES:
            resp = fetch(payload)
            if resp is not None and marker in resp.text and payload not in resp.text:
                self.findings.append(self._make_finding(
                    severity="HIGH",
                    title=f"Server-side template injection in {where}",
                    description=(
                        f"Input via {where} is evaluated as a server-side "
                        f"template expression ('{payload}' rendered as '{marker}')."
                    ),
                    url=url,
                    evidence=f"Payload: {payload} -> {marker}{evidence_suffix}",
                    remediation=(
                        "Never pass user input into a template engine as code. "
                        "Use logic-less/sandboxed templates and pass data as "
                        "context variables, not inline expressions."
                    ),
                ))
                return True

        return False

    def _test_url_params(self, url, params):
        """Inject into each query parameter."""
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            def fetch(value, _param=param):
                test_params = {k: v[0] if v else "" for k, v in original_params.items()}
                test_params[_param] = value
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                return self._safe_get(test_url)

            self._detect(fetch, f"query parameter '{param}'", url)

    def _test_form(self, form):
        """Inject into each form field."""
        for inp in form.inputs:
            if inp["type"] in ("hidden", "submit", "button", "image"):
                continue

            def fetch(value, _target=inp["name"]):
                data = {}
                for field in form.inputs:
                    data[field["name"]] = (
                        value if field["name"] == _target
                        else field.get("value", "test")
                    )
                if form.method == "GET":
                    return self._safe_get(form.action, params=data)
                return self._safe_post(form.action, data=data)

            self._detect(
                fetch,
                f"form field '{inp['name']}'",
                form.action,
                evidence_suffix=f" | Form on: {form.page_url}",
            )

    def _test_path_param(self, pp):
        """Inject into a path segment (e.g. the '123' in /user/123/profile)."""
        def fetch(value):
            return self._safe_get(self._build_path_param_url(pp, value))

        self._detect(
            fetch,
            f"path segment '{pp['param_value']}'",
            pp["url"],
            evidence_suffix=f" | Segment index: {pp['param_index']}",
        )


# ─────────────────────────────────────────────────────────────
#  SQL Injection Scanner
# ─────────────────────────────────────────────────────────────

class SQLiScanner(BaseModule):
    """
    Error-based SQL injection detection.

    Sends injection payloads to URL parameters and form fields,
    then checks for database error signatures in the response.
    """

    name = "sqli"
    description = "SQL Injection detection via error-based signatures"

    # Error-based, non-destructive probes only. Stacked/DDL payloads
    # (e.g. DROP TABLE) and time-based blind payloads (WAITFOR DELAY) are
    # intentionally excluded — this module detects via error signatures,
    # so they add no signal while risking damage to the target.
    PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        '" OR "1"="1',
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--",
    ]

    # Database error patterns that indicate SQL injection
    ERROR_SIGNATURES = [
        # MySQL
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"unclosed quotation mark",
        # PostgreSQL
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"unterminated quoted string",
        # MS SQL Server
        r"microsoft.*odbc.*sql server",
        r"unclosed quotation mark after the character string",
        r"\[microsoft\]\[odbc sql server driver\]",
        r"mssql_query\(\)",
        # SQLite
        r"sqlite.*error",
        r"sqlite3\.OperationalError",
        r"near \".*\": syntax error",
        # Oracle
        r"ora-\d{5}",
        r"oracle.*driver.*error",
        r"quoted string not properly terminated",
        # Generic
        r"sql syntax.*error",
        r"syntax error.*sql",
        r"invalid.*query",
        r"sql command not properly ended",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._error_patterns = [
            re.compile(sig, re.IGNORECASE) for sig in self.ERROR_SIGNATURES
        ]

    def scan(self, crawl_result):
        self.findings = []
        logger.info(f"[SQLi] Scanning {len(crawl_result.params)} parameterized URLs")

        # 1) Test URL parameters
        for url, params in crawl_result.params.items():
            self._test_url_params(url, params)

        # 2) Test forms
        logger.info(f"[SQLi] Scanning {len(crawl_result.forms)} forms")
        for form in crawl_result.forms:
            self._test_form(form)

        # 3) Test path-based parameters (e.g. /product/42)
        logger.info(f"[SQLi] Scanning {len(crawl_result.path_params)} path parameters")
        for pp in crawl_result.path_params:
            self._test_path_param(pp)

        logger.info(f"[SQLi] Done. {len(self.findings)} findings.")
        return self.findings

    def _test_path_param(self, pp):
        """Inject SQLi payloads into a path segment."""
        for payload in self.PAYLOADS:
            resp = self._safe_get(self._build_path_param_url(pp, payload))
            if resp is None:
                continue

            error_match = self._check_errors(resp.text)
            if error_match:
                self.findings.append(self._make_finding(
                    severity="CRITICAL",
                    title=f"SQL Injection in path segment '{pp['param_value']}'",
                    description=(
                        f"The path segment '{pp['param_value']}' appears "
                        f"vulnerable to SQL injection. A database error was triggered."
                    ),
                    url=pp["url"],
                    evidence=(
                        f"Payload: {payload} | "
                        f"Segment index: {pp['param_index']} | "
                        f"Error: {error_match}"
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate path input into SQL strings. "
                        "Apply input validation and least-privilege DB access."
                    ),
                ))
                break  # One finding per path parameter

    def _check_errors(self, text):
        """Check response body for SQL error signatures."""
        for pattern in self._error_patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    def _test_url_params(self, url, params):
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            for payload in self.PAYLOADS:
                test_params = {k: v[0] if v else "" for k, v in original_params.items()}
                test_params[param] = payload

                test_url = urlunparse(parsed._replace(
                    query=urlencode(test_params)
                ))
                resp = self._safe_get(test_url)
                if resp is None:
                    continue

                error_match = self._check_errors(resp.text)
                if error_match:
                    self.findings.append(self._make_finding(
                        severity="CRITICAL",
                        title=f"SQL Injection in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' appears vulnerable to "
                            f"SQL injection. A database error was triggered."
                        ),
                        url=url,
                        evidence=(
                            f"Payload: {payload} | "
                            f"Error: {error_match}"
                        ),
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings. "
                            "Apply input validation and least-privilege DB access."
                        ),
                    ))
                    break  # One finding per param

    def _test_form(self, form):
        for inp in form.inputs:
            if inp["type"] in ("hidden", "submit", "button", "image"):
                continue

            for payload in self.PAYLOADS:
                data = {}
                for field in form.inputs:
                    if field["name"] == inp["name"]:
                        data[field["name"]] = payload
                    else:
                        data[field["name"]] = field.get("value", "test")

                if form.method == "GET":
                    resp = self._safe_get(form.action, params=data)
                else:
                    resp = self._safe_post(form.action, data=data)

                if resp is None:
                    continue

                error_match = self._check_errors(resp.text)
                if error_match:
                    self.findings.append(self._make_finding(
                        severity="CRITICAL",
                        title=f"SQL Injection in form field '{inp['name']}'",
                        description=(
                            f"Form at {form.action} is vulnerable to SQL injection "
                            f"via field '{inp['name']}'."
                        ),
                        url=form.action,
                        evidence=(
                            f"Payload: {payload} | "
                            f"Error: {error_match} | "
                            f"Form on: {form.page_url}"
                        ),
                        remediation=(
                            "Use parameterized queries. Apply ORM or query builder. "
                            "Validate and sanitize all form inputs."
                        ),
                    ))
                    break


# ─────────────────────────────────────────────────────────────
#  CSRF Scanner
# ─────────────────────────────────────────────────────────────

class CSRFScanner(BaseModule):
    """
    CSRF detection.

    Checks for:
    1. POST forms that lack CSRF token fields
    2. Wildcard or misconfigured CORS headers
    3. Missing SameSite cookie attributes
    """

    name = "csrf"
    description = "Cross-Site Request Forgery (CSRF) detection"

    # Common CSRF token field names
    CSRF_TOKEN_NAMES = {
        "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
        "_csrf", "_token", "token", "authenticity_token",
        "xsrf", "xsrf_token", "_xsrf", "__requestverificationtoken",
        "antiforgerytoken", "anti-forgery-token",
    }

    def scan(self, crawl_result):
        self.findings = []
        self._seen_cors = set()  # dedup site-wide CORS misconfigurations

        # 1) Check POST forms for CSRF tokens
        logger.info(f"[CSRF] Checking {len(crawl_result.forms)} forms")
        for form in crawl_result.forms:
            if form.method == "POST":
                self._check_form_csrf(form)

        # 2) Check CORS on a sample of crawled pages (config is usually
        #    site-wide, so no need to hit every page)
        logger.info(f"[CSRF] Checking CORS on {len(crawl_result.pages)} pages")
        for page_url in crawl_result.pages[:10]:
            self._check_cors(page_url)

        logger.info(f"[CSRF] Done. {len(self.findings)} findings.")
        return self.findings

    def _check_form_csrf(self, form):
        """Check if a POST form has a CSRF token field."""
        field_names = {inp["name"].lower() for inp in form.inputs if inp["name"]}

        has_csrf = bool(field_names & self.CSRF_TOKEN_NAMES)

        if not has_csrf:
            # Also check for hidden fields with "token" in the name
            has_token_field = any(
                "token" in inp["name"].lower()
                for inp in form.inputs
                if inp["type"] == "hidden" and inp["name"]
            )

            if not has_token_field:
                self.findings.append(self._make_finding(
                    severity="MEDIUM",
                    title="POST form missing CSRF token",
                    description=(
                        f"A POST form at {form.action} does not contain a "
                        f"recognizable CSRF token field."
                    ),
                    url=form.action,
                    evidence=f"Form on page: {form.page_url} | Fields: {list(field_names)}",
                    remediation=(
                        "Add a unique, unpredictable CSRF token to all state-changing forms. "
                        "Use framework-provided CSRF protection (e.g., Django's "
                        "{% csrf_token %}, Rails' authenticity_token)."
                    ),
                ))

    def _check_cors(self, url):
        """Check for wildcard or overly permissive CORS."""
        # Send request with a fake Origin header
        headers = {"Origin": "https://evil-attacker.com"}
        resp = self._safe_get(url, headers=headers)
        if resp is None:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and "wildcard" not in self._seen_cors:
            self._seen_cors.add("wildcard")
            self.findings.append(self._make_finding(
                severity="MEDIUM",
                title="Wildcard CORS policy",
                description=(
                    "The server responds with Access-Control-Allow-Origin: * "
                    "which allows any website to make cross-origin requests."
                ),
                url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation=(
                    "Restrict CORS to specific trusted origins. "
                    "Never use wildcard with credentials."
                ),
            ))
        elif acao == "https://evil-attacker.com" and "reflect" not in self._seen_cors:
            self._seen_cors.add("reflect")
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            self.findings.append(self._make_finding(
                severity=severity,
                title="CORS reflects arbitrary Origin",
                description=(
                    "The server reflects the attacker-supplied Origin header "
                    "in Access-Control-Allow-Origin, meaning any site can "
                    "make authenticated cross-origin requests."
                ),
                url=url,
                evidence=(
                    f"Sent Origin: https://evil-attacker.com | "
                    f"ACAO: {acao} | ACAC: {acac}"
                ),
                remediation=(
                    "Validate the Origin header against a whitelist of "
                    "trusted domains. Never reflect arbitrary origins."
                ),
            ))


# ─────────────────────────────────────────────────────────────
#  Open Redirect Scanner
# ─────────────────────────────────────────────────────────────

class OpenRedirectScanner(BaseModule):
    """
    Open Redirect detection.

    Identifies URL parameters that look like redirect targets and
    tests whether the application follows them to an external URL.
    """

    name = "open_redirect"
    description = "Unvalidated redirect/forward detection"

    # Parameter names commonly used for redirects
    REDIRECT_PARAMS = {
        "url", "redirect", "next", "return", "returnto", "redir",
        "destination", "dest", "go", "target", "link", "out",
        "continue", "return_url", "redirect_url", "redirect_uri",
        "callback", "forward", "ref", "returnurl",
    }

    # External URLs to test redirection
    TEST_URLS = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com/%2F%2E%2E",
        "/\\evil.com",
        "https:evil.com",
    ]

    def scan(self, crawl_result):
        self.findings = []
        logger.info("[OpenRedirect] Scanning for open redirects")

        # Check parameterized URLs for redirect-like params
        for url, params in crawl_result.params.items():
            suspicious = {p for p in params if p.lower() in self.REDIRECT_PARAMS}
            for param in suspicious:
                self._test_redirect(url, param)

        # Also scan all forms for redirect fields
        for form in crawl_result.forms:
            for inp in form.inputs:
                if inp["name"].lower() in self.REDIRECT_PARAMS:
                    self._test_form_redirect(form, inp["name"])

        logger.info(f"[OpenRedirect] Done. {len(self.findings)} findings.")
        return self.findings

    def _test_redirect(self, url, param):
        """Test a URL parameter for open redirect."""
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query, keep_blank_values=True)

        for test_url in self.TEST_URLS:
            test_params = {k: v[0] if v else "" for k, v in original_params.items()}
            test_params[param] = test_url

            full_url = urlunparse(parsed._replace(
                query=urlencode(test_params)
            ))
            resp = self._safe_get(full_url)
            if resp is None:
                continue

            # Check if we got redirected to the evil URL
            location = resp.headers.get("Location", "")
            if self._is_external_redirect(location):
                self.findings.append(self._make_finding(
                    severity="MEDIUM",
                    title=f"Open redirect via parameter '{param}'",
                    description=(
                        f"The parameter '{param}' can redirect users to "
                        f"an arbitrary external URL."
                    ),
                    url=url,
                    evidence=(
                        f"Payload: {test_url} | "
                        f"Location header: {location}"
                    ),
                    remediation=(
                        "Validate redirect URLs against a whitelist of allowed "
                        "destinations. Use relative paths instead of full URLs. "
                        "Never redirect to user-supplied URLs without validation."
                    ),
                ))
                break

    def _test_form_redirect(self, form, field_name):
        """Test a form field for open redirect."""
        for test_url in self.TEST_URLS:
            data = {}
            for field in form.inputs:
                if field["name"] == field_name:
                    data[field["name"]] = test_url
                else:
                    data[field["name"]] = field.get("value", "test")

            if form.method == "GET":
                resp = self._safe_get(form.action, params=data)
            else:
                resp = self._safe_post(form.action, data=data)

            if resp is None:
                continue

            location = resp.headers.get("Location", "")
            if self._is_external_redirect(location):
                self.findings.append(self._make_finding(
                    severity="MEDIUM",
                    title=f"Open redirect via form field '{field_name}'",
                    description=(
                        f"Form at {form.action} can redirect to an external "
                        f"URL via field '{field_name}'."
                    ),
                    url=form.action,
                    evidence=(
                        f"Payload: {test_url} | "
                        f"Location: {location} | "
                        f"Form on: {form.page_url}"
                    ),
                    remediation=(
                        "Validate redirect destinations. Use a whitelist of "
                        "allowed redirect targets."
                    ),
                ))
                break

    @staticmethod
    def _is_external_redirect(location):
        """Check if a Location header points to an external domain."""
        if not location:
            return False
        # Check for known evil.com patterns
        return ("evil.com" in location.lower())


# ─────────────────────────────────────────────────────────────
#  Security Headers & Auth Scanner
# ─────────────────────────────────────────────────────────────

class HeaderScanner(BaseModule):
    """
    Security header and authentication checker.

    Checks for:
    1. Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
    2. Insecure cookie flags (missing Secure, HttpOnly, SameSite)
    3. HTTP (non-HTTPS) usage
    4. Server information disclosure
    """

    name = "headers"
    description = "Security headers, cookie flags, and transport security"

    # Required security headers and their purpose
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "CSP prevents XSS and data injection attacks",
            "remediation": (
                "Implement a strict Content-Security-Policy. Start with "
                "default-src 'self' and progressively allow needed sources."
            ),
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "HSTS enforces HTTPS connections",
            "remediation": (
                "Add Strict-Transport-Security header with max-age of at "
                "least 31536000 (1 year). Include includeSubDomains."
            ),
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Prevents clickjacking by controlling framing",
            "remediation": (
                "Set X-Frame-Options to DENY or SAMEORIGIN. "
                "Also set frame-ancestors in CSP."
            ),
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Prevents MIME-type sniffing attacks",
            "remediation": "Set X-Content-Type-Options: nosniff",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": "Legacy XSS filter (useful for older browsers)",
            "remediation": "Set X-XSS-Protection: 1; mode=block",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls referrer information leakage",
            "remediation": (
                "Set Referrer-Policy to strict-origin-when-cross-origin "
                "or no-referrer."
            ),
        },
    }

    def scan(self, crawl_result):
        self.findings = []
        # Header/cookie/server issues are site-wide, so we sample a few pages
        # but deduplicate findings by a stable key to avoid reporting the same
        # missing header 5 times.
        self._seen = set()
        logger.info(f"[Headers] Checking security headers on {len(crawl_result.pages)} pages")

        # Only need to check a sample of pages (headers are usually site-wide)
        pages_to_check = crawl_result.pages[:5]  # Check first 5 pages

        for url in pages_to_check:
            resp = self._safe_get(url)
            if resp is None:
                continue

            self._check_security_headers(url, resp)
            self._check_cookies(url, resp)
            self._check_server_disclosure(url, resp)

        # Check HTTPS usage
        self._check_https(crawl_result)

        logger.info(f"[Headers] Done. {len(self.findings)} findings.")
        return self.findings

    def _add_once(self, key, finding):
        """Append a finding only if an equivalent one hasn't been recorded."""
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)

    def _check_security_headers(self, url, response):
        """Check for missing security headers."""
        present = {k.lower() for k in response.headers.keys()}
        for header_name, info in self.SECURITY_HEADERS.items():
            if header_name.lower() not in present:
                self._add_once(
                    ("header", header_name),
                    self._make_finding(
                        severity=info["severity"],
                        title=f"Missing {header_name} header",
                        description=info["description"],
                        url=url,
                        evidence=f"Header '{header_name}' not present in response",
                        remediation=info["remediation"],
                    ),
                )

    def _check_cookies(self, url, response):
        """Check cookies for missing security flags."""
        for cookie in response.cookies:
            # http.cookiejar stores non-standard attributes (HttpOnly, SameSite)
            # in `_rest`; keys preserve original casing, so compare lowercased.
            rest = {k.lower() for k in getattr(cookie, "_rest", {}).keys()}
            issues = []

            if not cookie.secure:
                issues.append("Missing 'Secure' flag")
            if "httponly" not in rest:
                issues.append("Missing 'HttpOnly' flag")
            if "samesite" not in rest:
                issues.append("Missing 'SameSite' attribute")

            if issues:
                self._add_once(
                    ("cookie", cookie.name),
                    self._make_finding(
                        severity="MEDIUM" if not cookie.secure else "LOW",
                        title=f"Insecure cookie: '{cookie.name}'",
                        description=(
                            f"Cookie '{cookie.name}' has security issues: "
                            f"{', '.join(issues)}"
                        ),
                        url=url,
                        evidence=f"Cookie: {cookie.name} | Issues: {', '.join(issues)}",
                        remediation=(
                            "Set Secure, HttpOnly, and SameSite=Strict (or Lax) "
                            "on all session/auth cookies."
                        ),
                    ),
                )

    def _check_server_disclosure(self, url, response):
        """Check for server version disclosure."""
        server = response.headers.get("Server", "")
        x_powered = response.headers.get("X-Powered-By", "")

        if server and any(c.isdigit() for c in server):
            self._add_once(
                ("server", server),
                self._make_finding(
                    severity="INFO",
                    title="Server version disclosure",
                    description=(
                        f"The Server header reveals version information: '{server}'"
                    ),
                    url=url,
                    evidence=f"Server: {server}",
                    remediation="Remove or obfuscate the Server header version.",
                ),
            )

        if x_powered:
            self._add_once(
                ("x-powered-by", x_powered),
                self._make_finding(
                    severity="INFO",
                    title="Technology disclosure via X-Powered-By",
                    description=(
                        f"The X-Powered-By header reveals: '{x_powered}'"
                    ),
                    url=url,
                    evidence=f"X-Powered-By: {x_powered}",
                    remediation="Remove the X-Powered-By header.",
                ),
            )

    def _check_https(self, crawl_result):
        """Check if the target uses HTTPS."""
        for url in crawl_result.pages:
            if urlparse(url).scheme == "http":
                self.findings.append(self._make_finding(
                    severity="HIGH",
                    title="Site served over HTTP (not HTTPS)",
                    description=(
                        "The application is accessible over unencrypted HTTP. "
                        "All traffic including credentials can be intercepted."
                    ),
                    url=url,
                    evidence=f"URL scheme: http",
                    remediation=(
                        "Enforce HTTPS site-wide. Redirect all HTTP to HTTPS. "
                        "Enable HSTS with a long max-age."
                    ),
                ))
                break  # One finding is enough


# ─────────────────────────────────────────────────────────────
#  Path Traversal / Local File Inclusion Scanner
# ─────────────────────────────────────────────────────────────

class PathTraversalScanner(BaseModule):
    """
    Path Traversal / Local File Inclusion (LFI) detection.

    Injects ``../`` traversal sequences into URL parameters, form fields,
    and path segments, then checks whether the response contains the
    contents of a well-known system file (``/etc/passwd`` on *nix,
    ``win.ini`` on Windows). Only the *presence of the file's signature*
    counts as a hit, so a literal echo of the payload is not a false positive.
    """

    name = "path_traversal"
    description = "Path Traversal / Local File Inclusion (LFI) detection"

    # Parameter names commonly used to reference files on disk.
    FILE_PARAMS = {
        "file", "filename", "filepath", "path", "page", "template",
        "doc", "document", "folder", "root", "pg", "style", "pdf",
        "img", "image", "download", "read", "load", "view", "content",
        "include", "inc", "locate", "show", "site", "type", "dir",
    }

    # Traversal payloads. Depth up to 8 covers most deployments; the
    # encoded and null-byte variants defeat naive ``../`` stripping and
    # extension-append filters seen in older PHP apps.
    PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "../../../../etc/passwd%00",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "C:\\windows\\win.ini",
    ]

    # Signatures proving a real system file was read (not just reflected).
    SIGNATURES = [
        re.compile(r"root:.*:0:0:", re.IGNORECASE),      # /etc/passwd line
        re.compile(r"daemon:.*:/usr/sbin", re.IGNORECASE),
        re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE),  # win.ini
        re.compile(r"for 16-bit app support", re.IGNORECASE),  # win.ini
    ]

    def scan(self, crawl_result):
        self.findings = []
        logger.info(f"[PathTraversal] Scanning {len(crawl_result.params)} parameterized URLs")

        for url, params in crawl_result.params.items():
            self._test_url_params(url, params)

        logger.info(f"[PathTraversal] Scanning {len(crawl_result.forms)} forms")
        for form in crawl_result.forms:
            self._test_form(form)

        logger.info(f"[PathTraversal] Scanning {len(crawl_result.path_params)} path parameters")
        for pp in crawl_result.path_params:
            self._test_path_param(pp)

        logger.info(f"[PathTraversal] Done. {len(self.findings)} findings.")
        return self.findings

    def _match_signature(self, text):
        for sig in self.SIGNATURES:
            m = sig.search(text)
            if m:
                return m.group(0)[:80]
        return None

    def _report(self, where, url, payload, marker, evidence_suffix=""):
        self.findings.append(self._make_finding(
            severity="HIGH",
            title=f"Path traversal / LFI in {where}",
            description=(
                f"Input via {where} is used to build a file path without "
                f"validation, allowing arbitrary local files to be read."
            ),
            url=url,
            evidence=f"Payload: {payload} | Leaked: {marker}{evidence_suffix}",
            remediation=(
                "Never pass user input directly to file system APIs. Resolve "
                "the canonical path and confirm it stays within an allowed base "
                "directory. Use an allow-list of filenames/IDs and reject "
                "path separators and '..' sequences."
            ),
        ))

    def _test_url_params(self, url, params):
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query, keep_blank_values=True)

        # Prioritize file-ish param names, but fall back to testing all
        # params since the naming convention is only a hint.
        ordered = sorted(params, key=lambda p: p.lower() not in self.FILE_PARAMS)

        for param in ordered:
            for payload in self.PAYLOADS:
                test_params = {k: v[0] if v else "" for k, v in original_params.items()}
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                resp = self._safe_get(test_url)
                if resp is None:
                    continue
                marker = self._match_signature(resp.text)
                if marker:
                    self._report(f"query parameter '{param}'", url, payload, marker)
                    break  # One finding per parameter

    def _test_form(self, form):
        for inp in form.inputs:
            if inp["type"] in ("hidden", "submit", "button", "image"):
                continue
            for payload in self.PAYLOADS:
                data = {}
                for field in form.inputs:
                    data[field["name"]] = (
                        payload if field["name"] == inp["name"]
                        else field.get("value", "test")
                    )
                if form.method == "GET":
                    resp = self._safe_get(form.action, params=data)
                else:
                    resp = self._safe_post(form.action, data=data)
                if resp is None:
                    continue
                marker = self._match_signature(resp.text)
                if marker:
                    self._report(
                        f"form field '{inp['name']}'", form.action, payload, marker,
                        evidence_suffix=f" | Form on: {form.page_url}",
                    )
                    break

    def _test_path_param(self, pp):
        for payload in self.PAYLOADS:
            resp = self._safe_get(self._build_path_param_url(pp, payload))
            if resp is None:
                continue
            marker = self._match_signature(resp.text)
            if marker:
                self._report(
                    f"path segment '{pp['param_value']}'", pp["url"], payload, marker,
                    evidence_suffix=f" | Segment index: {pp['param_index']}",
                )
                break


# ─────────────────────────────────────────────────────────────
#  Module Registry
# ─────────────────────────────────────────────────────────────

# Maps CLI names to module classes
MODULE_REGISTRY = {
    "xss": XSSScanner,
    "sqli": SQLiScanner,
    "csrf": CSRFScanner,
    "open_redirect": OpenRedirectScanner,
    "path_traversal": PathTraversalScanner,
    "headers": HeaderScanner,
}

ALL_MODULE_NAMES = list(MODULE_REGISTRY.keys())


def get_module(name, session=None, timeout=10):
    """Instantiate a module by name."""
    cls = MODULE_REGISTRY.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown module: '{name}'. "
            f"Available: {', '.join(ALL_MODULE_NAMES)}"
        )
    return cls(session=session, timeout=timeout)
