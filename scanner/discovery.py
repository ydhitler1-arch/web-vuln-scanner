"""
Discovery Module
================
Pre-crawl reconnaissance to expand the attack surface beyond
what the BFS crawler finds in HTML alone.

Components:
    - DirectoryProber      — probes common paths, admin panels, search endpoints
    - SubdomainScanner     — checks common subdomain prefixes (www, api, admin, etc.)
    - TechFingerprinter    — detects CMS, framework, and server tech from signatures
    - PathParamDetector    — identifies path-based parameters (/user/123/profile)
"""

import re
import random
import string
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urlencode

import requests

logger = logging.getLogger("vulnscan.discovery")


# ─────────────────────────────────────────────────────────────
#  Directory / Path Prober
# ─────────────────────────────────────────────────────────────

class DirectoryProber:
    """
    Probes a target for common endpoints that the crawler might miss
    (admin panels, login pages, search forms, API roots, config files).

    Returns discovered URLs grouped by category.
    """

    # Common paths organized by category
    PROBE_PATHS = {
        "admin_panels": [
            "/admin", "/admin/", "/administrator", "/administrator/",
            "/admin/login", "/admin/dashboard",
            "/wp-admin", "/wp-admin/", "/wp-login.php",
            "/cpanel", "/cpanel/", "/dashboard", "/dashboard/",
            "/manage", "/management", "/panel",
            "/phpmyadmin", "/phpmyadmin/",
            "/adminer.php", "/adminer",
        ],
        "login_pages": [
            "/login", "/login/", "/signin", "/sign-in",
            "/user/login", "/account/login", "/auth/login",
            "/accounts/login", "/member/login",
            "/register", "/signup", "/sign-up",
            "/forgot-password", "/reset-password",
        ],
        "search_endpoints": [
            "/search?q=test",
            "/search?query=test",
            "/search?s=test",
            "/?s=test",
            "/?q=test",
            "/?search=test",
            "/?query=test",
            "/find?q=test",
            "/results?q=test",
        ],
        "api_endpoints": [
            "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
            "/rest", "/rest/", "/graphql", "/graphql/",
            "/api/users", "/api/config", "/api/status", "/api/health",
            "/v1/", "/v2/", "/v3/",
            "/json", "/ajax",
            "/.well-known/", "/.well-known/openid-configuration",
        ],
        "parameterized_pages": [
            "/index.php?id=1",
            "/page.php?id=1",
            "/view.php?id=1",
            "/item.php?id=1",
            "/product.php?id=1",
            "/article.php?id=1",
            "/news.php?id=1",
            "/category.php?id=1",
            "/user.php?id=1",
            "/profile.php?id=1",
            "/download.php?file=test",
            "/redirect.php?url=test",
            "/page?id=1",
            "/post?id=1",
            "/?id=1",
            "/?page=1",
            "/?p=1",
            "/?cat=1",
        ],
        "sensitive_files": [
            "/robots.txt",
            "/sitemap.xml",
            "/.env",
            "/.git/config",
            "/.git/HEAD",
            "/config.php",
            "/config.yml",
            "/wp-config.php.bak",
            "/.htaccess",
            "/web.config",
            "/crossdomain.xml",
            "/server-status",
            "/server-info",
            "/.DS_Store",
            "/backup.zip",
            "/backup.sql",
            "/debug", "/debug/",
            "/info.php", "/phpinfo.php",
            "/test.php",
            "/elmah.axd",
            "/trace.axd",
        ],
        "common_pages": [
            "/about", "/about-us", "/contact", "/contact-us",
            "/faq", "/help", "/support",
            "/terms", "/terms-of-service", "/privacy", "/privacy-policy",
            "/blog", "/news", "/sitemap",
            "/404", "/error",
        ],
    }

    def __init__(self, target_url, session=None, timeout=5, max_workers=20):
        # Probe from the origin root (scheme://host), not the given path.
        # Otherwise a target like ".../index.html" yields nonsense probes
        # such as ".../index.html/wp-admin".
        parsed = urlparse(target_url)
        if parsed.netloc:
            self.target_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            self.target_url = target_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self.max_workers = max_workers  # concurrent probe requests
        self.discovered = {}  # category -> list of {url, status, content_type, size}
        self.soft_404 = None  # baseline for sites that return 200 for anything

    @staticmethod
    def _random_path():
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        return f"/{token}-nonexistent-{token}"

    def _establish_baseline(self):
        """
        Detect soft-404s: sites that answer 200 (with a generic page) for
        paths that don't exist. Without this, every probed path looks like a
        hit. We record the size/content-type of a known-bad path and later
        discard 200 responses that look the same.
        """
        try:
            resp = self.session.get(
                self.target_url + self._random_path(),
                timeout=self.timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return

        if resp.status_code == 200:
            self.soft_404 = {
                "size": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
            }
            logger.info(
                f"[Discovery] Soft-404 detected (random path returned 200, "
                f"{self.soft_404['size']} bytes). Filtering look-alike responses."
            )

    def _looks_like_soft_404(self, resp):
        """True if a 200 response is indistinguishable from the soft-404 baseline."""
        if not self.soft_404:
            return False
        if resp.headers.get("Content-Type", "") != self.soft_404["content_type"]:
            return False
        base = self.soft_404["size"]
        size = len(resp.content)
        if base == 0:
            return size == 0
        return abs(size - base) / base < 0.05  # within 5% → same generic page

    def probe(self, categories=None):
        """
        Probe the target for common paths.

        Parameters
        ----------
        categories : list, optional
            Which categories to probe. Default: all.

        Returns
        -------
        dict : category -> list of discovered endpoints
        """
        if categories is None:
            categories = list(self.PROBE_PATHS.keys())

        # Learn what a "not found" looks like before probing real paths.
        self._establish_baseline()

        # Flatten to independent (category, path) tasks — these have no
        # ordering dependency, so we fan them out across a thread pool.
        tasks = [
            (category, path)
            for category in categories
            for path in self.PROBE_PATHS.get(category, [])
        ]
        total_paths = len(tasks)
        logger.info(
            f"[Discovery] Probing {total_paths} common paths across "
            f"{len(categories)} categories ({self.max_workers} workers)"
        )

        checked = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_cat = {
                executor.submit(self._probe_one, path): category
                for category, path in tasks
            }
            for future in as_completed(future_to_cat):
                checked += 1
                category = future_to_cat[future]
                hit = future.result()
                if hit:
                    self.discovered.setdefault(category, []).append(hit)
                if checked % 20 == 0:
                    logger.info(f"[Discovery] Probed {checked}/{total_paths} paths...")

        total_found = sum(len(v) for v in self.discovered.values())
        logger.info(f"[Discovery] Probing complete. {total_found} endpoints found across {len(self.discovered)} categories.")
        return self.discovered

    def _probe_one(self, path):
        """Probe a single path. Returns a hit dict, or None if not interesting."""
        url = self.target_url + path
        try:
            resp = self.session.get(
                url, timeout=self.timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return None

        # Consider it a hit if we get a 200 response (not a generic 404 page)
        if resp.status_code == 200:
            if self._looks_like_soft_404(resp):
                return None  # generic catch-all page, not a real endpoint
            return {
                "url": resp.url,  # Use final URL after redirects
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "size": len(resp.content),
                "path": path,
            }
        elif resp.status_code in (301, 302, 303, 307, 308):
            return {
                "url": url,
                "status": resp.status_code,
                "redirect_to": resp.headers.get("Location", ""),
                "path": path,
            }
        elif resp.status_code == 403:
            # Forbidden = exists but protected
            return {
                "url": url,
                "status": 403,
                "note": "Exists but access forbidden",
                "path": path,
            }
        return None

    def get_injectable_urls(self):
        """Return URLs that have query parameters (potential injection points)."""
        urls = []
        for category, hits in self.discovered.items():
            for hit in hits:
                if "?" in hit.get("url", ""):
                    urls.append(hit["url"])
        return urls

    def get_all_urls(self):
        """Return all discovered URLs for feeding into the crawler."""
        urls = []
        for category, hits in self.discovered.items():
            for hit in hits:
                url = hit.get("url", "")
                if url:
                    urls.append(url)
        return urls

    def summary(self):
        result = {}
        for category, hits in self.discovered.items():
            result[category] = len(hits)
        result["total_discovered"] = sum(result.values())
        return result


# ─────────────────────────────────────────────────────────────
#  Subdomain Scanner
# ─────────────────────────────────────────────────────────────

class SubdomainScanner:
    """
    Checks common subdomain prefixes by attempting HTTP connections.
    """

    COMMON_SUBDOMAINS = [
        "www", "api", "admin", "mail", "webmail",
        "dev", "staging", "stage", "test", "testing",
        "beta", "demo", "sandbox",
        "blog", "shop", "store", "app",
        "cdn", "static", "assets", "media", "img", "images",
        "m", "mobile",
        "portal", "secure", "auth", "sso", "login",
        "dashboard", "panel", "manage",
        "docs", "doc", "wiki", "help", "support",
        "status", "monitor",
        "old", "legacy", "backup", "bak",
        "db", "database", "sql", "mysql",
        "ftp", "sftp", "vpn",
        "git", "svn", "repo",
        "jenkins", "ci", "build",
        "grafana", "kibana", "elastic",
    ]

    def __init__(self, target_url, session=None, timeout=3, max_workers=20):
        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme or "https"
        self.session = session or requests.Session()
        self.timeout = timeout
        self.max_workers = max_workers  # concurrent subdomain checks
        self.wildcard = None  # baseline for wildcard-DNS / catch-all hosts

        # Extract root domain (strip www. if present)
        self.root_domain = self.base_domain
        if self.root_domain.startswith("www."):
            self.root_domain = self.root_domain[4:]

    def _establish_baseline(self):
        """
        Detect wildcard DNS / catch-all hosting: a random nonexistent
        subdomain that still answers. If found, we record its fingerprint so
        real look-alike subdomains aren't reported as false 'live' hits.
        """
        token = "".join(random.choices(string.ascii_lowercase, k=12))
        host = f"{token}-nonexistent.{self.root_domain}"
        try:
            resp = self.session.get(
                f"{self.scheme}://{host}", timeout=self.timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return

        self.wildcard = {
            "status": resp.status_code,
            "title": self._extract_title(resp.text),
            "size": len(resp.content),
        }
        logger.info(
            "[Subdomain] Wildcard/catch-all host detected; "
            "filtering look-alike subdomains."
        )

    def _matches_wildcard(self, resp):
        """True if a subdomain response is indistinguishable from the wildcard baseline."""
        if not self.wildcard:
            return False
        if resp.status_code != self.wildcard["status"]:
            return False
        title = self._extract_title(resp.text)
        if self.wildcard["title"] and title == self.wildcard["title"]:
            return True
        base = self.wildcard["size"]
        size = len(resp.content)
        if base == 0:
            return size == 0
        return abs(size - base) / base < 0.05

    def _check_one(self, sub):
        """Check a single subdomain. Returns a live-host dict, or None."""
        hostname = f"{sub}.{self.root_domain}"
        url = f"{self.scheme}://{hostname}"
        try:
            resp = self.session.get(
                url, timeout=self.timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return None

        if self._matches_wildcard(resp):
            logger.debug(f"[Subdomain] {hostname} matches wildcard baseline; skipping")
            return None

        return {
            "subdomain": hostname,
            "url": url,
            "status": resp.status_code,
            "server": resp.headers.get("Server", ""),
            "title": self._extract_title(resp.text),
        }

    def scan(self):
        """
        Check common subdomains. Returns list of live subdomains.
        """
        logger.info(
            f"[Subdomain] Scanning {len(self.COMMON_SUBDOMAINS)} subdomains "
            f"for {self.root_domain} ({self.max_workers} workers)"
        )

        # Detect wildcard DNS before trusting any 'live' result.
        self._establish_baseline()

        # Each subdomain check is independent → fan out across a thread pool.
        subs = [s for s in self.COMMON_SUBDOMAINS
                if f"{s}.{self.root_domain}" != self.base_domain]

        live = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for result in executor.map(self._check_one, subs):
                if result:
                    live.append(result)
                    logger.info(f"[Subdomain] LIVE: {result['subdomain']} ({result['status']})")

        logger.info(f"[Subdomain] Found {len(live)} live subdomains")
        return live

    @staticmethod
    def _extract_title(html):
        """Extract <title> from HTML."""
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ""


# ─────────────────────────────────────────────────────────────
#  Technology Fingerprinter
# ─────────────────────────────────────────────────────────────

class TechFingerprinter:
    """
    Identifies the technology stack of a web application by checking:
    - HTTP response headers
    - HTML meta tags and patterns
    - Cookie names
    - URL patterns and file extensions
    """

    # Signatures: (name, check_type, pattern, details)
    SIGNATURES = [
        # CMS
        ("WordPress", "html", r"/wp-content/|/wp-includes/|wp-json", "WordPress CMS"),
        ("WordPress", "header", r"X-Powered-By.*WordPress", "WordPress CMS"),
        ("WordPress", "meta", r'name=["\']generator["\'].*WordPress', "WordPress CMS"),
        ("Drupal", "header", r"X-Drupal-Cache|X-Generator.*Drupal", "Drupal CMS"),
        ("Drupal", "html", r"/sites/default/files|drupal\.js|Drupal\.settings", "Drupal CMS"),
        ("Joomla", "html", r"/media/jui/|/components/com_|joomla", "Joomla CMS"),
        ("Joomla", "meta", r'name=["\']generator["\'].*Joomla', "Joomla CMS"),
        ("Shopify", "html", r"cdn\.shopify\.com|Shopify\.theme", "Shopify"),
        ("Wix", "html", r"static\.wixstatic\.com|wix-code", "Wix"),
        ("Squarespace", "html", r"squarespace\.com|sqsp", "Squarespace"),

        # Frameworks
        ("Laravel", "cookie", r"laravel_session", "Laravel PHP Framework"),
        ("Django", "cookie", r"csrftoken", "Django Python Framework"),
        ("Django", "html", r"csrfmiddlewaretoken", "Django Python Framework"),
        ("Rails", "cookie", r"_.*_session", "Ruby on Rails"),
        ("Rails", "header", r"X-Runtime|X-Request-Id", "Ruby on Rails"),
        ("Express", "header", r"X-Powered-By.*Express", "Express.js (Node.js)"),
        ("ASP.NET", "header", r"X-AspNet-Version|X-AspNetMvc-Version", "ASP.NET"),
        ("ASP.NET", "cookie", r"ASP\.NET_SessionId|\.AspNetCore", "ASP.NET"),
        ("Spring", "header", r"X-Application-Context", "Spring Framework (Java)"),
        ("Next.js", "header", r"x-nextjs|X-Powered-By.*Next\.js", "Next.js"),
        ("Next.js", "html", r"__NEXT_DATA__|_next/static", "Next.js"),
        ("Nuxt.js", "html", r"__NUXT__|_nuxt/", "Nuxt.js"),
        ("React", "html", r"react-root|__react|reactroot|data-reactid", "React"),
        ("Angular", "html", r"ng-version=|ng-app|angular\.js", "Angular"),
        ("Vue.js", "html", r"v-cloak|v-bind|data-v-|vue\.js|Vue\.config", "Vue.js"),

        # Servers
        ("Nginx", "header", r"Server.*nginx", "Nginx web server"),
        ("Apache", "header", r"Server.*Apache", "Apache web server"),
        ("IIS", "header", r"Server.*IIS|Server.*Microsoft", "Microsoft IIS"),
        ("LiteSpeed", "header", r"Server.*LiteSpeed", "LiteSpeed web server"),
        ("Cloudflare", "header", r"Server.*cloudflare|cf-ray", "Cloudflare CDN/WAF"),
        ("AWS", "header", r"x-amz-|Server.*AmazonS3|Server.*awselb", "AWS"),

        # Languages
        ("PHP", "header", r"X-Powered-By.*PHP", "PHP"),
        ("PHP", "url", r"\.php", "PHP"),
        ("ASP", "url", r"\.aspx?|\.asmx", "ASP/ASP.NET"),
        ("JSP", "url", r"\.jsp|\.do|\.action", "Java (JSP/Servlet)"),
        ("Python", "header", r"X-Powered-By.*(Python|Gunicorn|uWSGI)", "Python"),

        # Security
        ("WAF-ModSecurity", "header", r"ModSecurity|NOYB", "ModSecurity WAF"),
        ("WAF-Cloudflare", "header", r"cf-ray|__cfduid", "Cloudflare WAF"),
        ("WAF-Sucuri", "header", r"X-Sucuri|sucuri", "Sucuri WAF"),
        ("WAF-Akamai", "header", r"X-Akamai|AkamaiGHost", "Akamai WAF/CDN"),
    ]

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.detected = {}  # tech_name -> {details, evidence}

    def fingerprint(self, target_url, crawled_pages=None):
        """
        Fingerprint the target. Checks the main page plus optionally
        any crawled pages.

        Returns dict of detected technologies.
        """
        logger.info(f"[Fingerprint] Scanning {target_url}")

        urls_to_check = [target_url]
        if crawled_pages:
            urls_to_check.extend(crawled_pages[:3])  # Check a few more

        for url in urls_to_check:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            self._check_signatures(url, resp)

        logger.info(f"[Fingerprint] Detected {len(self.detected)} technologies")
        return self.detected

    def _check_signatures(self, url, response):
        """Run all signature checks against a response."""
        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        cookies_str = " ".join(c.name for c in response.cookies)
        html = response.text[:50000]  # Limit HTML check size

        for name, check_type, pattern, details in self.SIGNATURES:
            if name in self.detected:
                continue  # Already found

            try:
                if check_type == "header" and re.search(pattern, headers_str, re.IGNORECASE):
                    match = re.search(pattern, headers_str, re.IGNORECASE)
                    self.detected[name] = {
                        "details": details,
                        "evidence": f"Header match: {match.group(0)[:100]}",
                        "url": url,
                    }
                elif check_type == "html" and re.search(pattern, html, re.IGNORECASE):
                    match = re.search(pattern, html, re.IGNORECASE)
                    self.detected[name] = {
                        "details": details,
                        "evidence": f"HTML match: {match.group(0)[:100]}",
                        "url": url,
                    }
                elif check_type == "cookie" and re.search(pattern, cookies_str, re.IGNORECASE):
                    self.detected[name] = {
                        "details": details,
                        "evidence": f"Cookie match: {pattern}",
                        "url": url,
                    }
                elif check_type == "meta" and re.search(pattern, html, re.IGNORECASE):
                    match = re.search(pattern, html, re.IGNORECASE)
                    self.detected[name] = {
                        "details": details,
                        "evidence": f"Meta tag: {match.group(0)[:100]}",
                        "url": url,
                    }
                elif check_type == "url" and re.search(pattern, url, re.IGNORECASE):
                    self.detected[name] = {
                        "details": details,
                        "evidence": f"URL pattern: {pattern}",
                        "url": url,
                    }
            except re.error:
                continue

    def get_tech_list(self):
        """Return a simple list of detected technology names."""
        return list(self.detected.keys())

    def summary(self):
        return {name: info["details"] for name, info in self.detected.items()}


# ─────────────────────────────────────────────────────────────
#  Path Parameter Detector
# ─────────────────────────────────────────────────────────────

class PathParamDetector:
    """
    Detects path-based parameters in URLs like:
      /user/123/profile  → 123 is a parameter
      /article/some-slug → some-slug might be injectable
      /api/v1/items/42   → 42 is a parameter

    Generates testable URLs by replacing detected path params with payloads.
    """

    # Patterns that suggest a path segment is a parameter
    PARAM_PATTERNS = [
        re.compile(r"/(\d+)(?:/|$)"),               # Numeric IDs: /123/
        re.compile(r"/([0-9a-f]{8,})(?:/|$)", re.I), # Hex IDs / UUIDs
        re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-)", re.I),  # UUID prefix
    ]

    # Path segments that are likely parameters (after these keywords)
    PARAM_KEYWORDS = {
        "user", "users", "profile", "account",
        "item", "items", "product", "products",
        "article", "articles", "post", "posts",
        "page", "pages", "category", "categories",
        "order", "orders", "invoice",
        "id", "view", "edit", "delete", "show",
        "download", "file", "doc", "document",
    }

    def __init__(self):
        self.parameterized = []  # list of {url, param_index, param_value, base_url}

    def detect(self, urls):
        """
        Scan a list of URLs for path-based parameters.

        Returns list of detected parameterized paths with their positions.
        """
        seen = set()

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.rstrip("/")
            segments = path.split("/")

            for i, segment in enumerate(segments):
                if not segment:
                    continue

                is_param = False
                reason = ""

                # Check numeric patterns
                for pattern in self.PARAM_PATTERNS:
                    if pattern.search("/" + segment + "/"):
                        is_param = True
                        reason = "numeric/id pattern"
                        break

                # Check if previous segment is a keyword
                if not is_param and i > 0:
                    prev = segments[i - 1].lower()
                    if prev in self.PARAM_KEYWORDS:
                        is_param = True
                        reason = f"follows keyword '{prev}'"

                if is_param:
                    key = (url, i)
                    if key not in seen:
                        seen.add(key)
                        self.parameterized.append({
                            "url": url,
                            "param_index": i,
                            "param_value": segment,
                            "reason": reason,
                            "segments": segments,
                        })

        logger.info(f"[PathParam] Detected {len(self.parameterized)} path parameters in {len(urls)} URLs")
        return self.parameterized

    def generate_test_urls(self, url, param_index, segments, payload):
        """Generate a URL with a path segment replaced by a payload."""
        new_segments = list(segments)
        new_segments[param_index] = payload
        parsed = urlparse(url)
        new_path = "/".join(new_segments)
        return f"{parsed.scheme}://{parsed.netloc}{new_path}"

    def get_injectable_paths(self):
        """Return path parameter info for scanner modules."""
        return self.parameterized
