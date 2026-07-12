"""
BFS Web Crawler (Enhanced)
==========================
Discovers pages, forms, links, and potential API endpoints
starting from a seed URL. Respects domain scope and max-page limits.

Enhancements over v1:
- Meta-refresh and JavaScript redirect detection
- Seed URL injection (accept extra URLs from discovery phase)
- Path parameter detection for injection testing
- Smarter deduplication (normalizes trailing slashes, fragments)
"""

import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from collections import deque

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("vulnscan.crawler")


class CrawlResult:
    """Container for all discovered assets from crawling."""

    def __init__(self):
        self.pages = []          # list of visited URLs
        self.forms = []          # list of FormData objects
        self.links = []          # list of all discovered hrefs
        self.api_endpoints = []  # list of likely API endpoint URLs
        self.params = {}         # url -> set of param names
        self.path_params = []    # list of path-based parameter info dicts
        self.redirects = []      # list of {from_url, to_url, type}
        self.technologies = {}   # detected tech (filled later by fingerprinter)

    def summary(self):
        return {
            "pages_crawled": len(self.pages),
            "forms_found": len(self.forms),
            "links_discovered": len(self.links),
            "api_endpoints": len(self.api_endpoints),
            "parameterized_urls": len(self.params),
            "path_parameters": len(self.path_params),
        }


class FormData:
    """Represents a discovered HTML form."""

    def __init__(self, action, method, inputs, page_url):
        self.action = action
        self.method = method.upper()
        self.inputs = inputs       # list of {name, type, value}
        self.page_url = page_url   # page where this form was found

    def to_dict(self):
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "page_url": self.page_url,
        }


class Crawler:
    """
    BFS crawler that discovers the attack surface of a web application.

    Parameters
    ----------
    seed_url : str
        Starting URL to crawl from.
    max_pages : int
        Maximum number of pages to visit (default 100).
    session : requests.Session, optional
        Shared session (e.g. with auth cookies).
    timeout : int
        HTTP request timeout in seconds.
    extra_seeds : list, optional
        Additional URLs to seed into the crawl queue (from discovery phase).
    """

    # Patterns that suggest an API endpoint
    API_PATTERNS = re.compile(
        r"(/api/|/v\d+/|/rest/|/graphql|/json|/ajax|/ws/)", re.IGNORECASE
    )

    # File extensions to skip
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    }

    # Common redirect-related parameter names
    REDIRECT_PARAMS = {
        "url", "redirect", "next", "return", "returnto", "redir",
        "destination", "dest", "go", "target", "link", "out",
        "continue", "return_url", "redirect_url", "redirect_uri",
    }

    # Meta-refresh pattern
    META_REFRESH_RE = re.compile(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>]+)',
        re.IGNORECASE,
    )

    # JavaScript redirect patterns
    JS_REDIRECT_RE = re.compile(
        r'(?:window\.location|location\.href|location\.replace)\s*[=\(]\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    # Path-based parameter patterns
    PATH_PARAM_PATTERNS = [
        re.compile(r"/(\d+)(?:/|$)"),                # Numeric IDs
        re.compile(r"/([0-9a-f]{8,})(?:/|$)", re.I),  # Hex IDs
        re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", re.I),  # UUIDs
    ]

    PATH_PARAM_KEYWORDS = {
        "user", "users", "profile", "account",
        "item", "items", "product", "products",
        "article", "articles", "post", "posts",
        "page", "pages", "category", "categories",
        "order", "orders", "id", "view", "edit", "show",
    }

    def __init__(self, seed_url, max_pages=100, session=None, timeout=10, extra_seeds=None):
        self.seed_url = seed_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.extra_seeds = extra_seeds or []

        parsed = urlparse(self.seed_url)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme

        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36 VulnScan/1.0"
            )
        })

        self.visited = set()
        self.result = CrawlResult()

    def _normalize_url(self, url):
        """Normalize URL for deduplication (strip fragment, trailing slash variants)."""
        url = url.split("#")[0]
        parsed = urlparse(url)
        # Normalize path — keep trailing slash only for root
        path = parsed.path
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return urlunparse(parsed._replace(path=path, fragment=""))

    def crawl(self):
        """
        Run BFS crawl starting from the seed URL plus any extra seeds.
        Returns a CrawlResult with all discovered assets.
        """
        # Build initial queue with seed + extras
        initial_urls = [self.seed_url] + [
            u for u in self.extra_seeds if self._is_in_scope(u)
        ]

        queue = deque()
        for url in initial_urls:
            normalized = self._normalize_url(url)
            if normalized not in self.visited:
                self.visited.add(normalized)
                queue.append(url)

        logger.info(f"Starting crawl from: {self.seed_url}")
        logger.info(f"Extra seeds: {len(self.extra_seeds)}")
        logger.info(f"Max pages: {self.max_pages}")

        while queue and len(self.result.pages) < self.max_pages:
            url = queue.popleft()

            try:
                response = self.session.get(
                    url, timeout=self.timeout, allow_redirects=True
                )
            except requests.RequestException as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue

            # Track redirects
            if response.url != url:
                self.result.redirects.append({
                    "from_url": url,
                    "to_url": response.url,
                    "type": "http_redirect",
                })
                # Make sure the final URL is also tracked
                final_normalized = self._normalize_url(response.url)
                self.visited.add(final_normalized)

            # Only parse HTML responses
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                # Check if it looks like an API endpoint
                if self.API_PATTERNS.search(url) or "json" in content_type:
                    self.result.api_endpoints.append(url)
                continue

            self.result.pages.append(response.url)
            logger.info(
                f"[{len(self.result.pages)}/{self.max_pages}] Crawled: {response.url}"
            )

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract forms
            self._extract_forms(soup, response.url)

            # Extract and enqueue links
            discovered = self._extract_links(soup, response.url)
            for link in discovered:
                normalized = self._normalize_url(link)
                if normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append(link)

            # Check for parameterized URL. Record params from both the
            # requested URL and the final URL: a param whose purpose is to
            # trigger a redirect (e.g. ?next=) disappears from response.url,
            # so relying on the final URL alone loses those injection points.
            self._extract_params(url)
            if response.url != url:
                self._extract_params(response.url)

            # Detect path-based parameters
            self._detect_path_params(response.url)

            # Check for meta-refresh and JS redirects
            redirect_urls = self._extract_redirects(response.text, response.url)
            for redir_url in redirect_urls:
                normalized = self._normalize_url(redir_url)
                if normalized not in self.visited and self._is_in_scope(redir_url):
                    self.visited.add(normalized)
                    queue.append(redir_url)

        logger.info(
            f"Crawl complete. {self.result.summary()}"
        )
        return self.result

    def _is_in_scope(self, url):
        """Check if URL belongs to the target domain."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        return parsed.netloc == self.base_domain

    def _should_skip(self, url):
        """Check if URL should be skipped (e.g. static assets)."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    def _extract_links(self, soup, page_url):
        """Extract all links from a page and return in-scope ones."""
        discovered = []

        # Standard <a>, <area>, <link> tags
        for tag in soup.find_all(["a", "area", "link"], href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue

            absolute = urljoin(page_url, href)
            absolute = absolute.split("#")[0]

            self.result.links.append(absolute)

            if self._is_in_scope(absolute) and not self._should_skip(absolute):
                discovered.append(absolute)

            if self.API_PATTERNS.search(absolute):
                self.result.api_endpoints.append(absolute)

        # <form> action URLs
        for form_tag in soup.find_all("form", action=True):
            action = form_tag.get("action", "").strip()
            if action and not action.startswith(("#", "javascript:")):
                absolute = urljoin(page_url, action)
                if self._is_in_scope(absolute):
                    discovered.append(absolute)

        # <iframe> src
        for iframe in soup.find_all("iframe", src=True):
            src = urljoin(page_url, iframe["src"])
            if self._is_in_scope(src):
                discovered.append(src)

        # Script src for API base URLs
        for script in soup.find_all("script", src=True):
            src = urljoin(page_url, script["src"])
            if self.API_PATTERNS.search(src):
                self.result.api_endpoints.append(src)

        # Inline script URLs (look for fetch/axios/XMLHttpRequest targets)
        for script in soup.find_all("script", src=False):
            if script.string:
                api_urls = re.findall(
                    r'["\'](/(?:api|rest|graphql|v\d+)/[^"\']*)["\']',
                    script.string,
                    re.IGNORECASE,
                )
                for api_path in api_urls:
                    full_url = urljoin(page_url, api_path)
                    self.result.api_endpoints.append(full_url)

        return discovered

    def _extract_forms(self, soup, page_url):
        """Extract all forms and their inputs from a page."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET")

            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                }
                if input_data["name"]:
                    inputs.append(input_data)

            form_data = FormData(
                action=action,
                method=method,
                inputs=inputs,
                page_url=page_url,
            )
            self.result.forms.append(form_data)

            logger.debug(
                f"Found form: {method} {action} "
                f"({len(inputs)} inputs) on {page_url}"
            )

    def _extract_params(self, url):
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            self.result.params[url] = set(params.keys())

    def _detect_path_params(self, url):
        """Detect path-based parameters (e.g., /user/123/profile)."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        segments = path.split("/")

        for i, segment in enumerate(segments):
            if not segment:
                continue

            is_param = False
            reason = ""

            for pattern in self.PATH_PARAM_PATTERNS:
                if pattern.fullmatch(segment) or pattern.search("/" + segment + "/"):
                    is_param = True
                    reason = "numeric/id pattern"
                    break

            if not is_param and i > 0:
                prev = segments[i - 1].lower()
                if prev in self.PATH_PARAM_KEYWORDS:
                    is_param = True
                    reason = f"follows keyword '{prev}'"

            if is_param:
                self.result.path_params.append({
                    "url": url,
                    "param_index": i,
                    "param_value": segment,
                    "reason": reason,
                    "segments": segments,
                })

    def _extract_redirects(self, html, page_url):
        """Extract redirect targets from meta-refresh tags and JavaScript."""
        urls = []

        # Meta-refresh
        for match in self.META_REFRESH_RE.finditer(html):
            target = match.group(1).strip().strip("'\"")
            absolute = urljoin(page_url, target)
            urls.append(absolute)
            self.result.redirects.append({
                "from_url": page_url,
                "to_url": absolute,
                "type": "meta_refresh",
            })
            logger.debug(f"Meta-refresh redirect: {page_url} -> {absolute}")

        # JavaScript redirects
        for match in self.JS_REDIRECT_RE.finditer(html):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "/")):
                absolute = urljoin(page_url, target)
                urls.append(absolute)
                self.result.redirects.append({
                    "from_url": page_url,
                    "to_url": absolute,
                    "type": "javascript",
                })
                logger.debug(f"JS redirect: {page_url} -> {absolute}")

        return urls

    def get_parameterized_urls(self):
        """Return URLs that have injectable query parameters."""
        return dict(self.result.params)

    def get_redirect_params(self):
        """Return URLs with parameters that look like redirect targets."""
        redirect_urls = {}
        for url, params in self.result.params.items():
            suspicious = params & self.REDIRECT_PARAMS
            if suspicious:
                redirect_urls[url] = suspicious
        return redirect_urls
