"""
Headless-Browser Renderer (optional)
====================================
Wraps Playwright/Chromium so the crawler can fetch the *rendered* DOM of
JavaScript-heavy pages (React/Vue/Angular SPAs) that a plain HTTP GET cannot
see. This is what fixes the "0 pages crawled" problem on modern sites.

Playwright is an OPTIONAL dependency — the scanner works without it and only
needs it when you pass `--render-js`. To enable:

    pip install playwright
    playwright install chromium
"""

import logging

logger = logging.getLogger("vulnscan.renderer")


class RendererUnavailable(RuntimeError):
    """Raised when Playwright or its browser is not installed/launchable."""


class PlaywrightRenderer:
    """
    Minimal synchronous Playwright wrapper.

    One browser + context is reused across the whole crawl; each page fetch
    opens and closes a fresh tab. Call `close()` when done (the crawler does
    this in a finally block).
    """

    def __init__(self, timeout=15, user_agent=None, cookies=None):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise RendererUnavailable(
                "Playwright is not installed. Enable JS rendering with:\n"
                "    pip install playwright\n"
                "    playwright install chromium"
            ) from e

        self._timeout_ms = int(timeout * 1000)
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=True)
        except Exception as e:
            self._pw.stop()
            raise RendererUnavailable(
                "Chromium is not installed for Playwright. Run:\n"
                "    playwright install chromium"
            ) from e

        ctx_kwargs = {}
        if user_agent:
            ctx_kwargs["user_agent"] = user_agent
        self._context = self._browser.new_context(**ctx_kwargs)
        if cookies:
            try:
                self._context.add_cookies(cookies)
            except Exception as e:  # malformed cookie spec shouldn't kill the crawl
                logger.debug(f"Could not seed cookies into browser: {e}")

    def fetch(self, url):
        """
        Navigate to `url`, wait for the page to settle, and return the
        rendered DOM.

        Returns (final_url, html, headers_dict, status_code).
        """
        page = self._context.new_page()
        try:
            resp = page.goto(url, timeout=self._timeout_ms, wait_until="domcontentloaded")
            # Give client-side rendering a chance to finish. networkidle can
            # legitimately time out on sites with long-poll/websocket traffic,
            # so treat a timeout as "good enough" rather than a failure.
            try:
                page.wait_for_load_state("networkidle", timeout=self._timeout_ms)
            except Exception:
                pass

            status = resp.status if resp else 0
            headers = dict(resp.headers) if resp else {}
            ctype = headers.get("content-type", "")

            if "text/html" in ctype or not ctype:
                html = page.content()          # fully rendered DOM
            else:
                html = resp.text() if resp else ""  # raw body for JSON/etc.

            return page.url, html, headers, status
        finally:
            page.close()

    def close(self):
        for closer in (
            getattr(self, "_context", None),
            getattr(self, "_browser", None),
        ):
            try:
                if closer is not None:
                    closer.close()
            except Exception:
                pass
        try:
            if getattr(self, "_pw", None) is not None:
                self._pw.stop()
        except Exception:
            pass
