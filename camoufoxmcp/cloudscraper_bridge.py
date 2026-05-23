"""cloudscraper bridge — HTTP-level Cloudflare bypass for CamoufoxMCP.

Two primary operations:
  1. fetch_via_cloudscraper(url) — fetch content directly, returns markdown + cookies
  2. solve_and_inject(page, url) — solve CF challenge, inject clearance cookies into
     an active Playwright page so the browser session can continue uninterrupted.

cloudscraper uses a requests.Session subclass that solves Cloudflare's
JavaScript challenges (v1, v2, v3, Turnstile) at the HTTP level. It's a
lightweight complement to Camoufox's browser-level stealth — use it when
the browser hits Cloudflare and you want a programmatic fallback without
human verification.
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any

logger = logging.getLogger("camoufoxmcp")


def _is_cf_challenge_html(html_content: str, status_code: int | None = None) -> bool:
    """Detect whether an HTTP response body is a Cloudflare challenge page.

    cloudscraper sometimes returns the challenge page as a successful response
    (no exception raised) when it can't solve newer CF protections. This
    inspects the body content for CF challenge signatures.

    NOTE: Real sites behind Cloudflare CDN may reference /cdn-cgi/ paths in
    their normal content. Only flag when definitive challenge markers are present.
    """
    content_lower = html_content.lower()

    # Strongest signal: CF challenge JS config object (only in challenge pages)
    if "_cf_chl_opt" in content_lower and ("ctype" in content_lower or "cray" in content_lower):
        return True

    # The classic challenge title
    if "<title>just a moment...</title>" in content_lower:
        return True

    # Challenge orchestrate script endpoint (not CDN assets)
    if "/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/" in content_lower:
        return True

    # JS variable assignment specific to challenges
    if "window._cf_chl_opt" in content_lower and "challenges.cloudflare.com" in content_lower:
        return True

    # Short body + classic CF text (catch simple IUAM pages)
    if len(html_content) < 5000:
        if any(phrase in content_lower for phrase in (
            "just a moment",
            "checking your browser",
            "enable javascript and cookies to continue",
            "attention required",
            "please turn javascript on",
            "ddos protection by cloudflare",
        )):
            return True

    # 403 + very short body + cloudflare mention (fringe case)
    if status_code == 403 and len(html_content) < 3000:
        if "cloudflare" in content_lower:
            return True

    return False


def _html_to_text(html_content: str, max_length: int = 50000) -> str:
    """Minimal HTML-to-readable-text conversion. Not full markdown, but
    good enough for an LLM to understand the page structure."""
    text = html_content

    # Remove script/style/comment blocks
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # Headings
    for i in range(3, 0, -1):
        text = re.sub(
            rf"<h{i}[^>]*>(.*?)</h{i}>",
            lambda m: f"\n{'#' * i} {m.group(1).strip()}\n",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )

    # Block elements → newlines
    text = re.sub(r"<(?:p|div|section|article|header|footer|main|aside|nav)[^>]*>",
                  "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:p|div|section|article|header|footer|main|aside|nav)>",
                  "", text, flags=re.IGNORECASE)
    text = re.sub(r"<br[^>]*>", "\n", text, flags=re.IGNORECASE)

    # Lists
    text = re.sub(r"<li[^>]*>(.*?)</li>",
                  lambda m: f"\n- {m.group(1).strip()}",
                  text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<(?:ul|ol)[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:ul|ol)[^>]*>", "", text, flags=re.IGNORECASE)

    # Inline formatting
    text = re.sub(r"<strong[^>]*>(.*?)</strong>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<b[^>]*>(.*?)</b>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<em[^>]*>(.*?)</em>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<i[^>]*>(.*?)</i>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", text, flags=re.IGNORECASE | re.DOTALL)

    # Links
    text = re.sub(r"<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)</a>",
                  r"[\2](\1)", text, flags=re.IGNORECASE | re.DOTALL)

    # Strip remaining tags
    text = re.sub(r"<[^>]+>", "", text)

    # Decode entities, collapse whitespace
    text = html.unescape(text)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + f"\n\n... (truncated, {len(text) - max_length} chars cut)"

    return text


def fetch_via_cloudscraper(
    url: str,
    max_length: int = 50000,
    proxy: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Fetch a URL through cloudscraper, bypassing Cloudflare challenges.

    Uses cloudscraper's JS challenge solver at the HTTP level — much
    lighter than launching a full browser. Returns the page content as
    readable text plus the clearance cookies so they can be reused.

    Args:
        url: Target URL to fetch.
        max_length: Truncate content at this many characters.
        proxy: Optional proxy URL (e.g. 'http://user:pass@host:port').
        timeout: Request timeout in seconds.

    Returns:
        {
            "status": "ok" | "error",
            "url": final URL after redirects,
            "status_code": HTTP status code,
            "content": extracted readable text,
            "cookies": {name: value, ...},  # CF clearance cookies
            "headers": {key: value, ...},    # response headers
            "elapsed_ms": round-trip time,
        }
    """
    import cloudscraper

    try:
        scraper_kwargs: dict[str, Any] = {
            "browser": "chrome",
            "debug": False,
        }
        if proxy:
            scraper_kwargs["proxies"] = {"http": proxy, "https": proxy}

        scraper = cloudscraper.create_scraper(**scraper_kwargs)

        t0 = __import__("time").time()
        resp = scraper.get(url, timeout=timeout, allow_redirects=True)
        elapsed_ms = int((__import__("time").time() - t0) * 1000)

        # Detect unsolved CF challenge in the response body
        if _is_cf_challenge_html(resp.text, resp.status_code):
            return {
                "status": "cf_blocked",
                "url": resp.url,
                "status_code": resp.status_code,
                "error": (
                    "Cloudflare challenge detected in response body. "
                    "cloudscraper was unable to solve this challenge — the site "
                    "may be using newer CF protection (Turnstile, JS VM v3, etc.)."
                ),
                "hint": (
                    "Try the full Camoufox browser: camoufox_launch() → "
                    "camoufox_navigate(url). The browser's Firefox fingerprint "
                    "can bypass challenges that HTTP-level solvers can't."
                ),
                "elapsed_ms": elapsed_ms,
            }

        content_text = _html_to_text(resp.text, max_length)

        # Extract cookies — cloudscraper stores CF clearance in the session
        cookies = {}
        for cookie in scraper.cookies:
            cookies[cookie.name] = cookie.value

        return {
            "status": "ok",
            "url": resp.url,
            "status_code": resp.status_code,
            "content": content_text,
            "cookies": cookies,
            "headers": dict(resp.headers),
            "elapsed_ms": elapsed_ms,
            "note": "Cookies can be reused in Camoufox browser via camoufox_cloudscraper_solve",
        }

    except cloudscraper.exceptions.CloudflareChallengeError as e:
        logger.warning("cloudscraper challenge error for %s: %s", url, e)
        return {
            "status": "cf_blocked",
            "url": url,
            "error": f"Cloudflare challenge unsolved: {e}",
            "hint": "cloudscraper couldn't solve this challenge — try the Camoufox browser directly",
        }
    except cloudscraper.exceptions.CloudflareLoopProtection as e:
        return {
            "status": "cf_loop",
            "url": url,
            "error": f"Cloudflare loop protection triggered: {e}",
            "hint": "Too many attempts — wait and try again, or use Camoufox browser with different fingerprint",
        }
    except Exception as e:
        # DNS/connection errors are common for dead sites — don't log tracebacks
        err_str = str(e).lower()
        if any(kw in err_str for kw in ("name or service not known", "nodename nor servname", "failed to resolve")):
            logger.info("cloudscraper DNS resolution failed for %s", url)
        else:
            logger.exception("cloudscraper fetch failed for %s", url)
        return {
            "status": "error",
            "url": url,
            "error": f"{type(e).__name__}: {e}",
        }


def solve_and_inject(
    page: Any,
    url: str,
    proxy: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Use cloudscraper to solve a Cloudflare challenge, then inject the
    resulting clearance cookies into an active Playwright page.

    This lets the Camoufox browser session bypass Cloudflare without
    needing human verification — cloudscraper solves the JS challenge
    at the HTTP level, and we transplant the clearance cookies into
    the browser context.

    Args:
        page: A Playwright Page object (from the active Camoufox session).
        url: The URL that is Cloudflare-blocked.
        proxy: Optional proxy URL.
        timeout: Request timeout in seconds.

    Returns:
        {
            "status": "ok" | "error",
            "cookies_injected": N,
            "cookie_names": [...],
            "next_step": "Call camoufox_navigate() with the same URL",
        }
    """
    import cloudscraper

    try:
        scraper_kwargs: dict[str, Any] = {
            "browser": "chrome",
            "debug": False,
        }
        if proxy:
            scraper_kwargs["proxies"] = {"http": proxy, "https": proxy}

        scraper = cloudscraper.create_scraper(**scraper_kwargs)

        # Hit the target — cloudscraper solves the challenge and stores
        # the clearance cookies in its session
        resp = scraper.get(url, timeout=timeout, allow_redirects=True)

        # Detect unsolved CF challenge in the response body
        if _is_cf_challenge_html(resp.text, resp.status_code):
            return {
                "status": "cf_blocked",
                "url": resp.url,
                "status_code": resp.status_code,
                "error": (
                    "Cloudflare challenge detected in response body. "
                    "cloudscraper was unable to solve this challenge."
                ),
                "hint": (
                    "The full Camoufox browser may be able to bypass this. "
                    "Try camoufox_navigate() directly — Camoufox's Firefox-based "
                    "fingerprint can solve challenges that HTTP-level solvers can't."
                ),
            }

        # Collect cookies from cloudscraper's session
        cookies_to_inject: list[dict[str, Any]] = []
        for cookie in scraper.cookies:
            cookies_to_inject.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
                "httpOnly": getattr(cookie, "has_nonstandard_attr", False) or False,
                "secure": cookie.secure or False,
            })

        if not cookies_to_inject:
            return {
                "status": "no_cookies",
                "url": resp.url,
                "status_code": resp.status_code,
                "error": "No Cloudflare clearance cookies found — the site may not be behind Cloudflare",
                "hint": "Try camoufox_navigate() directly — the browser may not be blocked",
            }

        # Inject cookies into the Playwright browser context
        context = page.context
        context.add_cookies(cookies_to_inject)

        cookie_names = [c["name"] for c in cookies_to_inject]
        logger.info(
            "Injected %d cloudscraper cookies into browser context: %s",
            len(cookies_to_inject),
            cookie_names,
        )

        return {
            "status": "ok",
            "url": resp.url,
            "status_code": resp.status_code,
            "cookies_injected": len(cookies_to_inject),
            "cookie_names": cookie_names,
            "next_step": (
                "Cookies injected. Call camoufox_navigate() with the same URL — "
                "the browser should now bypass Cloudflare."
            ),
        }

    except cloudscraper.exceptions.CloudflareChallengeError as e:
        logger.warning("cloudscraper solve failed for %s: %s", url, e)
        return {
            "status": "cf_blocked",
            "url": url,
            "error": f"Cloudflare challenge unsolved: {e}",
            "hint": (
                "cloudscraper couldn't solve this challenge. "
                "The site may be using a newer Cloudflare protection. "
                "Try a different approach: different proxy, different user-agent, "
                "or wait and retry."
            ),
        }
    except Exception as e:
        logger.exception("cloudscraper solve_and_inject failed for %s", url)
        return {
            "status": "error",
            "url": url,
            "error": f"{type(e).__name__}: {e}",
        }
