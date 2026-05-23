"""FlareSolverr bridge — Docker-based Cloudflare bypass for the hardest challenges.

FlareSolverr runs headless Chromium with puppeteer-extra stealth plugin. It
solves Cloudflare Turnstile, JS VM v3 ("managed challenge"), and other
protections that HTTP-level solvers (cloudscraper, curl_cffi) cannot handle.

Requires Docker: docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest

Three operations:
  1. check_flaresolverr_health() — verify FlareSolverr is running
  2. fetch_via_flaresolverr(url) — fetch content through FlareSolverr
  3. solve_cf_challenge(url) — solve challenge, return clearance tokens
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger("camoufoxmcp")

DEFAULT_FLARESOLVERR_URL = "http://localhost:8191/v1"
FLARESOLVERR_CONTAINER = "camoufox-flaresolverr"
FLARESOLVERR_IMAGE = "flaresolverr/flaresolverr:latest"
FLARESOLVERR_PORT = "8191"


def _html_to_text(html_content: str, max_length: int = 50000) -> str:
    """Minimal HTML-to-readable-text conversion."""
    import html as _html

    text = html_content
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    for i in range(3, 0, -1):
        text = re.sub(
            rf"<h{i}[^>]*>(.*?)</h{i}>",
            lambda m: f"\n{'#' * i} {m.group(1).strip()}\n",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )

    text = re.sub(r"<(?:p|div|section|article|header|footer|main|aside|nav)[^>]*>",
                  "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:p|div|section|article|header|footer|main|aside|nav)>",
                  "", text, flags=re.IGNORECASE)
    text = re.sub(r"<br[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<li[^>]*>(.*?)</li>",
                  lambda m: f"\n- {m.group(1).strip()}",
                  text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<(?:ul|ol)[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:ul|ol)[^>]*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<strong[^>]*>(.*?)</strong>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<b[^>]*>(.*?)</b>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<em[^>]*>(.*?)</em>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<i[^>]*>(.*?)</i>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)</a>",
                  r"[\2](\1)", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    text = _html.unescape(text)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + f"\n\n... (truncated, {len(text) - max_length} chars cut)"

    return text


def _call_flaresolverr(
    payload: dict[str, Any],
    flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
) -> dict[str, Any]:
    """Send a request to FlareSolverr and return parsed JSON."""
    req = urllib.request.Request(
        flaresolverr_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        if isinstance(e.reason, ConnectionRefusedError) or "Connection refused" in str(e.reason):
            raise FlareSolverrNotRunning(
                "FlareSolverr is not running. Start it with:\n"
                "  docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest"
            )
        raise


class FlareSolverrNotRunning(ConnectionError):
    """FlareSolverr Docker container is not running."""


# ---------------------------------------------------------------------------
# Docker lifecycle management
# ---------------------------------------------------------------------------

def _docker(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a docker command, return (exit_code, stdout, stderr)."""
    import subprocess
    try:
        r = subprocess.run(
            ["docker"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", "docker: command not found"
    except subprocess.TimeoutExpired:
        return -1, "", "docker: timed out"


def is_flaresolverr_running() -> bool:
    """Check if the FlareSolverr container is running."""
    code, stdout, _ = _docker([
        "inspect", "-f", "{{.State.Running}}",
        FLARESOLVERR_CONTAINER,
    ])
    return code == 0 and stdout == "true"


def is_flaresolverr_healthy(url: str = DEFAULT_FLARESOLVERR_URL) -> bool:
    """Check if FlareSolverr is accepting requests."""
    try:
        result = _call_flaresolverr({"cmd": "sessions.list"}, url)
        return result.get("status") == "ok"
    except Exception:
        return False


def start_flaresolverr(
    image: str = FLARESOLVERR_IMAGE,
    container: str = FLARESOLVERR_CONTAINER,
    port: str = FLARESOLVERR_PORT,
) -> dict[str, Any]:
    """Start FlareSolverr Docker container if not already running.

    Uses a named container with restart policy so it survives Docker
    daemon restarts. Safe to call multiple times — no-op if already running.
    """
    # Already running?
    if is_flaresolverr_running():
        if is_flaresolverr_healthy():
            return {
                "status": "already_running",
                "container": container,
                "port": port,
                "message": "FlareSolverr is already running and healthy",
            }

    # Container exists but stopped? Start it
    code, stdout, _ = _docker(["inspect", "-f", "{{.State.Status}}", container])
    if code == 0:
        logger.info("FlareSolverr container exists (status=%s), starting...", stdout)
        code, _, stderr = _docker(["start", container], timeout=10)
        if code != 0:
            return {
                "status": "error",
                "error": f"Failed to start existing container: {stderr}",
            }
    else:
        # Pull image if not present, then create + start
        logger.info("Pulling FlareSolverr image: %s", image)
        code, _, stderr = _docker(["pull", image], timeout=120)
        if code != 0:
            return {
                "status": "error",
                "error": f"Failed to pull image: {stderr}",
                "hint": "Is Docker installed and running?",
            }

        logger.info("Creating FlareSolverr container: %s", container)
        code, _, stderr = _docker([
            "run", "-d",
            "--name", container,
            "--restart", "unless-stopped",
            "-p", f"{port}:8191",
            image,
        ], timeout=30)
        if code != 0:
            return {
                "status": "error",
                "error": f"Failed to create container: {stderr}",
            }

    # Wait for it to become healthy
    logger.info("Waiting for FlareSolverr to become healthy...")
    for i in range(15):
        time.sleep(2)
        if is_flaresolverr_healthy():
            return {
                "status": "started",
                "container": container,
                "port": port,
                "url": f"http://localhost:{port}/v1",
                "message": f"FlareSolverr started and healthy (took ~{(i+1)*2}s)",
            }

    return {
        "status": "started_unhealthy",
        "container": container,
        "port": port,
        "error": "Container started but not responding. Check docker logs.",
        "hint": f"docker logs {container}",
    }


def stop_flaresolverr(container: str = FLARESOLVERR_CONTAINER) -> dict[str, Any]:
    """Stop the FlareSolverr Docker container."""
    if not is_flaresolverr_running():
        return {"status": "not_running", "container": container, "message": "FlareSolverr was not running"}

    code, _, stderr = _docker(["stop", container], timeout=15)
    if code != 0:
        return {"status": "error", "error": f"Failed to stop: {stderr}"}

    return {"status": "stopped", "container": container, "message": "FlareSolverr stopped"}


def ensure_flaresolverr_running() -> dict[str, Any]:
    """Check FlareSolverr health; auto-start if not running.

    Called automatically before any Tier 3 fetch. Returns readiness status.
    """
    if is_flaresolverr_running() and is_flaresolverr_healthy():
        return {"status": "ready", "message": "FlareSolverr is running"}

    logger.info("FlareSolverr not running, auto-starting...")
    return start_flaresolverr()


def check_flaresolverr_health(
    flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
) -> dict[str, Any]:
    """Check if FlareSolverr is running and healthy.

    Returns:
        {
            "status": "ok" | "error",
            "version": "..." or None,
            "uptime_ms": ... or None,
        }
    """
    try:
        result = _call_flaresolverr(
            {"cmd": "sessions.list"},
            flaresolverr_url,
        )
        return {
            "status": "ok",
            "version": result.get("version", "unknown"),
            "message": "FlareSolverr is running",
        }
    except FlareSolverrNotRunning:
        return {
            "status": "not_running",
            "error": "FlareSolverr is not running",
            "hint": "docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest",
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
        }


def fetch_raw_via_flaresolverr(
    url: str,
    max_timeout: int = 60000,
    flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Fetch a URL through FlareSolverr, returning raw bytes for route fulfillment.

    Same heavy-artillery CF bypass as fetch_via_flaresolverr, but returns
    the raw response body (bytes) and headers — designed for Playwright
    route interception where the browser needs the exact HTTP response.

    Args:
        url: Target URL.
        max_timeout: Max solve time in ms.
        flaresolverr_url: FlareSolverr endpoint.
        proxy: Optional proxy URL.

    Returns:
        {"status": "ok"|"cf_blocked"|"error", "body": b"...", "headers": {...},
         "status_code": 200, "elapsed_ms": ...}
    """
    t0 = time.time()

    ensure = ensure_flaresolverr_running()
    if ensure["status"] not in ("ready", "already_running", "started"):
        return {
            "status": "error",
            "url": url,
            "error": f"FlareSolverr not available: {ensure.get('error', ensure.get('status'))}",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    payload: dict[str, Any] = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": max_timeout,
    }
    if proxy:
        payload["proxy"] = {"url": proxy}

    try:
        result = _call_flaresolverr(payload, flaresolverr_url)
    except FlareSolverrNotRunning:
        return {
            "status": "error", "url": url,
            "error": "FlareSolverr not running",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
    except Exception as e:
        return {
            "status": "error", "url": url,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    elapsed_ms = int((time.time() - t0) * 1000)

    if result.get("status") != "ok":
        return {
            "status": "error", "url": url,
            "error": result.get("message", "FlareSolverr returned error"),
            "elapsed_ms": elapsed_ms,
        }

    solution = result.get("solution", {})
    response_html = solution.get("response", "")

    if _is_cf_challenge_html(response_html):
        return {
            "status": "cf_blocked", "url": solution.get("url", url),
            "error": "FlareSolverr could not solve the Cloudflare challenge.",
            "elapsed_ms": elapsed_ms,
        }

    # Extract content-type from response headers
    headers = solution.get("headers", {})
    if not headers:
        headers = {"content-type": "text/html; charset=utf-8"}

    return {
        "status": "ok",
        "url": solution.get("url", url),
        "status_code": solution.get("status", 200),
        "body": response_html.encode("utf-8"),
        "headers": headers,
        "elapsed_ms": elapsed_ms,
    }


def fetch_via_flaresolverr(
    url: str,
    max_length: int = 50000,
    max_timeout: int = 60000,
    flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Fetch a URL through FlareSolverr, bypassing all Cloudflare protections.

    FlareSolverr runs headless Chromium with stealth plugins. It solves
    Turnstile, JS VM v3 ("managed challenge"), IUAM, and CAPTCHA challenges
    that no HTTP-level solver can handle.

    This is the heavy artillery — use when cloudscraper and curl_cffi fail.
    Requires Docker running FlareSolverr on port 8191.

    Args:
        url: Target URL to fetch.
        max_length: Truncate returned text at this many characters.
        max_timeout: Max time FlareSolverr spends solving (ms, default 60000).
        flaresolverr_url: FlareSolverr endpoint (default: http://localhost:8191/v1).
        proxy: Optional proxy URL for FlareSolverr's browser.

    Returns:
        {
            "status": "ok" | "cf_blocked" | "error",
            "url": final URL,
            "content": extracted readable text,
            "cookies": [{name, value, domain, ...}],
            "cf_clearance": "..." or None,
            "elapsed_ms": round-trip time,
        }
    """
    t0 = time.time()

    # Auto-start FlareSolverr if not running
    ensure = ensure_flaresolverr_running()
    if ensure["status"] not in ("ready", "already_running", "started"):
        return {
            "status": "error",
            "url": url,
            "error": f"FlareSolverr not available: {ensure.get('error', ensure.get('status'))}",
            "hint": ensure.get("hint", "Ensure Docker is running and try again"),
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    payload: dict[str, Any] = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": max_timeout,
    }
    if proxy:
        payload["proxy"] = {"url": proxy}

    try:
        result = _call_flaresolverr(payload, flaresolverr_url)
    except FlareSolverrNotRunning:
        return {
            "status": "error",
            "url": url,
            "error": "FlareSolverr not running",
            "hint": "docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
    except Exception as e:
        logger.exception("FlareSolverr call failed for %s", url)
        return {
            "status": "error",
            "url": url,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    elapsed_ms = int((time.time() - t0) * 1000)

    if result.get("status") != "ok":
        return {
            "status": "error",
            "url": url,
            "error": result.get("message", "FlareSolverr returned error"),
            "elapsed_ms": elapsed_ms,
        }

    solution = result.get("solution", {})
    response_html = solution.get("response", "")
    cookies = solution.get("cookies", [])

    # Detect if challenge was actually solved
    if _is_cf_challenge_html(response_html):
        return {
            "status": "cf_blocked",
            "url": solution.get("url", url),
            "error": (
                "FlareSolverr could not solve the Cloudflare challenge. "
                "The site may be using protection beyond current capabilities."
            ),
            "elapsed_ms": elapsed_ms,
        }

    # Extract the cf_clearance cookie value (the key CF bypass token)
    cf_clearance = None
    for c in cookies:
        if c.get("name") == "cf_clearance":
            cf_clearance = c.get("value")
            break

    content_text = _html_to_text(response_html, max_length)
    links = _extract_links(response_html, solution.get("url", url))

    return {
        "status": "ok",
        "url": solution.get("url", url),
        "status_code": solution.get("status", 200),
        "content": content_text,
        "links": links,
        "cookies": cookies,
        "cf_clearance": cf_clearance,
        "elapsed_ms": elapsed_ms,
        "solver": "flaresolverr (headless Chromium + puppeteer-extra)",
    }


def _extract_links(html_content: str, base_url: str = "") -> list[dict[str, str]]:
    """Extract all <a href> links from HTML, returning structured link data.
    
    Filters out navigation, anchors, javascript:, and common noise patterns.
    Returns relative URLs resolved against base_url when provided.
    """
    from urllib.parse import urljoin
    
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    
    # Match <a> tags with href
    for m in re.finditer(
        r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        html_content,
        re.IGNORECASE | re.DOTALL,
    ):
        href = m.group(1).strip()
        text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        
        # Skip noise
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if not text:
            continue
        if len(text) > 300:  # likely not a real link text
            continue
        
        # Resolve relative URLs
        full_url = urljoin(base_url, href) if base_url else href
        
        # Dedupe
        if full_url in seen:
            continue
        seen.add(full_url)
        
        # Classify link type
        link_type = "page"
        if any(full_url.lower().endswith(ext) for ext in (
            ".pdf", ".zip", ".7z", ".rar", ".tar.gz", ".gz", ".exe", ".dll",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".mp3",
            ".json", ".xml", ".csv", ".txt", ".md", ".py", ".js", ".html",
            ".bin", ".pcap", ".pcapng", ".log", ".elf", ".dmp",
        )):
            link_type = "file"
        elif "/" in full_url and not full_url.endswith("/"):
            pass  # keep as "page"

        links.append({
            "text": text,
            "url": full_url,
            "type": link_type,
        })

    # Also extract Phoenix LiveView navigation targets (phx-click="change-directory")
    for m in re.finditer(
        r'phx-click="([^"]+)"',
        html_content,
        re.IGNORECASE,
    ):
        attr_value = m.group(1)
        # Unescape HTML entities
        attr_value = attr_value.replace("&quot;", '"').replace("&amp;", "&")
        # Extract path value from the JSON-like structure
        val_match = re.search(r'"value"\s*:\s*"([^"]+)"', attr_value)
        evt_match = re.search(r'"event"\s*:\s*"([^"]+)"', attr_value)
        if val_match and evt_match and evt_match.group(1) == "change-directory":
            path_value = val_match.group(1)
            full_url = urljoin(base_url, "/" + path_value) if base_url else "/" + path_value
            if full_url not in seen:
                seen.add(full_url)
                text = path_value.rstrip("/").rsplit("/", 1)[-1] if "/" in path_value else path_value
                links.append({
                    "text": text,
                    "url": full_url,
                    "type": "page",
                })

    return links


def solve_via_flaresolverr(
    url: str,
    max_timeout: int = 60000,
    flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Solve Cloudflare challenge via FlareSolverr, returning clearance cookies.

    Uses FlareSolverr's headless Chromium to solve the CF challenge and
    returns the resulting cookies for injection into a browser context.
    This is the heavy-artillery equivalent of cloudscraper's solve_and_inject
    — use when cloudscraper's HTTP-level solver fails (cf_blocked status).

    Args:
        url: Target URL behind Cloudflare.
        max_timeout: Max solve time in ms (default: 60000).
        flaresolverr_url: FlareSolverr endpoint.
        proxy: Optional proxy URL for FlareSolverr's browser.

    Returns:
        {
            "status": "ok" | "cf_blocked" | "error",
            "url": final URL,
            "cookies": [{name, value, domain, path, ...}],
            "cf_clearance": "..." or None,
            "elapsed_ms": round-trip time,
        }
    """
    t0 = time.time()

    # Auto-start FlareSolverr if not running
    ensure = ensure_flaresolverr_running()
    if ensure["status"] not in ("ready", "already_running", "started"):
        return {
            "status": "error",
            "url": url,
            "error": f"FlareSolverr not available: {ensure.get('error', ensure.get('status'))}",
            "hint": ensure.get("hint", "Ensure Docker is running and try again"),
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    payload: dict[str, Any] = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": max_timeout,
    }
    if proxy:
        payload["proxy"] = {"url": proxy}

    try:
        result = _call_flaresolverr(payload, flaresolverr_url)
    except FlareSolverrNotRunning:
        return {
            "status": "error",
            "url": url,
            "error": "FlareSolverr not running",
            "hint": "docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
    except Exception as e:
        logger.exception("FlareSolverr solve failed for %s", url)
        return {
            "status": "error",
            "url": url,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": int((time.time() - t0) * 1000),
        }

    elapsed_ms = int((time.time() - t0) * 1000)

    if result.get("status") != "ok":
        return {
            "status": "error",
            "url": url,
            "error": result.get("message", "FlareSolverr returned error"),
            "elapsed_ms": elapsed_ms,
        }

    solution = result.get("solution", {})
    response_html = solution.get("response", "")

    # Detect unsolved challenge
    if _is_cf_challenge_html(response_html):
        return {
            "status": "cf_blocked",
            "url": solution.get("url", url),
            "error": (
                "FlareSolverr could not solve the Cloudflare challenge. "
                "The site may be using protection beyond current capabilities."
            ),
            "elapsed_ms": elapsed_ms,
        }

    # Extract and normalize cookies for browser injection
    raw_cookies = solution.get("cookies", [])
    cookies: list[dict[str, Any]] = []
    cf_clearance = None
    for c in raw_cookies:
        cookie = {
            "name": c.get("name", ""),
            "value": c.get("value", ""),
            "domain": c.get("domain", ""),
            "path": c.get("path", "/"),
            "secure": c.get("secure", False),
            "httpOnly": c.get("httpOnly", False),
        }
        if c.get("expiry"):
            cookie["expires"] = c["expiry"]
        cookies.append(cookie)

        if c.get("name") == "cf_clearance":
            cf_clearance = c.get("value")

    return {
        "status": "ok",
        "url": solution.get("url", url),
        "cookies": cookies,
        "cf_clearance": cf_clearance,
        "elapsed_ms": elapsed_ms,
        "solver": "flaresolverr (headless Chromium + puppeteer-extra)",
    }


def _is_cf_challenge_html(html_content: str) -> bool:
    """Detect unsolved CF challenge in response body.

    Must be careful to avoid false positives: real sites behind Cloudflare
    may reference /cdn-cgi/ CDN paths in their normal content. Only flag
    when definitive challenge markers are present.
    """
    content_lower = html_content.lower()

    # Strongest signal: CF challenge JS config object (only in challenge pages)
    if "_cf_chl_opt" in content_lower and ("ctype" in content_lower or "cray" in content_lower):
        return True

    # The classic challenge title
    if "<title>just a moment...</title>" in content_lower:
        return True

    # Challenge script endpoint (the orchestrate script, not CDN assets)
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
        )):
            return True

    return False
