"""CamoufoxMCP server — stealth browser automation for AI agents.

~21 tools. Snapshot-first. Three-tier Cloudflare bypass with auto-managed FlareSolverr.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session import BrowserSession, SessionConfig, BrowserSessionError, PageNotFoundError, PageClosedError, _random_viewport
from .snapshot import take_snapshot, resolve_ref
from .markdown import extract_markdown
from .vision import take_screenshot
from .cloudscraper_bridge import fetch_via_cloudscraper, solve_and_inject
from .flaresolverr_bridge import (
    fetch_via_flaresolverr,
    check_flaresolverr_health,
    start_flaresolverr,
    stop_flaresolverr,
    ensure_flaresolverr_running,
    is_flaresolverr_running,
    FlareSolverrNotRunning,
)

logger = logging.getLogger("camoufoxmcp")

LOGS_DIR = Path.home() / ".camoufoxmcp" / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

_session = BrowserSession()
_capabilities: set[str] = set()
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="camoufox")

# -----------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------

def _configure_logging() -> None:
    if getattr(_configure_logging, "_done", False):
        return
    log_level = os.getenv("CAMOUFOX_MCP_LOG_LEVEL", "INFO").upper()
    log_path = Path(os.getenv("CAMOUFOX_MCP_LOG_FILE", str(LOGS_DIR / "server.log")))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_path)
    fh.setFormatter(formatter)
    logger.handlers.clear()
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    logger.addHandler(fh)
    logger.propagate = False
    if os.getenv("CAMOUFOX_MCP_LOG_STDERR", "").lower() in {"1", "true", "yes"}:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(formatter)
        logger.addHandler(sh)
    for name in ("mcp", "mcp.server", "mcp.server.fastmcp", "anyio", "uvicorn"):
        logging.getLogger(name).setLevel(logging.ERROR)
    _configure_logging._done = True


# -----------------------------------------------------------------------
# Error helpers
# -----------------------------------------------------------------------

def _err(msg: str, *, hint: str | None = None) -> dict[str, Any]:
    r: dict[str, Any] = {"status": "error", "error": msg}
    if hint:
        r["hint"] = hint
    return r


async def _safe(handler, *args, **kwargs) -> dict[str, Any]:
    try:
        return await handler(*args, **kwargs)
    except (PageNotFoundError, PageClosedError, BrowserSessionError) as e:
        return _err(str(e))
    except Exception as e:
        err_str = str(e).lower()
        if any(kw in err_str for kw in ("closed", "crashed", "disconnected", "not connected")):
            _session._force_cleanup()
            logger.warning("Browser connection lost: %s", e)
            return _err("Browser session lost. Call camoufox_launch() to start a new session.")
        logger.exception("Tool error: %s", type(e).__name__)
        return _err(f"{type(e).__name__}: {e}")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

async def _run_in_executor(self, func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(self._executor, lambda: func(*args, **kwargs))


# -----------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------

def create_server(caps: set[str] | None = None):
    global _capabilities
    _capabilities = caps or set()
    _configure_logging()

    mcp = FastMCP(
        "camoufox",
        log_level=os.getenv("CAMOUFOX_MCP_LOG_LEVEL", "ERROR"),
        instructions=(
            "Camoufox — stealth browser automation powered by Camoufox (humanized Playwright Firefox fork).\n\n"
            "WORKFLOW:\n"
            "Basic browsing:\n"
            "1. camoufox_launch() — start browser (headless or headed)\n"
            "2. camoufox_navigate(page_id, url) — go to URL\n"
            "3. camoufox_snapshot(page_id) — get interactive elements as [@eN] refs\n"
            "4. camoufox_click / camoufox_type / camoufox_scroll — interact\n"
            "5. camoufox_read_page(page_id) — page as clean markdown\n"
            "6. camoufox_screenshot(page_id) — screenshot\n"
            "7. camoufox_close() — done\n\n"
            "CLOUDFLARE BYPASS (three tiers, escalate as needed):\n"
            "Tier 1 (fast, no deps): camoufox_cloudscraper_fetch(url)\n"
            "  HTTP-level JS solver. Handles IUAM, v1, v2. ~100-500ms.\n"
            "Tier 2 (browser-level): camoufox_cloudscraper_solve(page_id)\n"
            "  Solves CF + injects cookies into Camoufox browser context.\n"
            "Tier 3 (heavy artillery): camoufox_flaresolverr_fetch(url)\n"
            "  Docker-based headless Chromium. Solves Turnstile, JS VM v3,\n"
            "  managed challenges — bypasses EVERYTHING. ~1-10s.\n"
            "  Requires: docker run -d -p 8191:8191 flaresolverr/flaresolverr\n\n"
            "WHEN BROWSER IS BLOCKED (camoufox_navigate → cloudflare_blocked=true):\n"
            "  1. Try camoufox_cloudscraper_solve(page_id) → re-navigate\n"
            "  2. If that fails, camoufox_cloudscraper_fetch(url) for direct content\n"
            "  3. If still blocked, camoufox_flaresolverr_fetch(url) for guaranteed bypass\n\n"
            "KEY DIFFERENCE from CloakBrowser:\n"
            "Camoufox is Firefox-based Playwright with three-tier Cloudflare bypass —\n"
            "cloudscraper (fast HTTP), cookie injection (browser), FlareSolverr (guaranteed)."
        ),
    )

    # --- Browser lifecycle ---

    @mcp.tool()
    async def camoufox_launch(
        display_mode: str = "headless",
        proxy: str | None = None,
        humanize: bool = True,
        human_preset: str = "default",
        stealth_args: bool = True,
        timezone: str | None = None,
        locale: str | None = None,
        viewport_width: int | None = None,
        viewport_height: int | None = None,
        color_scheme: str | None = None,
        user_agent: str | None = None,
        user_data_dir: str | None = None,
    ) -> dict[str, Any]:
        """Launch a stealth Camoufox browser instance.

        Camoufox is a humanized Playwright Firefox fork that auto-passes most
        Cloudflare challenges and fingerprint checks.

        Args:
            display_mode: 'headless' (default, invisible) or 'headed' (visible window).
                Agent can switch modes per-task — headed is useful when Cloudflare blocks
                and human verification is needed, or for visual debugging.
            proxy: Proxy URL e.g. 'http://user:***@proxy:8080'.
            humanize: Human-like mouse/keyboard/scroll (default: True).
            human_preset: 'default' or 'careful' (slower).
            timezone: IANA timezone e.g. 'America/New_York'.
            locale: BCP 47 locale e.g. 'en-US'.
            viewport_width: Viewport width in pixels.
            viewport_height: Viewport height in pixels.
            color_scheme: 'light', 'dark', or 'no-preference'.
            user_agent: Custom user agent override.
            user_data_dir: Persistent profile path (cookies survive restarts).
        """
        headless = display_mode != "headed"

        if _session.is_running:
            return {"status": "already_running", "pages": _session.list_pages()}

        vp = _random_viewport()
        w = viewport_width or vp["width"]
        h = viewport_height or vp["height"]

        cfg = SessionConfig(
            headless=headless,
            proxy=proxy,
            humanize=humanize,
            human_preset=human_preset,
            stealth_args=stealth_args,
            timezone=timezone,
            locale=locale,
            viewport={"width": w, "height": h},
            color_scheme=color_scheme,
            user_agent=user_agent,
            user_data_dir=user_data_dir,
        )

        await _session.launch(cfg, _executor)
        page_id = await _session.new_page()

        return {
            "status": "launched",
            "page_id": page_id,
            "display_mode": display_mode,
            "stealth": True,
            "humanize": humanize,
            "hint": "Next: call camoufox_navigate(page_id, url)",
        }

    @mcp.tool()
    async def camoufox_close() -> dict[str, Any]:
        """Close the Camoufox browser and release all resources."""
        if not _session.is_running:
            return {"status": "not_running"}
        await _session.close()
        return {"status": "closed"}

    # --- Navigation ---

    @mcp.tool()
    async def camoufox_navigate(page_id: str, url: str, timeout: int = 30000) -> dict[str, Any]:
        """Navigate to a URL with smart waiting.

        Returns cloudflare_blocked=true if Cloudflare challenge detected.
        In that case call camoufox_snapshot_if_blocked() next.

        Args:
            page_id: Target page ID from camoufox_launch or camoufox_new_page.
            url: Full URL to navigate to.
            timeout: Navigation timeout in ms (default: 30000).
        """
        page = _session.get_page(page_id)

        loop = asyncio.get_event_loop()

        def _nav():
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(6000)
            return {
                "url": page.url,
                "title": page.title(),
            }

        result = await loop.run_in_executor(_executor, _nav)
        title = result["title"]
        url_final = result["url"]

        title_lower = title.lower()
        cf_blocked = any(
            p in title_lower
            for p in ("just a moment", "checking your browser", "cloudflare", "attention required")
        )

        return {
            "status": "navigated",
            "url": url_final,
            "title": title,
            "cloudflare_blocked": cf_blocked,
            "settled": not cf_blocked,
            "hint": (
                "Cloudflare detected. Use camoufox_cloudscraper_solve(page_id) to "
                "bypass with cloudscraper's JS solver, then re-navigate."
            ) if cf_blocked else None,
        }

    # --- Snapshot (PRIMARY page understanding) ---

    @mcp.tool()
    async def camoufox_snapshot(
        page_id: str,
        full: bool = False,
        max_length: int = 12000,
    ) -> dict[str, Any]:
        """Capture the page's accessibility tree — PRIMARY way to understand pages.

        Returns interactive elements with [@eN] ref IDs for camoufox_click,
        camoufox_type, etc. Call this BEFORE interacting with any page.

        Args:
            page_id: Target page ID.
            full: Include surrounding text context (default: False).
            max_length: Max characters in snapshot (default: 12000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, take_snapshot, page, page_id, _session, full, max_length)

    # --- Cloudscraper integration: HTTP-level CF bypass ---

    @mcp.tool()
    async def camoufox_cloudscraper_fetch(
        url: str,
        max_length: int = 50000,
        proxy: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Fetch a URL through cloudscraper, bypassing Cloudflare at the HTTP level.

        Use this when:
        - You need quick page content without full browser interaction
        - A target is behind Cloudflare and you want a fast, lightweight fetch
        - Camoufox browser is blocked and you want an alternative access path

        cloudscraper solves Cloudflare JS challenges (v1, v2, v3, Turnstile)
        using a requests.Session — no browser needed. Much faster than full
        browser navigation.

        The returned cookies can be injected into a Camoufox browser session
        via camoufox_cloudscraper_solve() so the browser can continue.

        Args:
            url: Full URL to fetch.
            max_length: Max characters in returned content (default: 50000).
            proxy: Optional proxy URL e.g. 'http://user:pass@host:port'.
            timeout: Request timeout in seconds (default: 30).

        Returns:
            {
                "status": "ok" | "cf_blocked" | "error",
                "url": final URL after redirects,
                "status_code": HTTP status,
                "content": extracted readable text,
                "cookies": {name: value, ...},
                "elapsed_ms": round-trip time,
            }
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            fetch_via_cloudscraper,
            url,
            max_length,
            proxy,
            timeout,
        )

    @mcp.tool()
    async def camoufox_cloudscraper_solve(
        page_id: str,
        proxy: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Use cloudscraper to solve Cloudflare and inject cookies into the browser.

        When Camoufox browser hits a Cloudflare challenge and you don't want
        to use human verification, this tool:
        1. Uses cloudscraper's JS solver to get valid clearance cookies
        2. Injects those cookies into the active Camoufox browser session
        3. The browser can then navigate past Cloudflare without challenge

        Call this after camoufox_navigate() returns cloudflare_blocked=true.
        After it succeeds, re-navigate with camoufox_navigate() — the browser
        will pass through Cloudflare with the injected cookies.

        Args:
            page_id: Page ID from the blocked browser session.
            proxy: Optional proxy URL.
            timeout: Request timeout in seconds (default: 30).

        Returns:
            {
                "status": "ok" | "cf_blocked" | "error",
                "cookies_injected": N,
                "cookie_names": [...],
                "next_step": "Call camoufox_navigate() again",
            }
        """
        page = _session.get_page(page_id)
        url = page.url
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            solve_and_inject,
            page,
            url,
            proxy,
            timeout,
        )

    # --- FlareSolverr integration: Docker-based CF bypass (hardest challenges) ---
    # Auto-start: camoufox_flaresolverr_fetch will start FlareSolverr if needed
    # Manage manually: camoufox_flaresolverr_start / _stop

    @mcp.tool()
    async def camoufox_flaresolverr_start() -> dict[str, Any]:
        """Start FlareSolverr Docker container if not running.

        Pulls the image if needed, creates a named container
        ('camoufox-flaresolverr'), and waits for it to become healthy.
        Safe to call even if already running (no-op).

        FlareSolverr solves Turnstile, JS VM v3, and CAPTCHA challenges
        that cloudscraper cannot handle.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, start_flaresolverr)

    @mcp.tool()
    async def camoufox_flaresolverr_stop() -> dict[str, Any]:
        """Stop the FlareSolverr Docker container.

        Frees resources when Tier 3 bypass is no longer needed.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, stop_flaresolverr)

    @mcp.tool()
    async def camoufox_flaresolverr_health() -> dict[str, Any]:
        """Check if FlareSolverr Docker container is running.

        FlareSolverr solves the hardest Cloudflare challenges (Turnstile,
        JS VM v3 "managed challenge") that cloudscraper can't handle.
        It requires Docker running on port 8191.

        Start it once:
          docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, check_flaresolverr_health)

    @mcp.tool()
    async def camoufox_flaresolverr_fetch(
        url: str,
        max_length: int = 50000,
        max_timeout: int = 60000,
        proxy: str | None = None,
    ) -> dict[str, Any]:
        """Fetch a URL through FlareSolverr — bypasses ALL Cloudflare protections.

        This is the HEAVY ARTILLERY for Cloudflare bypass. FlareSolverr runs
        headless Chromium with puppeteer-extra stealth plugin and solves:
        - Cloudflare Turnstile
        - JS VM v3 "managed challenge"
        - IUAM (I'm Under Attack Mode)
        - CAPTCHA challenges

        Use this when cloudscraper (camoufox_cloudscraper_fetch) fails with
        cf_blocked status. Requires Docker running FlareSolverr on port 8191.

        Slower than cloudscraper (1-10s vs 50-500ms) but bypasses everything.

        Start FlareSolverr (one-time):
          docker run -d --restart unless-stopped -p 8191:8191 flaresolverr/flaresolverr:latest

        Args:
            url: Target URL to fetch.
            max_length: Max characters in returned content (default: 50000).
            max_timeout: Max solve time in ms (default: 60000).
            proxy: Optional proxy URL for FlareSolverr's browser.

        Returns:
            {
                "status": "ok" | "cf_blocked" | "error",
                "url": final URL,
                "content": extracted readable text,
                "cookies": [...],
                "cf_clearance": "..." or None,
                "elapsed_ms": round-trip time,
                "solver": "flaresolverr (headless Chromium + puppeteer-extra)",
            }
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            fetch_via_flaresolverr,
            url,
            max_length,
            max_timeout,
            "http://localhost:8191/v1",
            proxy,
        )

    # --- Ref-based interaction ---

    @mcp.tool()
    async def camoufox_click(page_id: str, ref: str) -> dict[str, Any]:
        """Click an element by its [@eN] ref ID from camoufox_snapshot.

        Auto-retries once if element moved.

        Args:
            page_id: Target page ID.
            ref: Ref from snapshot e.g. '@e5' or 'e5'.
        """
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        loop = asyncio.get_event_loop()

        def _click():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            target.click(selector, timeout=5000)
            return {"status": "clicked", "ref": f"@{clean_ref}"}

        try:
            return await loop.run_in_executor(_executor, _click)
        except Exception as exc:
            # Retry once
            def _retry():
                target = page
                if frame_idx is not None:
                    frames = page.frames
                    if frame_idx < len(frames):
                        target = frames[frame_idx]
                target.click(selector, timeout=5000)
                return {"status": "clicked", "ref": f"@{clean_ref}"}
            try:
                return await loop.run_in_executor(_executor, _retry)
            except Exception:
                return _err(f"Click failed: {exc}")

    @mcp.tool()
    async def camoufox_type(
        page_id: str,
        ref: str,
        text: str,
        clear: bool = True,
        submit: bool = False,
    ) -> dict[str, Any]:
        """Type text into an input by ref from camoufox_snapshot.

        Args:
            page_id: Target page ID.
            ref: Ref from snapshot.
            text: Text to type.
            clear: Clear field first (default: True).
            submit: Press Enter after typing (default: False).
        """
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        loop = asyncio.get_event_loop()

        def _type():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            if clear:
                target.fill(selector, "")
            target.type(selector, text)
            if submit:
                target.press(selector, "Enter")
            return {"status": "typed", "ref": f"@{clean_ref}", "length": len(text), "submitted": submit}

        return await loop.run_in_executor(_executor, _type)

    @mcp.tool()
    async def camoufox_select(
        page_id: str,
        ref: str,
        value: str | None = None,
        label: str | None = None,
        index: int | None = None,
    ) -> dict[str, Any]:
        """Select a dropdown option by ref.

        Provide exactly one of: value, label, or index.
        """
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        loop = asyncio.get_event_loop()

        kwargs = {}
        if value is not None:
            kwargs["value"] = value
        elif label is not None:
            kwargs["label"] = label
        elif index is not None:
            kwargs["index"] = index
        else:
            return _err("Provide one of: value, label, or index.")

        def _select():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            selected = target.select_option(selector, **kwargs)
            return {"status": "selected", "ref": f"@{clean_ref}", "selected": selected}

        return await loop.run_in_executor(_executor, _select)

    @mcp.tool()
    async def camoufox_hover(page_id: str, ref: str) -> dict[str, Any]:
        """Hover over an element by ref."""
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        loop = asyncio.get_event_loop()

        def _hover():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            target.hover(selector)
            return {"status": "hovered", "ref": f"@{clean_ref}"}

        return await loop.run_in_executor(_executor, _hover)

    @mcp.tool()
    async def camoufox_scroll(
        page_id: str,
        direction: str = "down",
        amount: int = 500,
    ) -> dict[str, Any]:
        """Scroll the page.

        Args:
            page_id: Target page ID.
            direction: 'up' or 'down' (default: down).
            amount: Pixels to scroll (default: 500).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _scroll():
            if direction == "up":
                page.evaluate(f"window.scrollBy(0, -{amount})")
            else:
                page.evaluate(f"window.scrollBy(0, {amount})")
            page.wait_for_timeout(300)
            return {"status": "scrolled", "direction": direction, "amount": amount}

        return await loop.run_in_executor(_executor, _scroll)

    @mcp.tool()
    async def camoufox_evaluate(page_id: str, expression: str) -> dict[str, Any]:
        """Execute JavaScript in the page context.

        Args:
            page_id: Target page ID.
            expression: JavaScript expression to evaluate.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _eval():
            result = page.evaluate(expression)
            return {"status": "evaluated", "result": result}

        return await loop.run_in_executor(_executor, _eval)

    # --- Content extraction ---

    @mcp.tool()
    async def camoufox_read_page(page_id: str, max_length: int = 50000) -> dict[str, Any]:
        """Extract page content as clean markdown.

        Strips navigation, ads, footers — returns just main content.

        Args:
            page_id: Target page ID.
            max_length: Max characters (default: 50000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, extract_markdown, page, max_length)

    @mcp.tool()
    async def camoufox_screenshot(page_id: str, full_page: bool = False) -> dict[str, Any]:
        """Take an annotated screenshot with element indices overlaid.

        Args:
            page_id: Target page ID.
            full_page: Capture entire scrollable page (default: False).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, take_screenshot, page, full_page)

    @mcp.tool()
    async def camoufox_wait(page_id: str, timeout_ms: int = 5000) -> dict[str, Any]:
        """Wait for the page to settle (no DOM mutations + network idle).

        Args:
            page_id: Target page ID.
            timeout_ms: Max wait time in ms (default: 5000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _wait():
            page.wait_for_load_state("networkidle", timeout=timeout_ms / 1000)
            return {"status": "settled", "elapsed_ms": timeout_ms}

        try:
            return await loop.run_in_executor(_executor, _wait)
        except Exception:
            return {"status": "not_settled", "elapsed_ms": timeout_ms, "note": "networkidle timeout reached"}

    @mcp.tool()
    async def camoufox_get_dialogs(page_id: str, filter_text: str | None = None) -> dict[str, Any]:
        """Get captured JavaScript dialogs (alert/confirm/prompt).

        Dialogs are auto-accepted to prevent blocking. This retrieves the log.

        Args:
            page_id: Target page ID.
            filter_text: Optional — only return dialogs containing this string.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _get_dialogs():
            # Playwright captures dialog events - get them from page context
            # We store dialogs in a JS variable on the page
            try:
                result = page.evaluate("""
                    () => {
                        if (!window._camoufox_dialogs) return [];
                        return window._camoufox_dialogs;
                    }
                """)
                dialogs = json.loads(result) if result else []
                if filter_text:
                    dialogs = [d for d in dialogs if filter_text.lower() in d.get("message", "").lower()]
                return {"status": "ok", "dialogs": dialogs, "count": len(dialogs)}
            except Exception:
                return {"status": "ok", "dialogs": [], "count": 0, "note": "No dialogs captured"}

        return await loop.run_in_executor(_executor, _get_dialogs)

    @mcp.tool()
    async def camoufox_list_pages() -> dict[str, Any]:
        """List all open pages (page_id + URL)."""
        return {"status": "ok", "pages": _session.list_pages()}

    return mcp