"""CamoufoxMCP server — stealth browser automation for AI agents.

~35 tools. Snapshot-first. Two-tier Cloudflare bypass (cloudscraper + FlareSolverr).
Bug bounty tools: JS extraction, network capture, authenticated API calls, token extraction.
Playwright MCP parity: press keys, back/forward, console logs, tab management, cookies,
file upload, annotated screenshots, real dialog capture.
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

from .session import BrowserSession, SessionConfig, BrowserSessionError, PageNotFoundError, PageClosedError, _random_viewport, _detect_screen_size
from .snapshot import take_snapshot, resolve_ref
from .markdown import extract_markdown
from .vision import take_screenshot
from .cloudscraper_bridge import fetch_via_cloudscraper, solve_and_inject
from .flaresolverr_bridge import (
    fetch_via_flaresolverr,
    fetch_raw_via_flaresolverr,
    solve_via_flaresolverr,
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

def _resolve_page(page_id: str | None = None):
    """Get page — use explicit page_id or fall back to active page."""
    if page_id:
        return _session.get_page(page_id), page_id
    active = _session.active_page_id
    if not active:
        raise BrowserSessionError("No active page. Launch browser and navigate first.")
    return _session.get_page(active), active


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
            "4. camoufox_click / camoufox_type / camoufox_scroll / camoufox_press — interact\n"
            "5. camoufox_read_page(page_id) — page as clean markdown\n"
            "6. camoufox_screenshot(page_id) — screenshot (with optional element annotation)\n"
            "7. camoufox_close() — done\n\n"
            "REF-BASED TOOLS accept [@eN] snapshot refs OR raw CSS selectors.\n"
            "When an element isn't captured by the snapshot (e.g. inside a React portal\n"
            "or popover), use a CSS selector directly: 'input[name=\"email\"]', '#submit', etc.\n\n"
            "BATCH FORM FILLING:\n"
            "camoufox_fill_form(page_id, fields) — fill multiple form fields in one call\n\n"
            "DRAG & DROP:\n"
            "camoufox_drag(page_id, start, end) — drag one element onto another\n\n"
            "KEYBOARD & NAVIGATION:\n"
            "camoufox_press(page_id, key) — press Enter, Tab, Escape, ArrowDown, etc.\n"
            "camoufox_back(page_id) — navigate back in history\n"
            "camoufox_console(page_id) — get browser console messages (JS errors, warnings)\n\n"
            "JAVASCRIPT:\n"
            "camoufox_evaluate(page_id, expression, timeout) — run sync or async JS\n\n"
            "TAB MANAGEMENT:\n"
            "camoufox_new_page() — open additional tab\n"
            "camoufox_list_pages() — see all open tabs\n"
            "camoufox_close_page(page_id) — close a tab\n\n"
            "COOKIES:\n"
            "camoufox_get_cookies(urls) — get browser cookies (optionally filtered)\n"
            "camoufox_set_cookies(cookies) — set cookies\n"
            "camoufox_clear_cookies() — clear all cookies\n\n"
            "CLOUDFLARE BYPASS (two tiers, escalate as needed):\n"
            "Tier 1 (fast, no Docker): camoufox_cloudscraper_fetch(url)\n"
            "  HTTP-level JS solver. Handles IUAM, v1, v2. ~100-500ms.\n"
            "  Also: camoufox_cloudscraper_solve(page_id) to inject\n"
            "  cookies into active browser context.\n"
            "Tier 2 (heavy artillery): camoufox_flaresolverr_fetch(url)\n"
            "  Docker-based headless Chromium. Solves Turnstile, JS VM v3,\n"
            "  managed challenges — bypasses EVERYTHING. ~1-15s.\n"
            "  Auto-starts Docker container on first use.\n\n"
            "WHEN BROWSER IS BLOCKED (camoufox_navigate → cloudflare_blocked=true):\n"
            "  1. camoufox_cloudscraper_fetch(url) — fast HTTP bypass\n"
            "  2. If blocked, camoufox_flaresolverr_fetch(url) — guaranteed bypass\n\n"
            "BUG BOUNTY TOOLS:\n"
            "camoufox_extract_tokens(page_id) — grab JWT, CSRF, cookies from session\n"
            "camoufox_api_call(page_id, method, path) — make API call with browser auth\n"
            "camoufox_js_extract(page_id) — find endpoints/secrets in loaded JS\n"
            "camoufox_network_capture(page_id) — capture XHR/fetch traffic\n\n"
            "KEY DIFFERENCE from CloakBrowser:\n"
            "Camoufox is Firefox-based Playwright with two-tier Cloudflare bypass —\n"
            "cloudscraper (fast HTTP) → FlareSolverr (Docker Chromium, guaranteed)."
        ),
    )

    # ==================================================================
    # Browser lifecycle
    # ==================================================================

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

        if headless:
            vp = _random_viewport()
            w = viewport_width or vp["width"]
            h = viewport_height or vp["height"]
        else:
            detected_w, detected_h = _detect_screen_size()
            w = viewport_width or detected_w
            h = viewport_height or detected_h

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

    @mcp.tool()
    async def camoufox_resize_viewport(
        width: int = 0,
        height: int = 0,
    ) -> dict[str, Any]:
        """Resize the browser viewport to specific dimensions or auto-fit the screen.

        Use this in headed mode to make the browser window fit the user's actual
        display. Pass width=0, height=0 to auto-detect the screen size on macOS.

        New pages created after this call inherit the resized viewport.

        Args:
            width: Desired width in pixels (0 = auto-detect from screen).
            height: Desired height in pixels (0 = auto-detect from screen).
        """
        if not _session.is_running:
            return _err("Browser not running. Call camoufox_launch() first.")
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, lambda: _session.resize_viewport_sync(width, height))

    # ==================================================================
    # Page / tab management
    # ==================================================================

    @mcp.tool()
    async def camoufox_new_page() -> dict[str, Any]:
        """Open a new tab/page in the existing browser session.

        The new page becomes the active page. Use camoufox_list_pages()
        to see all open tabs, and camoufox_navigate() on the returned
        page_id to load a URL.

        Returns:
            {"status": "created", "page_id": "page_abc123", "active": true}
        """
        page_id = await _session.new_page()
        return {
            "status": "created",
            "page_id": page_id,
            "active": True,
            "hint": "Next: camoufox_navigate(page_id, url)",
        }

    @mcp.tool()
    async def camoufox_close_page(page_id: str) -> dict[str, Any]:
        """Close a specific page/tab.

        Args:
            page_id: Page ID to close.
        """
        await _session.close_page(page_id)
        return {"status": "closed", "page_id": page_id}

    @mcp.tool()
    async def camoufox_list_pages() -> dict[str, Any]:
        """List all open pages (page_id + URL)."""
        return {"status": "ok", "pages": _session.list_pages()}

    # ==================================================================
    # Navigation
    # ==================================================================

    @mcp.tool()
    async def camoufox_navigate(page_id: str, url: str, timeout: int = 30000) -> dict[str, Any]:
        """Navigate to a URL with smart waiting.

        Returns cloudflare_blocked=true if Cloudflare challenge detected.
        In that case call camoufox_cloudscraper_solve() or camoufox_flaresolverr_solve().

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

    @mcp.tool()
    async def camoufox_back(page_id: str | None = None) -> dict[str, Any]:
        """Navigate back to the previous page in browser history.

        Args:
            page_id: Target page ID. Uses active page if omitted.
        """
        page, pid = _resolve_page(page_id)
        loop = asyncio.get_event_loop()

        def _back():
            page.go_back(wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(2000)
            return {"url": page.url, "title": page.title()}

        result = await loop.run_in_executor(_executor, _back)
        return {"status": "navigated", "url": result["url"], "title": result["title"], "page_id": pid}

    # ==================================================================
    # Snapshot (PRIMARY page understanding)
    # ==================================================================

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

    # ==================================================================
    # Keyboard & input
    # ==================================================================

    @mcp.tool()
    async def camoufox_press(page_id: str | None = None, key: str = "Enter") -> dict[str, Any]:
        """Press a keyboard key. Useful for submitting forms (Enter), navigating (Tab),
        or keyboard shortcuts.

        Args:
            page_id: Target page ID. Uses active page if omitted.
            key: Key to press (e.g., 'Enter', 'Tab', 'Escape', 'ArrowDown').
        """
        page, pid = _resolve_page(page_id)
        loop = asyncio.get_event_loop()

        def _press():
            page.keyboard.press(key)
            page.wait_for_timeout(500)
            return {"status": "pressed", "key": key}

        return await loop.run_in_executor(_executor, _press)

    # ==================================================================
    # Ref-based interaction
    # ==================================================================

    @mcp.tool()
    async def camoufox_click(
        page_id: str,
        ref: str,
        double: bool = False,
    ) -> dict[str, Any]:
        """Click an element by ref from camoufox_snapshot, or by CSS selector.

        Accepts [@eN] snapshot refs, frame refs, or raw CSS selectors
        (e.g. 'button[data-testid="submit"]', '#login-btn', '.primary-button').
        Auto-retries once if element moved.

        Args:
            page_id: Target page ID.
            ref: Ref from snapshot e.g. '@e5', 'e5', or a CSS selector.
            double: Double-click instead of single click (default: False).
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
            if double:
                target.dblclick(selector, timeout=5000)
            else:
                target.click(selector, timeout=5000)
            return {"status": "clicked", "ref": f"@{clean_ref}", "double": double}

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
                if double:
                    target.dblclick(selector, timeout=5000)
                else:
                    target.click(selector, timeout=5000)
                return {"status": "clicked", "ref": f"@{clean_ref}", "double": double}
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
        """Type text into an input by ref from camoufox_snapshot, or by CSS selector.

        Accepts [@eN] snapshot refs, frame refs, or raw CSS selectors
        (e.g. 'input[name="email"]', '#password', '.search-input').

        Args:
            page_id: Target page ID.
            ref: Ref from snapshot, or a CSS selector.
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
    async def camoufox_fill_form(
        page_id: str,
        fields: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Fill multiple form fields at once.

        Each field is a dict with:
          - name: Human-readable field name (for logging)
          - target: Ref from snapshot or CSS selector for the input element
          - type: 'textbox', 'checkbox', 'radio', 'combobox', or 'slider'
          - value: Value to fill (string for textbox/combobox/slider, bool for checkbox, string for radio value)

        Args:
            page_id: Target page ID.
            fields: List of field dicts, e.g.
                [{"name": "Email", "target": "input[name='email']", "type": "textbox", "value": "user@example.com"},
                 {"name": "Agree", "target": "@e15", "type": "checkbox", "value": true}]
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _fill():
            results = []
            for f in fields:
                name = f.get("name", "unnamed")
                target_raw = f.get("target", "")
                field_type = f.get("type", "textbox")
                value = f.get("value")

                if not target_raw:
                    results.append({"field": name, "status": "error", "error": "No target provided"})
                    continue

                _, selector, _ = resolve_ref(_session, page_id, target_raw)

                try:
                    if field_type == "textbox":
                        page.fill(selector, str(value) if value is not None else "")
                        results.append({"field": name, "status": "filled", "value": value})

                    elif field_type == "checkbox":
                        if value:
                            page.check(selector)
                        else:
                            page.uncheck(selector)
                        results.append({"field": name, "status": "toggled", "checked": bool(value)})

                    elif field_type == "radio":
                        page.check(selector)
                        results.append({"field": name, "status": "selected", "value": value})

                    elif field_type == "combobox":
                        page.select_option(selector, str(value) if value is not None else "")
                        results.append({"field": name, "status": "selected", "value": value})

                    elif field_type == "slider":
                        page.fill(selector, str(value) if value is not None else "")
                        results.append({"field": name, "status": "set", "value": value})

                    else:
                        results.append({"field": name, "status": "error", "error": f"Unknown type: {field_type}"})
                except Exception as exc:
                    results.append({"field": name, "status": "error", "error": str(exc)})

            return {"status": "ok", "filled": len([r for r in results if r["status"] != "error"]),
                    "errors": len([r for r in results if r["status"] == "error"]),
                    "fields": results}

        return await loop.run_in_executor(_executor, _fill)

    @mcp.tool()
    async def camoufox_select(
        page_id: str,
        ref: str,
        value: str | None = None,
        label: str | None = None,
        index: int | None = None,
    ) -> dict[str, Any]:
        """Select a dropdown option by ref from camoufox_snapshot, or by CSS selector.

        Provide exactly one of: value, label, or index.
        Accepts [@eN] snapshot refs or raw CSS selectors (e.g. 'select[name="country"]').
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
        """Hover over an element by ref from camoufox_snapshot, or by CSS selector.

        Accepts [@eN] snapshot refs or raw CSS selectors.
        """
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
    async def camoufox_drag(
        page_id: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Drag an element onto another element.

        Accepts [@eN] snapshot refs or raw CSS selectors for both start and end.

        Args:
            page_id: Target page ID.
            start: Ref or CSS selector for the element to drag.
            end: Ref or CSS selector for the drop target.
        """
        page = _session.get_page(page_id)
        start_clean, start_sel, start_frame = resolve_ref(_session, page_id, start)
        end_clean, end_sel, end_frame = resolve_ref(_session, page_id, end)
        loop = asyncio.get_event_loop()

        def _drag():
            start_target = page
            if start_frame is not None:
                frames = page.frames
                if start_frame < len(frames):
                    start_target = frames[start_frame]
            end_target = page
            if end_frame is not None:
                frames = page.frames
                if end_frame < len(frames):
                    end_target = frames[end_frame]

            start_target.drag_and_drop(start_sel, end_sel)
            return {"status": "dragged", "from": start_clean, "to": end_clean}

        return await loop.run_in_executor(_executor, _drag)

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
    async def camoufox_evaluate(
        page_id: str,
        expression: str,
        timeout: int = 30000,
    ) -> dict[str, Any]:
        """Execute JavaScript in the page context.

        Supports sync and async expressions. Async functions are automatically
        awaited by Playwright. Use this to read page state, manipulate the DOM,
        or interact with JavaScript APIs.

        Args:
            page_id: Target page ID.
            expression: JavaScript expression or async function, e.g.:
                'document.title'
                '() => { return { url: location.href, cookies: document.cookie }; }'
                'async () => { await new Promise(r => setTimeout(r, 1000)); return "done"; }'
            timeout: Max wait time in ms for async expressions (default: 30000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _eval():
            result = page.evaluate(expression)
            return {"status": "evaluated", "result": result}

        return await loop.run_in_executor(_executor, _eval)

    @mcp.tool()
    async def camoufox_file_upload(page_id: str, ref: str, file_paths: str) -> dict[str, Any]:
        """Upload files to a file input element identified by ref from camoufox_snapshot, or by CSS selector.

        Args:
            page_id: Target page ID.
            ref: Ref from snapshot pointing to a file input, or a CSS selector.
            file_paths: Comma-separated absolute file paths to upload.
        """
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        files = [p.strip() for p in file_paths.split(",") if p.strip()]
        if not files:
            return _err("No file paths provided.")

        loop = asyncio.get_event_loop()

        def _upload():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            target.set_input_files(selector, files)
            return {"status": "uploaded", "ref": f"@{clean_ref}", "files": files, "count": len(files)}

        return await loop.run_in_executor(_executor, _upload)

    # ==================================================================
    # Content extraction
    # ==================================================================

    @mcp.tool()
    async def camoufox_read_page(page_id: str, max_length: int = 50000) -> dict[str, Any]:
        """Extract page content as clean markdown.

        Uses trafilatura (production-grade readability) when available,
        falls back to regex-based extraction. Strips navigation, ads, footers.

        Args:
            page_id: Target page ID.
            max_length: Max characters (default: 50000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, extract_markdown, page, max_length)

    @mcp.tool()
    async def camoufox_screenshot(
        page_id: str,
        full_page: bool = False,
        annotate: bool = False,
    ) -> dict[str, Any]:
        """Take a screenshot, optionally with numbered element annotations.

        When annotate=True, overlays numbered badges [1] [2] ... on interactive
        elements. Match badge numbers to [@eN] refs from camoufox_snapshot().

        Args:
            page_id: Target page ID.
            full_page: Capture entire scrollable page (default: False).
            annotate: Overlay numbered element indices (default: False).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor, take_screenshot, page, full_page, annotate, _session, page_id,
        )

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

    # ==================================================================
    # Dialogs & console
    # ==================================================================

    @mcp.tool()
    async def camoufox_get_dialogs(
        page_id: str | None = None,
        filter_text: str | None = None,
    ) -> dict[str, Any]:
        """Get captured JavaScript dialogs (alert/confirm/prompt).

        Dialogs are auto-dismissed to prevent blocking. This retrieves the log.

        Args:
            page_id: Target page ID. Uses active page if omitted.
            filter_text: Optional — only return dialogs containing this string.
        """
        _, pid = _resolve_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, _session.get_dialogs, pid, filter_text)

    @mcp.tool()
    async def camoufox_console(
        page_id: str | None = None,
        filter_text: str | None = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """Get browser console messages (JS errors, warnings, logs).

        Useful for debugging JavaScript errors on the page, finding which
        API calls failed, and discovering app behaviour.

        Args:
            page_id: Target page ID. Uses active page if omitted.
            filter_text: Optional — only return messages containing this string.
            clear: If true, clear console messages after reading.
        """
        _, pid = _resolve_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, _session.get_console, pid, filter_text, clear)

    # ==================================================================
    # Cookie management
    # ==================================================================

    @mcp.tool()
    async def camoufox_get_cookies(urls: str | None = None) -> dict[str, Any]:
        """Get cookies from the browser context.

        Args:
            urls: Optional comma-separated URLs to filter cookies by domain.
                  If omitted, returns all cookies.
        """
        url_list = [u.strip() for u in urls.split(",") if u.strip()] if urls else None
        loop = asyncio.get_event_loop()

        def _get():
            cookies = _session.get_cookies(url_list)
            return {"status": "ok", "cookies": cookies, "count": len(cookies)}

        return await loop.run_in_executor(_executor, _get)

    @mcp.tool()
    async def camoufox_set_cookies(cookies_json: str) -> dict[str, Any]:
        """Set cookies in the browser context.

        Args:
            cookies_json: JSON string of cookie objects, e.g.
                '[{"name":"session","value":"abc","domain":".example.com","path":"/"}]'
        """
        try:
            cookies = json.loads(cookies_json)
            if not isinstance(cookies, list):
                return _err("cookies_json must be a JSON array of cookie objects.")
        except json.JSONDecodeError as e:
            return _err(f"Invalid JSON: {e}")

        loop = asyncio.get_event_loop()

        def _set():
            _session.set_cookies(cookies)
            return {"status": "set", "count": len(cookies)}

        return await loop.run_in_executor(_executor, _set)

    @mcp.tool()
    async def camoufox_clear_cookies() -> dict[str, Any]:
        """Clear all cookies from the browser context."""
        loop = asyncio.get_event_loop()

        def _clear():
            _session.clear_cookies()
            return {"status": "cleared"}

        return await loop.run_in_executor(_executor, _clear)

    # ==================================================================
    # Cloudscraper integration: HTTP-level CF bypass
    # ==================================================================

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
            proxy: Optional proxy URL e.g. 'http://user:***@host:port'.
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

    # ==================================================================
    # FlareSolverr integration: Docker-based CF bypass (hardest challenges)
    # ==================================================================

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

        Returns a 'links' array with structured link data — use this to
        discover files/pages in directory listings (like VX-Underground).

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

    @mcp.tool()
    async def camoufox_flaresolverr_solve(
        page_id: str,
        url: str | None = None,
        proxy: str | None = None,
        max_timeout: int = 60000,
    ) -> dict[str, Any]:
        """Use FlareSolverr to bypass Cloudflare — sets up persistent proxy routing.

        This is the ULTIMATE Cloudflare bypass for Camoufox browser. Instead
        of just injecting cookies (which fail due to fingerprint binding),
        this tool sets up Playwright route interception: ALL requests to the
        CF-protected domain are proxied through FlareSolverr's headless
        Chromium, which has CF clearance.

        After this call, the browser can navigate the target domain normally:
        camoufox_navigate(), camoufox_click(), camoufox_snapshot() — all
        work because network traffic flows through FlareSolverr.

        Workflow:
        1. camoufox_launch() → navigate → cf_blocked
        2. camoufox_flaresolverr_solve(page_id) → routes set up
        3. camoufox_navigate(page_id, same URL) → page loads!
        4. All subsequent navigation/clicks on that domain → transparent

        Args:
            page_id: Page ID from the browser session.
            url: Target URL (defaults to current page URL).
            proxy: Optional proxy URL for FlareSolverr.
            max_timeout: Max solve time in ms (default: 60000).

        Returns:
            {
                "status": "ok" | "cf_blocked" | "error",
                "domain": "example.com",
                "routes_active": True,
                "next_step": "Call camoufox_navigate() — all requests proxied through FlareSolverr",
            }
        """
        page = _session.get_page(page_id)
        target_url = url or page.url
        loop = asyncio.get_event_loop()

        def _solve_and_setup_proxy():
            from urllib.parse import urlparse
            import re as _re

            # Step 1: Prime FlareSolverr — solve CF for this domain
            solve_result = solve_via_flaresolverr(
                target_url, max_timeout,
                "http://localhost:8191/v1", proxy,
            )
            if solve_result.get("status") != "ok":
                return solve_result

            # Step 2: Inject cookies into browser context
            cookies = solve_result.get("cookies", [])
            cookie_names = []
            if cookies:
                context = page.context
                context.add_cookies(cookies)
                cookie_names = [c["name"] for c in cookies]
                logger.info("Injected %d FlareSolverr cookies: %s",
                            len(cookies), cookie_names)

            # Step 3: Extract domain
            domain = urlparse(target_url).netloc
            if not domain:
                return {"status": "error", "url": target_url,
                        "error": "Could not extract domain from URL"}

            # Step 4: Set up persistent route interception
            # Only proxy main document/xhr/fetch requests — subresources load directly
            def _proxy_route(route):
                if route.request.resource_type not in ("document", "xhr", "fetch"):
                    route.continue_()
                    return

                req_url = route.request.url
                try:
                    result = fetch_raw_via_flaresolverr(
                        req_url, max_timeout=30000,
                        flaresolverr_url="http://localhost:8191/v1",
                        proxy=proxy,
                    )
                    if result.get("status") == "ok":
                        route.fulfill(
                            status=result.get("status_code", 200),
                            headers=result.get("headers",
                                {"content-type": "text/html; charset=utf-8"}),
                            body=result.get("body", b""),
                        )
                        return
                except Exception as e:
                    logger.warning("FlareSolverr route proxy error: %s", e)
                try:
                    route.continue_()
                except Exception:
                    pass

            route_re = _re.compile(rf"https?://{_re.escape(domain)}/.*")
            page.route(route_re, _proxy_route)
            page.route(f"**/*{domain}**", _proxy_route)
            logger.info("FlareSolverr route interception ACTIVE for: %s", domain)

            return {
                "status": "ok",
                "url": solve_result.get("url", target_url),
                "domain": domain,
                "routes_active": True,
                "cookies_injected": len(cookie_names),
                "cookie_names": cookie_names,
                "cf_clearance": solve_result.get("cf_clearance"),
                "next_step": (
                    "Route interception ACTIVE. Call camoufox_navigate() — "
                    "ALL requests to this domain proxy through FlareSolverr's "
                    "Chromium, bypassing Cloudflare transparently. All subsequent "
                    "navigation, clicks, and snapshots on this domain work normally."
                ),
            }

        return await loop.run_in_executor(_executor, _solve_and_setup_proxy)

    # ==================================================================
    # Bug bounty / authenticated API tools
    # ==================================================================

    @mcp.tool()
    async def camoufox_extract_tokens(page_id: str) -> dict[str, Any]:
        """Extract authentication tokens from the current page context.

        Pulls JWT, CSRF token, session cookies, and API keys from the browser's
        current session. Use this after logging in to capture credentials for
        direct API testing.

        Args:
            page_id: Target page ID.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _extract():
            tokens = page.evaluate("""
                () => {
                    const result = {};

                    // Cookies
                    result.cookies = document.cookie ? document.cookie.split(';').map(c => c.trim()).filter(Boolean) : [];

                    // CSRF from meta tags
                    const csrfMeta = document.querySelector('meta[name="csrf-token"], meta[name="csrf"], meta[name="_csrf"], meta[name="csrf-param"]');
                    if (csrfMeta) result.metaCsrf = csrfMeta.content || csrfMeta.getAttribute('value');

                    // Try localStorage for common token keys
                    const storageTokens = {};
                    for (const key of ['jwtToken', 'csrfToken', 'token', 'auth', 'authToken', 'accessToken', 'access_token', 'idToken', 'refreshToken', 'refresh_token']) {
                        try {
                            const val = localStorage.getItem(key);
                            if (val) storageTokens[key] = val.length > 80 ? (val.slice(0, 40) + '...' + val.slice(-20)) : val;
                        } catch(e) {}
                    }
                    if (Object.keys(storageTokens).length) result.storageTokens = storageTokens;

                    // sessionStorage
                    const sessionTokens = {};
                    for (const key of ['jwtToken', 'csrfToken', 'token', 'auth', 'authToken', 'accessToken']) {
                        try {
                            const val = sessionStorage.getItem(key);
                            if (val) sessionTokens[key] = val.length > 80 ? (val.slice(0, 40) + '...' + val.slice(-20)) : val;
                        } catch(e) {}
                    }
                    if (Object.keys(sessionTokens).length) result.sessionTokens = sessionTokens;

                    // Check for JWT in Authorization header pattern (from XHR intercepts)
                    result.note = 'Injected JWT/CSRF are NOT captured here. Login as a user, then call this tool.';

                    return result;
                }
            """)
            return {"status": "ok", "tokens": tokens}

        return await loop.run_in_executor(_executor, _extract)

    @mcp.tool()
    async def camoufox_api_call(
        page_id: str,
        method: str,
        path: str,
        body: str | None = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        """Make an API call using the browser's authenticated session.

        Uses the browser's cookies, and auto-detects CSRF tokens from meta tags
        or localStorage. Works with any web app — no hardcoded paths.

        Args:
            page_id: Target page ID.
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            path: API path (e.g. '/api/v1/users/1').
            body: JSON body for POST/PUT/PATCH requests.
            content_type: Content-Type header (default: application/json).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        # Escape for safe embedding in JS template
        safe_path = path.replace("\\", "\\\\").replace("'", "\\'")
        safe_method = method.upper()
        safe_content_type = content_type.replace("\\", "\\\\").replace("'", "\\'")
        body_str = json.dumps(body) if body else "null"

        def _call():
            result = page.evaluate(f"""
                async () => {{
                    try {{
                        // Get CSRF from meta tags or localStorage
                        let csrf = '';
                        const csrfMeta = document.querySelector('meta[name="csrf-token"], meta[name="csrf"], meta[name="_csrf"]');
                        if (csrfMeta) csrf = csrfMeta.content || csrfMeta.getAttribute('value') || '';
                        if (!csrf) {{
                            for (const key of ['csrfToken', 'csrf-token', '_csrf']) {{
                                try {{ csrf = localStorage.getItem(key) || ''; if (csrf) break; }} catch(e) {{}}
                            }}
                        }}

                        const headers = {{
                            'Accept': 'application/json',
                            'Content-Type': '{safe_content_type}',
                        }};
                        if (csrf && !['GET', 'HEAD', 'OPTIONS'].includes('{safe_method}')) {{
                            headers['X-CSRF-Token'] = csrf;
                            headers['X-CSRFToken'] = csrf;
                        }}

                        const fetchOpts = {{
                            method: '{safe_method}',
                            headers: headers,
                            credentials: 'include',
                        }};
                        if (['POST', 'PUT', 'PATCH'].includes('{safe_method}') && {body_str}) {{
                            fetchOpts.body = JSON.stringify({body_str});
                        }}

                        const resp = await fetch('{safe_path}', fetchOpts);
                        const text = await resp.text();
                        let data;
                        try {{ data = JSON.parse(text); }} catch(e) {{ data = text; }}

                        return {{
                            status: resp.status,
                            statusText: resp.statusText,
                            data: typeof data === 'string' ? data.slice(0, 5000) : data,
                            headers: Object.fromEntries(resp.headers.entries())
                        }};
                    }} catch(e) {{
                        return {{ error: e.message }};
                    }}
                }}
            """)
            return {"status": "ok", "method": safe_method, "path": path, **result}

        return await loop.run_in_executor(_executor, _call)

    @mcp.tool()
    async def camoufox_js_extract(
        page_id: str,
        search_patterns: str = "api,csrf,token,secret,key,endpoint,graphql,websocket,admin,support",
    ) -> dict[str, Any]:
        """Extract API endpoints, secrets, and auth logic from loaded JS bundles.

        Downloads all JS files loaded on the current page, searches them for
        API paths, authentication tokens, and other security-relevant patterns.
        Use this to discover hidden API endpoints and understand the auth flow.

        Args:
            page_id: Target page ID.
            search_patterns: Comma-separated patterns to search for.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _extract():
            result = page.evaluate(f"""
                () => {{
                    const patterns = '{search_patterns}'.split(',').map(p => p.trim());
                    const results = {{ endpoints: [], secrets: [], authPatterns: [] }};

                    // Get all script URLs from the page
                    const scripts = Array.from(document.querySelectorAll('script[src]'));
                    const scriptUrls = scripts.map(s => s.src).filter(s => s);

                    // Also check inline scripts
                    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent).filter(t => t && t.length > 100);

                    // Extract API paths from all scripts
                    const allText = inlineScripts.join('\\n');
                    const apiPaths = allText.match(/['"`]\\/api\\/[a-zA-Z0-9_\\/.-]+['\"`]/g) || [];
                    results.endpoints = [...new Set(apiPaths.map(p => p.replace(/['\"`]/g, '')))].slice(0, 100);

                    // Search for secrets/keys
                    for (const pattern of ['secret', 'key', 'token', 'password']) {{
                        const re = new RegExp(pattern + '[\\\\s]*[=:][\\\\s]*['\\\"`]([^'\\\"`]{{8,}})['\\\"`]', 'gi');
                        let match;
                        while ((match = re.exec(allText)) !== null) {{
                            if (!match[1].includes('{{') && !match[1].includes('function') && !match[1].includes('require')) {{
                                results.secrets.push({{ pattern, value: match[1].slice(0, 40) + '...', source: 'inline' }});
                            }}
                        }}
                    }}

                    // Look for auth-related patterns
                    const authPatterns = allText.match(/['\"`](csrf|jwt|bearer|authorization|authenticate|oauth)['\"`]/gi) || [];
                    results.authPatterns = [...new Set(authPatterns.map(a => a.replace(/['\"`]/g, '')))];

                    // Count JS files
                    results.scriptCount = scriptUrls.length;
                    results.scriptUrls = scriptUrls.slice(0, 20);

                    return results;
                }}
            """)
            return {"status": "ok", **result}

        return await loop.run_in_executor(_executor, _extract)

    @mcp.tool()
    async def camoufox_network_capture(
        page_id: str,
        url_filter: str | None = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """Capture browser network requests for API endpoint discovery.

        Monitors XHR/fetch requests made by the page. Use this to discover
        real API endpoints by interacting with the page and then capturing
        what requests the React app actually makes.

        Args:
            page_id: Target page ID.
            url_filter: Optional substring filter for request URLs.
            clear: If true, clear captured requests after reading.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _capture():
            # Ensure the capture array exists
            page.evaluate("""
                if (!window._camoufox_network) {
                    window._camoufox_network = [];
                    const origFetch = window.fetch;
                    window.fetch = function(...args) {
                        const entry = {
                            url: typeof args[0] === 'string' ? args[0] : args[0].url,
                            method: (args[1] && args[1].method) || 'GET',
                            body: (args[1] && args[1].body) ? String(args[1].body).slice(0, 500) : null,
                            timestamp: Date.now()
                        };
                        window._camoufox_network.push(entry);
                        return origFetch.apply(this, args);
                    };

                    // Also hook XHR
                    const origXHROpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) {
                        this._camoufox_method = method;
                        this._camoufox_url = url;
                        this._camoufox_start = Date.now();
                        return origXHROpen.apply(this, arguments);
                    };
                    const origXHRSend = XMLHttpRequest.prototype.send;
                    XMLHttpRequest.prototype.send = function(body) {
                        window._camoufox_network.push({
                            url: this._camoufox_url,
                            method: this._camoufox_method,
                            body: body ? String(body).slice(0, 500) : null,
                            timestamp: this._camoufox_start,
                            type: 'xhr'
                        });
                        return origXHRSend.apply(this, arguments);
                    };
                }
            """)

            # Get captured requests — properly handle clear parameter
            url_filter_js = "null" if url_filter is None else f"'{url_filter}'"
            clear_js = "true" if clear else "false"

            raw = page.evaluate(f"""
                () => {{
                    const requests = window._camoufox_network || [];
                    const filter = {url_filter_js};
                    const shouldClear = {clear_js};
                    const filtered = filter
                        ? requests.filter(r => r.url && r.url.includes(filter))
                        : requests;
                    const result = {{
                        total: requests.length,
                        filtered: filtered.length,
                        requests: filtered.slice(-50)  // Last 50 requests
                    }};
                    if (shouldClear) {{
                        window._camoufox_network = [];
                    }}
                    return result;
                }}
            """)
            return {"status": "ok", **raw}

        return await loop.run_in_executor(_executor, _capture)

    return mcp
