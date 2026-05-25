"""BrowserSession — manages Camoufox browser lifecycle, pages, and contexts.

Playwright MCP quality: dialog auto-capture, console capture, network response
capture, page management (create/switch/close), active-page tracking.
"""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("camoufoxmcp")


def _random_viewport(seed: int | None = None) -> dict[str, int]:
    """Return a randomized headless viewport from realistic 1080p laptop pool."""
    rng = random.Random(seed)
    bases = [(1920, 947), (1920, 1000), (1366, 768), (1440, 900), (1512, 982)]
    w, h = rng.choice(bases)
    w = w + rng.randint(-20, 20)
    h = h + rng.randint(-10, 10)
    return {"width": w, "height": h}


class BrowserSessionError(RuntimeError):
    """Raised when the browser session is in an invalid state."""


class PageNotFoundError(KeyError):
    """Raised when a page_id doesn't exist in the session."""


class PageClosedError(BrowserSessionError):
    """Raised when a page exists in tracking but is actually closed/crashed."""


@dataclass
class SessionConfig:
    """Configuration for launching a Camoufox session."""
    headless: bool = True
    proxy: str | None = None
    humanize: bool = True
    human_preset: str = "default"
    stealth_args: bool = True
    timezone: str | None = None
    locale: str | None = None
    viewport: dict[str, int] | None = None
    color_scheme: str | None = None
    user_agent: str | None = None
    user_data_dir: str | None = None
    extra_args: list[str] | None = None


class BrowserSession:
    """Manages a shared Camoufox browser instance and its pages.

    Camoufox is a synchronous Playwright wrapper, so we run all browser
    calls in a dedicated ThreadPoolExecutor and await them from async tools.

    Active page tracking: one page_id is designated as "active" — the default
    target for user-implied interactions. switch_page() changes it. Tools accept
    an explicit page_id to override.
    """

    def __init__(self) -> None:
        self._browser: Any = None        # Camoufox Browser (from context manager)
        self._context: Any = None        # Playwright BrowserContext
        self._pages: dict[str, Any] = {}
        self._page_ids: list[str] = []
        self._active_page_id: str | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._display_mode: str = "headless"

        # Per-page dialog and console stores (populated by page event handlers)
        self._dialogs: dict[str, list[dict[str, Any]]] = {}
        self._console: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._browser is not None and self._context is not None

    @property
    def display_mode(self) -> str:
        return self._display_mode

    @property
    def active_page_id(self) -> str | None:
        if self._active_page_id and self._active_page_id in self._pages:
            if not self._pages[self._active_page_id].is_closed():
                return self._active_page_id
        # Fall back to first open page
        for pid in self._page_ids:
            if not self._pages[pid].is_closed():
                self._active_page_id = pid
                return pid
        return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _setup_page_handlers(self, page: Any, page_id: str) -> None:
        """Attach event handlers to a page for dialog + console capture.

        These are Playwright's sync event hooks. Dialogs are auto-dismissed
        (to prevent blocking) and recorded. Console messages are captured.
        """

        # Initialize stores for this page
        self._dialogs[page_id] = []
        self._console[page_id] = []

        def _on_dialog(dialog):
            try:
                msg = dialog.message
                dlg_type = dialog.type  # "alert", "confirm", "prompt", "beforeunload"
                self._dialogs[page_id].append({
                    "type": dlg_type,
                    "message": msg,
                    "default_value": dialog.default_value if dlg_type == "prompt" else None,
                })
                # Auto-dismiss to prevent the browser from hanging
                if dlg_type == "beforeunload":
                    dialog.accept()
                else:
                    dialog.dismiss()
            except Exception:
                try:
                    dialog.dismiss()
                except Exception:
                    pass

        def _on_console(msg):
            self._console[page_id].append({
                "type": msg.type,
                "text": msg.text,
                "location": msg.location if hasattr(msg, "location") else None,
            })
            # Trim to last 200 messages to prevent unbounded growth
            if len(self._console[page_id]) > 200:
                self._console[page_id] = self._console[page_id][-200:]

        page.on("dialog", _on_dialog)
        page.on("console", _on_console)

    async def launch(self, cfg: SessionConfig, executor: ThreadPoolExecutor) -> None:
        """Launch Camoufox browser in the thread executor."""
        if self.is_running:
            await self.close()

        self._executor = executor
        self._display_mode = "headed" if not cfg.headless else "headless"

        def _sync_launch():
            from camoufox.sync_api import Camoufox
            from camoufox.utils import launch_options

            opts = launch_options(
                headless=cfg.headless,
                humanize=cfg.humanize if cfg.humanize is not False else None,
                locale=cfg.locale,
                proxy={"server": cfg.proxy} if cfg.proxy else None,
            )

            browser = Camoufox(**opts)
            raw = browser.__enter__()

            from playwright.sync_api import Browser
            if isinstance(raw, Browser):
                ctx = raw.new_context(
                    viewport=cfg.viewport,
                    locale=cfg.locale,
                    timezone_id=cfg.timezone,
                    color_scheme=cfg.color_scheme,
                    user_agent=cfg.user_agent,
                )
            else:
                ctx = raw
            return browser, ctx

        loop = asyncio.get_event_loop()
        self._browser, self._context = await loop.run_in_executor(executor, _sync_launch)
        self._pages = {}
        self._page_ids = []
        self._active_page_id = None
        self._dialogs = {}
        self._console = {}
        logger.info("Camoufox browser launched (headless=%s)", cfg.headless)

    async def new_page(self) -> str:
        """Create a new page in the existing context. Sets it as active."""
        if not self.is_running:
            raise BrowserSessionError("Browser not running. Call launch() first.")

        def _sync_new_page():
            page = self._context.new_page()
            page_id = f"page_{uuid.uuid4().hex[:8]}"
            return page_id, page

        loop = asyncio.get_event_loop()
        page_id, page = await loop.run_in_executor(self._executor, _sync_new_page)

        # Attach dialog + console handlers
        def _attach():
            self._setup_page_handlers(page, page_id)

        await loop.run_in_executor(self._executor, _attach)

        self._pages[page_id] = page
        self._page_ids.append(page_id)
        self._active_page_id = page_id
        logger.debug("New page %s (total: %d)", page_id, len(self._pages))
        return page_id

    async def switch_page(self, page_id: str) -> None:
        """Set the active page."""
        if page_id not in self._pages:
            raise PageNotFoundError(f"No page found with id: {page_id}")
        page = self._pages[page_id]
        if page.is_closed():
            raise PageClosedError(f"Page {page_id} was closed")
        self._active_page_id = page_id

    async def close_page(self, page_id: str) -> None:
        """Close a specific page."""
        if page_id not in self._pages:
            raise PageNotFoundError(f"No page found with id: {page_id}")

        def _sync_close():
            page = self._pages[page_id]
            try:
                page.close()
            except Exception:
                pass

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, _sync_close)

        self._pages.pop(page_id, None)
        if page_id in self._page_ids:
            self._page_ids.remove(page_id)
        self._dialogs.pop(page_id, None)
        self._console.pop(page_id, None)

        if self._active_page_id == page_id:
            self._active_page_id = None

        logger.debug("Closed page %s (remaining: %d)", page_id, len(self._pages))

    def get_page(self, page_id: str) -> Any:
        if page_id not in self._pages:
            raise PageNotFoundError(f"No page found with id: {page_id}")
        page = self._pages[page_id]
        if page.is_closed():
            del self._pages[page_id]
            if page_id in self._page_ids:
                self._page_ids.remove(page_id)
            raise PageClosedError(f"Page {page_id} was closed")
        return page

    def list_pages(self) -> list[dict[str, str]]:
        result = []
        for pid in self._page_ids:
            if pid in self._pages and not self._pages[pid].is_closed():
                is_active = " (active)" if pid == self._active_page_id else ""
                result.append({
                    "page_id": pid,
                    "url": self._pages[pid].url,
                    "active": pid == self._active_page_id,
                })
        return result

    # ------------------------------------------------------------------
    # Dialog & console accessors
    # ------------------------------------------------------------------

    def get_dialogs(self, page_id: str, filter_text: str | None = None) -> dict[str, Any]:
        page = self.get_page(page_id)
        dialogs = self._dialogs.get(page_id, [])
        if filter_text:
            dialogs = [d for d in dialogs if filter_text.lower() in d.get("message", "").lower()]
        return {"status": "ok", "dialogs": dialogs, "count": len(dialogs)}

    def get_console(self, page_id: str, filter_text: str | None = None,
                    clear: bool = False) -> dict[str, Any]:
        page = self.get_page(page_id)
        entries = self._console.get(page_id, [])
        if filter_text:
            entries = [e for e in entries if filter_text.lower() in e.get("text", "").lower()]
        if clear:
            self._console[page_id] = []
        return {"status": "ok", "messages": entries, "count": len(entries)}

    # ------------------------------------------------------------------
    # Cookie management
    # ------------------------------------------------------------------

    def get_cookies(self, urls: list[str] | None = None) -> list[dict[str, Any]]:
        """Get all cookies from the browser context, optionally filtered by URL."""
        cookies = self._context.cookies(urls) if urls else self._context.cookies()
        # Serialize for JSON return
        return [
            {
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", ""),
                "expires": c.get("expires", -1),
            }
            for c in cookies
        ]

    def set_cookies(self, cookies: list[dict[str, Any]]) -> None:
        """Set cookies in the browser context."""
        self._context.add_cookies(cookies)

    def clear_cookies(self) -> None:
        """Clear all cookies from the browser context."""
        self._context.clear_cookies()

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    async def close(self) -> None:
        if not self.is_running:
            return

        def _sync_close():
            for page in list(self._context.pages):
                try:
                    page.close()
                except Exception:
                    pass
            try:
                self._context.close()
            except Exception:
                pass
            try:
                self._browser.__exit__(None, None, None)
            except Exception:
                pass

        loop = asyncio.get_event_loop()
        if self._executor:
            try:
                await loop.run_in_executor(self._executor, _sync_close)
            except Exception as exc:
                logger.warning("Error during close: %s", exc)

        self._pages = {}
        self._page_ids = []
        self._active_page_id = None
        self._dialogs = {}
        self._console = {}
        self._browser = None
        self._context = None
        logger.info("Camoufox browser closed")

    def _force_cleanup(self) -> None:
        self._pages = {}
        self._page_ids = []
        self._active_page_id = None
        self._dialogs = {}
        self._console = {}
        self._browser = None
        self._context = None
