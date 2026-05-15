"""BrowserSession — manages Camoufox browser lifecycle, pages, and contexts."""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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
    """

    def __init__(self) -> None:
        self._browser: Any = None   # Camoufox Browser (from context manager)
        self._context: Any = None   # Playwright BrowserContext
        self._pages: dict[str, Any] = {}
        self._page_ids: list[str] = []
        self._executor: ThreadPoolExecutor | None = None

    @property
    def is_running(self) -> bool:
        return self._browser is not None and self._context is not None

    async def launch(self, cfg: SessionConfig, executor: ThreadPoolExecutor) -> None:
        """Launch Camoufox browser in the thread executor.

        Camoufox's sync API is blocking, so we hand off to the executor thread.
        """
        if self.is_running:
            await self.close()

        self._executor = executor

        def _sync_launch():
            from camoufox.sync_api import Camoufox
            from camoufox.utils import launch_options

            # Build launch kwargs — Camoufox wraps Playwright
            opts = launch_options(
                headless=cfg.headless,
                humanize=cfg.humanize if cfg.humanize is not False else None,
                locale=cfg.locale,
                proxy={"server": cfg.proxy} if cfg.proxy else None,
            )

            browser = Camoufox(**opts)
            # Enter context manager — browser is either Browser or BrowserContext
            raw = browser.__enter__()
            # If raw is a Browser (not BrowserContext), create a context from it
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
                ctx = raw  # already a BrowserContext (persistent context path)
            return browser, ctx

        loop = asyncio.get_event_loop()
        self._browser, self._context = await loop.run_in_executor(executor, _sync_launch)
        self._pages = {}
        self._page_ids = []
        logger.info("Camoufox browser launched (headless=%s)", cfg.headless)

    async def new_page(self) -> str:
        """Create a new page in the existing context."""
        if not self.is_running:
            raise BrowserSessionError("Browser not running. Call launch() first.")

        def _sync_new_page():
            page = self._context.new_page()
            page_id = f"page_{uuid.uuid4().hex[:8]}"
            return page_id, page

        loop = asyncio.get_event_loop()
        page_id, page = await loop.run_in_executor(self._executor, _sync_new_page)
        self._pages[page_id] = page
        self._page_ids.append(page_id)
        logger.debug("New page %s (total: %d)", page_id, len(self._pages))
        return page_id

    def get_page(self, page_id: str) -> Any:
        if page_id not in self._pages:
            raise PageNotFoundError(f"No page found with id: {page_id}")
        page = self._pages[page_id]
        if page.is_closed():
            del self._pages[page_id]
            self._page_ids.remove(page_id)
            raise PageClosedError(f"Page {page_id} was closed")
        return page

    def list_pages(self) -> list[dict[str, str]]:
        return [
            {"page_id": pid, "url": self._pages[pid].url}
            for pid in self._page_ids
            if not self._pages[pid].is_closed()
        ]

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
        self._browser = None
        self._context = None
        logger.info("Camoufox browser closed")

    def _force_cleanup(self) -> None:
        self._pages = {}
        self._page_ids = []
        self._browser = None
        self._context = None