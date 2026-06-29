"""BrowserSession — manages Camoufox browser lifecycle, pages, and contexts.

Playwright MCP quality: dialog auto-capture, console capture, network response
capture, page management (create/switch/close), active-page tracking.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
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


def _detect_screen_size() -> tuple[int, int]:
    """Detect the primary display resolution on the host machine.

    macOS: uses system_profiler or returns a sensible Retina-aware default.
    Falls back to 1440x875 (half a 1440p display, accounting for menu bar + dock).
    """
    import platform
    if platform.system() == "Darwin":
        try:
            import subprocess
            r = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True, text=True, timeout=5,
            )
            # Parse "Resolution: 2560 x 1664" or similar
            for line in r.stdout.splitlines():
                if "Resolution:" in line:
                    parts = line.split(":")[-1].strip().split("x")
                    if len(parts) == 2:
                        w_raw = parts[0].strip().replace(" ", "")
                        h_raw = parts[1].strip().replace(" ", "")
                        try:
                            w = int(w_raw)
                            h = int(h_raw)
                            # On Retina displays, system_profiler reports the scaled resolution.
                            # Use ~90% of height to leave room for menu bar + dock.
                            usable_h = int(h * 0.85)
                            return w, usable_h
                        except ValueError:
                            pass
        except Exception:
            pass
        # Fallback: common MacBook Pro 14" / 16" scaled res
        return 1512, 840

    # Linux/Windows fallback
    return 1440, 875


class BrowserSessionError(RuntimeError):
    """Raised when the browser session is in an invalid state."""


class PageNotFoundError(KeyError):
    """Raised when a page_id doesn't exist in the session."""


class PageClosedError(BrowserSessionError):
    """Raised when a page exists in tracking but is actually closed/crashed."""


def _ensure_macos_properties_json() -> None:
    """Work around Camoufox macOS bundle layout drift.

    Camoufox v135.0.1-beta.24 stores ``properties.json`` in
    ``Contents/Resources``. Some launcher paths look for it next to the
    executable in ``Contents/MacOS`` and fail before Playwright can start:

        No such file or directory: .../Contents/MacOS/properties.json

    Keep the workaround local and idempotent. Prefer a symlink so future
    Camoufox fetches update the canonical Resources copy; fall back to copying
    on filesystems that do not allow symlinks.
    """
    if os.name != "posix":
        return
    try:
        from camoufox.pkgman import camoufox_path

        bundle = Path(camoufox_path()) / "Camoufox.app" / "Contents"
        resources = bundle / "Resources" / "properties.json"
        macos = bundle / "MacOS" / "properties.json"
        if not resources.exists() or macos.exists():
            return
        macos.parent.mkdir(parents=True, exist_ok=True)
        try:
            macos.symlink_to(resources)
        except OSError:
            shutil.copy2(resources, macos)
    except Exception:
        logger.debug("Unable to prepare Camoufox macOS properties.json workaround", exc_info=True)


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
    storage_state: dict[str, Any] | str | None = None


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
        self._current_viewport: dict[str, int] | None = None  # tracked so new pages inherit it
        self._last_config: SessionConfig | None = None

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

            _ensure_macos_properties_json()

            opts = launch_options(
                headless=cfg.headless,
                humanize=cfg.humanize if cfg.humanize is not False else None,
                locale=cfg.locale,
                proxy={"server": cfg.proxy} if cfg.proxy else None,
                window=(cfg.viewport["width"], cfg.viewport["height"])
                if (not cfg.headless and cfg.viewport)
                else None,
            )

            if cfg.user_data_dir:
                Path(cfg.user_data_dir).mkdir(parents=True, exist_ok=True)
                opts["user_data_dir"] = cfg.user_data_dir

            browser = Camoufox(
                from_options=opts,
                persistent_context=bool(cfg.user_data_dir),
            )
            raw = browser.__enter__()

            from playwright.sync_api import Browser
            if isinstance(raw, Browser):
                ctx = raw.new_context(
                    viewport=cfg.viewport,
                    locale=cfg.locale,
                    timezone_id=cfg.timezone,
                    color_scheme=cfg.color_scheme,
                    user_agent=cfg.user_agent,
                    storage_state=cfg.storage_state,  # type: ignore[arg-type]
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
        self._current_viewport = dict(cfg.viewport) if cfg.viewport else None
        self._last_config = replace(cfg)
        logger.info("Camoufox browser launched (headless=%s, viewport=%s)", cfg.headless, self._current_viewport)

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

        # Inherit viewport from session if one was set (post-launch resize)
        if self._current_viewport:
            def _apply_vp():
                try:
                    page.set_viewport_size(self._current_viewport)
                except Exception:
                    pass
            loop.run_in_executor(self._executor, _apply_vp)

        logger.debug("New page %s (total: %d)", page_id, len(self._pages))
        return page_id

    async def resize_viewport(self, width: int, height: int) -> dict[str, Any]:
        """Resize the viewport on all open pages and store for future pages.

        On macOS, auto-detect can be done by passing width=0, height=0.
        """
        if width == 0 or height == 0:
            w, h = _detect_screen_size()
            width = width or w
            height = height or h

        self._current_viewport = {"width": width, "height": height}

        def _resize_all():
            count = 0
            for page in list(self._context.pages):
                try:
                    if not page.is_closed():
                        page.set_viewport_size({"width": width, "height": height})
                        count += 1
                except Exception:
                    pass
            return count

        loop = asyncio.get_event_loop()
        count = await loop.run_in_executor(self._executor, _resize_all)

        logger.info("Viewport resized to %dx%d on %d pages", width, height, count)
        return {"status": "resized", "width": width, "height": height, "pages_affected": count}

    def _relaunch_headed_for_viewport_sync(self, width: int, height: int) -> dict[str, Any]:
        """Relaunch headed Camoufox so its fingerprint window matches the requested viewport.

        Camoufox freezes window.innerWidth/window.outerWidth from the launch-time
        fingerprint. Calling page.set_viewport_size() alone resizes screenshots but does
        not update the spoofed window metrics, which makes JS/CSS-driven layouts render
        off-screen. A headed resize therefore has to relaunch with a new Camoufox
        `window=(width, height)` fingerprint and restore cookies + URLs.
        """
        if not self._last_config:
            raise BrowserSessionError("Cannot resize headed browser before launch config is available")

        from camoufox.sync_api import Camoufox
        from camoufox.utils import launch_options
        from playwright.sync_api import Browser

        _ensure_macos_properties_json()

        old_pages = []
        active_old = self._active_page_id
        for pid in list(self._page_ids):
            page = self._pages.get(pid)
            if page and not page.is_closed():
                url = page.url
                old_pages.append({"page_id": pid, "url": url, "active": pid == active_old})

        try:
            storage_state = self._context.storage_state()
        except Exception:
            storage_state = None

        try:
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
        finally:
            self._pages = {}
            self._page_ids = []
            self._dialogs = {}
            self._console = {}
            self._active_page_id = None

        cfg = replace(
            self._last_config,
            viewport={"width": width, "height": height},
            storage_state=storage_state,
        )

        opts = launch_options(
            headless=False,
            humanize=cfg.humanize if cfg.humanize is not False else None,
            locale=cfg.locale,
            proxy={"server": cfg.proxy} if cfg.proxy else None,
            window=(width, height),
        )
        if cfg.user_data_dir:
            Path(cfg.user_data_dir).mkdir(parents=True, exist_ok=True)
            opts["user_data_dir"] = cfg.user_data_dir
        browser = Camoufox(
            from_options=opts,
            persistent_context=bool(cfg.user_data_dir),
        )
        raw = browser.__enter__()
        if isinstance(raw, Browser):
            ctx = raw.new_context(
                viewport=cfg.viewport,
                locale=cfg.locale,
                timezone_id=cfg.timezone,
                color_scheme=cfg.color_scheme,
                user_agent=cfg.user_agent,
                storage_state=cfg.storage_state,  # type: ignore[arg-type]
            )
        else:
            ctx = raw

        self._browser = browser
        self._context = ctx
        self._last_config = cfg
        self._current_viewport = {"width": width, "height": height}

        restored = 0
        pages_to_restore = old_pages or [{"page_id": f"page_{uuid.uuid4().hex[:8]}", "url": "about:blank", "active": True}]
        for info in pages_to_restore:
            page_id = info["page_id"]
            page = self._context.new_page()
            self._setup_page_handlers(page, page_id)
            self._pages[page_id] = page
            self._page_ids.append(page_id)
            if info.get("active"):
                self._active_page_id = page_id
            url = info.get("url") or "about:blank"
            if url and url != "about:blank":
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    logger.warning("Failed restoring page %s to %s", page_id, url, exc_info=True)
            restored += 1

        if not self._active_page_id and self._page_ids:
            self._active_page_id = self._page_ids[0]

        return {
            "status": "resized",
            "width": width,
            "height": height,
            "pages_affected": restored,
            "restarted": True,
            "hint": "Headed Camoufox was relaunched so spoofed window metrics match the visible viewport.",
        }

    def resize_viewport_sync(self, width: int, height: int) -> dict[str, Any]:
        """Synchronous wrapper — call from within the executor thread."""
        if width == 0 or height == 0:
            w, h = _detect_screen_size()
            width = width or w
            height = height or h

        if self._display_mode == "headed":
            return self._relaunch_headed_for_viewport_sync(width, height)

        self._current_viewport = {"width": width, "height": height}

        count = 0
        for page in list(self._context.pages):
            try:
                if not page.is_closed():
                    page.set_viewport_size({"width": width, "height": height})
                    count += 1
            except Exception:
                pass

        logger.info("Viewport resized to %dx%d on %d pages", width, height, count)
        return {"status": "resized", "width": width, "height": height, "pages_affected": count}

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
