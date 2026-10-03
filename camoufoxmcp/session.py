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
from urllib.parse import unquote, urlsplit

from . import hardening

logger = logging.getLogger("camoufoxmcp")


def _hardening_launch_kwargs() -> dict[str, Any]:
    """The launch_options kwargs that make a launch hardened.

    Returned as kwargs rather than applied to the result because
    ``launch_options`` is where a fingerprint becomes the env vars Camoufox
    reads -- there is no later point at which it can be injected.

    ``i_know_what_im_doing`` is set deliberately and not to silence a warning
    that is being ignored: Camoufox warns against a custom fingerprint because
    it is *less* random than its own generator, and less random is exactly the
    goal here. Suppressing the warning without that reasoning would be worse
    than leaving it on.
    """
    fingerprint = hardening.load_or_create_fingerprint()
    kwargs: dict[str, Any] = {
        "fingerprint": fingerprint,
        "os": hardening.host_os_family(),
        "i_know_what_im_doing": True,
        # Camoufox caches pages and requests when this is on, which is both
        # cross-run state and a source of launch-to-launch variation.
        "enable_cache": False,
        "config": dict(hardening.HARDENED_CONFIG),
        "firefox_user_prefs": dict(hardening.HARDENED_PREFS),
        "block_webrtc": True,
    }
    webgl = hardening.webgl_config(fingerprint)
    if webgl:
        # The fingerprint alone does not pin WebGL: launch_options samples a
        # fresh vendor/renderer pair on every call, so without this the
        # renderer changes between launches (measured: NVIDIA in one, AMD in
        # the next) while everything else stayed pinned.
        kwargs["webgl_config"] = webgl
    return kwargs


def _build_launch_options(
    cfg: SessionConfig,
    headless: bool,
    window: tuple[int, int] | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Build the full ``launch_options`` call for a config.

    Shared by the initial launch and the headed relaunch, because they were
    two copies of the same construction and hardening is precisely the kind of
    thing a second copy silently forgets -- a resize would then relaunch with a
    random fingerprint and report success.

    Returns ``(opts, hardening_report)``; the report is None for an ordinary
    launch.
    """
    from camoufox.utils import launch_options

    # Credentials go in Playwright's own fields, not in the server URL. See
    # _parse_proxy() for why this matters for Tor.
    proxy_cfg: dict[str, Any] | None = None
    if cfg.proxy:
        server, user, password = _parse_proxy(cfg.proxy)
        proxy_cfg = {"server": server}
        if cfg.proxy_username or user:
            proxy_cfg["username"] = cfg.proxy_username or user
        if cfg.proxy_password or password:
            proxy_cfg["password"] = cfg.proxy_password or password

    # Hardened mode is assembled *before* launch_options rather than applied to
    # its output. launch_options is the only place a fingerprint can be
    # injected -- it converts it into the env vars Camoufox's patches read -- so
    # patching the returned dict would be a no-op that looked like it worked.
    hard: dict[str, Any] = {}
    report: dict[str, Any] | None = None
    if cfg.hardened:
        hard = _hardening_launch_kwargs()
        report = {
            "fingerprint": hardening.fingerprint_summary(hard["fingerprint"]),
            **hardening.describe(),
        }

    opts = launch_options(
        headless=headless,
        # Humanized cursor movement is per-session behaviour that varies, and
        # its whole purpose is to look like a person rather than like one
        # stable configuration. Hardened mode drops it.
        humanize=None if cfg.hardened else (cfg.humanize if cfg.humanize is not False else None),
        locale=cfg.locale,
        proxy=proxy_cfg,
        window=window,
        **hard,
    )

    # Merged over Camoufox's defaults rather than replacing them --
    # launch_options already sets its own prefs, and dropping them would
    # silently weaken the fingerprint for the sake of hardening the transport.
    if cfg.firefox_user_prefs:
        prefs = dict(opts.get("firefox_user_prefs") or {})
        prefs.update(cfg.firefox_user_prefs)
        opts["firefox_user_prefs"] = prefs

    # Hardened mode does not persist. A profile directory is exactly the
    # cross-run state the mode exists to remove, so it is skipped even if one
    # was configured; camoufox_launch refuses the combination up front, and
    # this is the belt to that braces.
    if cfg.user_data_dir and not cfg.hardened:
        Path(cfg.user_data_dir).mkdir(parents=True, exist_ok=True)
        opts["user_data_dir"] = cfg.user_data_dir

    return opts, report


def _parse_proxy(proxy: str) -> tuple[str, str | None, str | None]:
    """Split userinfo out of a proxy URL.

    Returns ``(server_url, username, password)``. Playwright takes proxy
    credentials in separate ``username``/``password`` fields; credentials
    embedded in the server URL are honoured by Chromium but are not reliable
    on Firefox, which is the only engine this server drives.

    This does not carry Tor's circuit isolation. It used to be described that
    way -- the credential would be hashed by ``IsolateSOCKSAuth`` to select a
    circuit -- but Playwright refuses to launch Firefox with SOCKS
    authentication at all, so the credential was never sent and the launch
    failed rather than silently sharing a circuit. Isolation is a dedicated
    SocksPort per label now; see ``tor.py``.
    """
    raw = (proxy or "").strip()
    if not raw:
        return "", None, None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return proxy.strip(), None, None
    if not parts.hostname:
        return proxy.strip(), None, None

    netloc = parts.hostname
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    server = f"{parts.scheme}://{netloc}"
    username = unquote(parts.username) if parts.username else None
    password = unquote(parts.password) if parts.password else None
    return server, username, password


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


def host_in_scope(host: str, patterns: list[str] | None) -> bool:
    """Whether ``host`` matches any entry in a header-scope allowlist.

    An empty or missing allowlist means "no scoping" and is handled by the
    caller, not here -- this function answers the narrower question and returns
    False for an empty list rather than silently meaning "everything".

    Entries match a host and its subdomains: ``stripchat.com`` covers both
    ``stripchat.com`` and ``www.stripchat.com``. A leading dot is accepted and
    ignored (``.stripchat.com`` means the same thing) because that is the form
    people copy out of cookie banners and DNS zones. Matching is case-insensitive
    and anchored at a label boundary, so ``notstripchat.com`` does not match
    ``stripchat.com`` -- a plain ``str.endswith`` would say it does, and a header
    silently leaking to a lookalike domain is exactly the failure this guards.
    """
    if not patterns:
        return False
    host = (host or "").lower().strip(".")
    for raw in patterns:
        pat = (raw or "").lower().strip().strip(".")
        if not pat:
            continue
        if host == pat or host.endswith("." + pat):
            return True
    return False


def merge_headers(current: dict[str, str], managed: dict[str, str],
                  host: str, scope: list[str] | None) -> dict[str, str]:
    """Return the headers to send for one request under a header policy.

    Playwright reports header names lowercased, but callers write them however
    they like, so every removal here is case-insensitive. Without that, a
    context that already carries ``hackerone`` keeps it alongside the
    ``HackerOne`` being added and the request goes out with the header twice.

    The strip always happens, including on requests that are *in* scope. That is
    what makes the scope authoritative rather than additive: a header that
    arrived from somewhere else -- a context-wide setting, a service worker, an
    earlier tool call -- cannot survive on a host this policy excludes.
    """
    out = {k: v for k, v in current.items()
           if k.lower() not in {m.lower() for m in managed}}
    if host_in_scope(host, scope):
        out.update(managed)
    return out


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
    # Custom request headers. Sent on every request when `header_scope` is
    # empty; sent only to matching hosts when it is set. See set_http_headers().
    http_headers: dict[str, str] | None = None
    header_scope: list[str] | None = None
    # Proxy credentials, split out of `proxy` by _parse_proxy() so they travel
    # in Playwright's documented fields rather than embedded in the server URL.
    proxy_username: str | None = None
    proxy_password: str | None = None
    # Extra Firefox prefs merged over Camoufox's defaults. Used to harden a
    # Tor-routed session (remote DNS so lookups do not leak past Tor, and
    # WebRTC off so it cannot expose the real address).
    firefox_user_prefs: dict[str, Any] | None = None
    # Tor routing, for reporting. The proxy fields above carry the actual
    # wiring -- these exist so the session can describe what it is doing.
    tor: bool = False
    tor_isolation: str | None = None
    tor_exit_nodes: str | None = None
    # Hardened mode: pin one persisted fingerprint, turn on RFP, and drop every
    # per-launch randomiser Camoufox owns. See hardening.py -- this reduces
    # uniqueness, it is not anonymity.
    hardened: bool = False


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
        # What hardened mode actually pinned, for reporting back on the launch.
        # None on an ordinary launch, so its presence is itself the answer to
        # "is this session hardened?".
        self._hardening_report: dict[str, Any] | None = None
        # Name of the vault account this session was launched from or loaded,
        # so close can write refreshed tokens back. None for an anonymous session.
        self.account_name: str | None = None

        # Custom request headers, and the route handler enforcing them. The
        # handler is kept so a later set_http_headers() can unroute exactly the
        # one it installed; leaving stale handlers stacked would apply old
        # policies in an order nothing controls.
        self._http_headers: dict[str, str] = {}
        self._header_scope: list[str] | None = None
        self._header_route_installed: bool = False

        # Per-page dialog and console stores (populated by page event handlers)
        self._dialogs: dict[str, list[dict[str, Any]]] = {}
        self._console: dict[str, list[dict[str, Any]]] = {}

        # Ref freshness bookkeeping. `_nav_epoch` counts main-frame
        # navigations per page; `_ref_signature` records the epoch and
        # mutation bucket at the moment the last snapshot was taken. Together
        # they answer "is this [@eN] still the element it was?" -- a question
        # that cannot be answered by looking at the ref itself.
        # `_nav_url` holds the last URL seen per page, so a fragment-only
        # change can be told apart from a real navigation.
        self._nav_epoch: dict[str, int] = {}
        self._nav_url: dict[str, str] = {}
        self._ref_signature: dict[str, dict[str, Any]] = {}

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
    def hardening_report(self) -> dict[str, Any] | None:
        """What this session pinned, or None if it is not a hardened session.

        Its absence is meaningful: an ordinary launch does not get a
        ``hardened: false`` stub, so the key's presence on a launch result is
        itself the answer.
        """
        return self._hardening_report

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

        # Main-frame navigations only. Subframe navigations are excluded
        # deliberately: an ad iframe reloading would otherwise bump the epoch
        # on every page forever, making every ref permanently "hard stale" and
        # training the caller to ignore the check. The cost is that a ref
        # *inside* a navigated subframe is not caught -- a gap worth having,
        # because the alternative guard is one nobody can use.
        self._nav_epoch[page_id] = 0
        self._nav_url.pop(page_id, None)

        def _bump_epoch():
            self._nav_epoch[page_id] = self._nav_epoch.get(page_id, 0) + 1

        def _on_frame_navigated(frame):
            # Playwright reports a *fragment* change as a navigation, but the
            # document is the same and the refs are still valid. Verified: on a
            # `location.hash = 'x'` the epoch incremented. Counting it would
            # hard-stale every ref on any scroll-spy or anchor-link page, which
            # is most docs sites -- so the guard would fire constantly and be
            # ignored. The URL is compared without its fragment for that reason.
            try:
                if frame != page.main_frame:
                    return
                url = frame.url or ""
                previous = self._nav_url.get(page_id)
                self._nav_url[page_id] = url
                if previous is None:
                    return
                if url.split("#", 1)[0] != previous.split("#", 1)[0]:
                    _bump_epoch()
            except Exception:
                pass

        def _on_load():
            # A reload navigates to the *same* URL, so the comparison above
            # cannot see it -- but it does replace the document, so every ref
            # is stale and must be reported as such. `load` fires for a reload
            # (and for a first load, where the extra bump is harmless because
            # only equality between snapshots is ever compared) and does not
            # fire for a fragment change or a pushState.
            try:
                _bump_epoch()
            except Exception:
                pass

        page.on("dialog", _on_dialog)
        page.on("console", _on_console)
        page.on("framenavigated", _on_frame_navigated)
        page.on("load", _on_load)

    # ------------------------------------------------------------------
    # Custom request headers
    # ------------------------------------------------------------------

    def _apply_http_headers_sync(self, headers: dict[str, str] | None,
                                 scope: list[str] | None) -> dict[str, Any]:
        """(Re)install the header policy on the live context. Executor thread.

        Two mechanisms, chosen by whether a scope was given, and the difference
        is not cosmetic:

        ``set_extra_http_headers`` is context-wide. It stamps the header onto
        every request the context makes -- including third-party CDN, analytics
        and font requests. For an engagement header that is a disclosure to
        hosts that are not part of the engagement and cannot be being tested.

        ``ctx.route`` is the only mechanism that can scope per host, so a scope
        switches to it. It costs a handler invocation per request and disables
        some caching, which is why the unscoped case still uses the cheaper
        context-wide call.
        """
        ctx = self._context
        if ctx is None:
            raise BrowserSessionError("Browser not running. Call launch() first.")

        # Tear the old policy down before installing the new one. Unrouting
        # matters as much as routing: leaving a stale handler stacked means two
        # policies apply in an order nothing controls.
        if self._header_route_installed:
            try:
                ctx.unroute("**/*")
            except Exception:
                logger.debug("unroute failed; continuing", exc_info=True)
            self._header_route_installed = False
        try:
            ctx.set_extra_http_headers({})
        except Exception:
            logger.debug("clearing context-wide headers failed", exc_info=True)

        self._http_headers = dict(headers or {})
        self._header_scope = [s for s in (scope or []) if s and s.strip()] or None

        if not self._http_headers:
            logger.info("Custom request headers cleared")
            return {"status": "cleared", "headers": [], "scope": None, "scoped": False}

        if not self._header_scope:
            ctx.set_extra_http_headers(self._http_headers)
            logger.info("Applied %d context-wide header(s): %s",
                        len(self._http_headers), sorted(self._http_headers))
            return {
                "status": "applied",
                "headers": sorted(self._http_headers),
                "scope": None,
                "scoped": False,
                "warning": (
                    "No header_scope given, so these ride on EVERY request this "
                    "context makes, including third-party hosts. Pass "
                    "header_scope=[...] to restrict them to the hosts that are "
                    "actually in scope."
                ),
            }

        def _handler(route, request):
            try:
                host = urlsplit(request.url).hostname or ""
                merged = merge_headers(dict(request.headers), self._http_headers,
                                       host, self._header_scope)
                route.continue_(headers=merged)
            except Exception:
                # A header policy must never break the request it decorates.
                # Falling back to an unmodified continue keeps the page working
                # and loses only the header, which is the honest failure: a
                # silent breakage here would look like the site being down.
                logger.warning("Header route handler failed; sending unmodified",
                               exc_info=True)
                try:
                    route.continue_()
                except Exception:
                    pass

        ctx.route("**/*", _handler)
        self._header_route_installed = True
        logger.info("Applied %d scoped header(s) to %s",
                    len(self._http_headers), self._header_scope)
        return {
            "status": "applied",
            "headers": sorted(self._http_headers),
            "scope": list(self._header_scope),
            "scoped": True,
        }

    async def set_http_headers(self, headers: dict[str, str] | None,
                               scope: list[str] | None = None) -> dict[str, Any]:
        """Set, replace, or clear custom request headers on the live context.

        Passing an empty dict or None clears them.
        """
        if not self.is_running:
            raise BrowserSessionError("Browser not running. Call launch() first.")
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, lambda: self._apply_http_headers_sync(headers, scope))

    def get_http_headers(self, reveal: bool = False) -> dict[str, Any]:
        """Report the header policy currently in force.

        Values are masked unless ``reveal=True``. This is a status call -- the
        caller asked "what is configured", not "give me the secrets" -- and a
        header value is often a bearer token. `camoufox_extract_tokens` remains
        the tool that returns secrets, because calling it is an explicit ask.
        """
        def _mask(value: str) -> str:
            if reveal:
                return value
            if len(value) <= 4:
                return "*" * len(value)
            return "%s%s (%d chars)" % (value[:4], "*" * 8, len(value))

        return {
            "status": "ok",
            "headers": {k: _mask(v) for k, v in self._http_headers.items()},
            "names": sorted(self._http_headers),
            "scope": list(self._header_scope) if self._header_scope else None,
            "scoped": bool(self._header_scope),
            "count": len(self._http_headers),
        }

    async def launch(self, cfg: SessionConfig, executor: ThreadPoolExecutor) -> None:
        """Launch Camoufox browser in the thread executor."""
        if self.is_running:
            await self.close()

        self._executor = executor
        self._display_mode = "headed" if not cfg.headless else "headless"

        def _sync_launch():
            from camoufox.sync_api import Camoufox

            _ensure_macos_properties_json()

            # Headed mode needs the fingerprint window aligned with the viewport
            # so pages are not rendered off-screen. Hardened mode needs a fixed
            # window in both display modes, because the fingerprint's window
            # metrics are what the page reads back.
            window = None
            if cfg.viewport and (cfg.hardened or not cfg.headless):
                window = (cfg.viewport["width"], cfg.viewport["height"])

            opts, self._hardening_report = _build_launch_options(cfg, cfg.headless, window)

            browser = Camoufox(
                from_options=opts,
                persistent_context=bool(cfg.user_data_dir) and not cfg.hardened,
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
        self._nav_epoch = {}
        self._nav_url = {}
        self._ref_signature = {}
        self._current_viewport = dict(cfg.viewport) if cfg.viewport else None
        self._last_config = replace(cfg)
        # The context is brand new, so no route can be installed on it yet --
        # clear the flag before applying, or set_http_headers() would try to
        # unroute a handler that belongs to a context that no longer exists.
        self._header_route_installed = False
        await loop.run_in_executor(
            executor,
            lambda: self._apply_http_headers_sync(cfg.http_headers, cfg.header_scope),
        )
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

        # Same construction as the initial launch, so a hardened session stays
        # hardened across a resize instead of quietly coming back with a fresh
        # random fingerprint.
        opts, self._hardening_report = _build_launch_options(cfg, False, (width, height))
        browser = Camoufox(
            from_options=opts,
            persistent_context=bool(cfg.user_data_dir) and not cfg.hardened,
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

        # A headed resize relaunches the browser, so the header policy has to be
        # installed on the new context. Restoring it BEFORE the page-restore
        # loop below is what makes the restored navigations carry the header --
        # applying it after would silently reload every in-scope page without
        # it, which is the exact failure the feature exists to prevent.
        self._header_route_installed = False
        self._apply_http_headers_sync(cfg.http_headers, cfg.header_scope)

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

    def export_storage_state(self) -> dict[str, Any]:
        """Cookies + localStorage of the live context (Playwright storage_state)."""
        return self._context.storage_state()

    def import_storage_state(self, state: dict[str, Any]) -> dict[str, int]:
        """Apply a saved login to the RUNNING context.

        Cookies are added directly. localStorage can only be written from inside
        its origin, so it is installed as an init script (applies to pages loaded
        from now on, including already-open tabs after their next navigation).
        """
        from . import accounts

        cookies = state.get("cookies") or []
        if cookies:
            self._context.add_cookies(cookies)
        script = accounts.local_storage_init_script(state)
        if script:
            self._context.add_init_script(script)
        return {"cookies": len(cookies), "local_storage_origins": len(state.get("origins") or [])}

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
        self._nav_epoch = {}
        self._nav_url = {}
        self._ref_signature = {}
        self._browser = None
        self._context = None
        self.account_name = None
        logger.info("Camoufox browser closed")

    def _force_cleanup(self) -> None:
        self._pages = {}
        self._page_ids = []
        self._active_page_id = None
        self._dialogs = {}
        self._console = {}
        self._nav_epoch = {}
        self._nav_url = {}
        self._ref_signature = {}
        self._browser = None
        self._context = None
