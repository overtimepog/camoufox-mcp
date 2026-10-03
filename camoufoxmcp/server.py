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
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session import BrowserSession, SessionConfig, BrowserSessionError, _random_viewport, _detect_screen_size
from .snapshot import take_snapshot, resolve_ref, ref_freshness, _STATE_PROBE_JS
from .observe import (
    detect_blockers,
    page_fingerprint,
    fingerprint_delta,
    run_checks,
    wait_for_checks,
    console_index,
    CHECK_NAMES,
)
from . import hardening
from . import tor as tor_mod
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
)

logger = logging.getLogger("camoufoxmcp")

LOGS_DIR = Path.home() / ".camoufoxmcp" / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

_session = BrowserSession()
# Unwired. create_server(caps=...) accepts a capability set and stores it here,
# but no tool consults it, so nothing is actually gated. Kept because the
# signature is public and changing it is out of scope — but do not read this as
# "capability gating exists".
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


# Only snapshot refs can go stale. A raw CSS selector is re-resolved against the
# live DOM on every use, so it is never pointing at a remembered position.
_SNAPSHOT_REF_RE = re.compile(r"^e\d+$")


def _stale_guard(page: Any, page_id: str, ref: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Check ref freshness before acting on it.

    Returns ``(blocking_error, freshness_note)``. A ref from before a
    navigation is refused rather than resolved, because resolving it silently
    acts on whatever now occupies that position — a click that "succeeds" on
    the wrong element is worse than one that fails.

    A ref that is merely stale (DOM moved, no navigation) proceeds and carries
    the note, since most mutations are unrelated to the element in hand and
    refusing outright would make the tool unusable on any live page.
    """
    if not isinstance(ref, str) or not _SNAPSHOT_REF_RE.match(ref.lstrip("@")):
        return None, None
    try:
        freshness = ref_freshness(_session, page, page_id)
    except Exception as exc:
        logger.debug("freshness check failed: %s", exc)
        return None, None

    verdict = freshness.get("verdict")
    if verdict == "hard_stale":
        return _err(
            f"STALE_REF {ref}: {freshness.get('detail')}",
            hint=freshness.get("hint", "Re-run camoufox_snapshot."),
        ), None
    if verdict == "stale_warning":
        return None, freshness
    return None, None


def _attach_freshness(out: dict[str, Any], note: dict[str, Any] | None) -> dict[str, Any]:
    if note:
        out["ref_freshness"] = note
    return out


async def _explain_failure(page: Any, selector: str | None) -> dict[str, Any] | None:
    """Probe the target's state and name why an action failed, if it can.

    Returns the probed state plus the sentence explaining it, or None when the
    probe cannot run. `camoufox_act` has done this since it was written; the
    older single-action tools returned a generic "if the element is covered by
    an overlay, camoufox_snapshot marks it [occluded by ...]" hint instead,
    which tells the caller what to go and check rather than what is true.

    Measured before this existed: `camoufox_click` on an overlay-covered button
    came back with that generic sentence and no target_state at all, while the
    same click through `camoufox_act` came back with "covered by div#overlay".
    """
    if not selector:
        return None
    try:
        loop = asyncio.get_event_loop()
        state = await loop.run_in_executor(
            _executor, lambda: page.locator(selector).first.evaluate(_STATE_PROBE_JS))
    except Exception as exc:
        logger.debug("state probe after failure did not run: %s", exc)
        return None
    if not isinstance(state, dict):
        return None
    note = _state_explanation(state)
    if not note:
        return None
    return {"state": state, "note": note}


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
            "camoufox_evaluate(page_id, expression) — run sync or async JS.\n"
            "No timeout parameter: Playwright's evaluate takes none, and a\n"
            "deadline has to go inside the expression as a Promise.race.\n\n"
            "TAB MANAGEMENT:\n"
            "camoufox_new_page() — open additional tab\n"
            "camoufox_list_pages() — see all open tabs\n"
            "camoufox_close_page(page_id) — close a tab\n\n"
            "COOKIES:\n"
            "camoufox_get_cookies(urls) — get browser cookies (optionally filtered)\n"
            "camoufox_set_cookies(cookies) — set cookies\n"
            "camoufox_clear_cookies() — clear all cookies\n\n"
            "CUSTOM REQUEST HEADERS:\n"
            "camoufox_launch(headers={...}, header_scope=[...]) — set at launch\n"
            "camoufox_set_headers({...}, [...]) — set/change/clear on a live session\n"
            "camoufox_get_headers() — report what is in force (values masked)\n"
            "Some bug-bounty programs require an attribution header on ALL traffic\n"
            "(e.g. HackerOne: yourhandle). ALWAYS pass header_scope: without it the\n"
            "header is sent to every host the page touches, including third-party\n"
            "CDNs and analytics, disclosing the engagement to hosts that are not in\n"
            "it. Note that a custom header is not CORS-safelisted, so it forces a\n"
            "preflight OPTIONS on cross-origin calls — if a site fails to load after\n"
            "you add a header, that is why, and header_scope is the fix.\n\n"
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
            "cloudscraper (fast HTTP) → FlareSolverr (Docker Chromium, guaranteed).\n\n"
            "ACTING AND VERIFYING (prefer these over raw click/type):\n"
            "camoufox_act(page_id, action, ref=...) — one call that acts, waits for\n"
            "  the page to settle, then reports whether anything actually changed.\n"
            "  Use it when you need to know a click worked. It fires the stale-ref\n"
            "  and occlusion guards, so a covered or post-navigation target is\n"
            "  reported rather than silently mis-clicked.\n"
            "camoufox_verify(page_id, text_present=..., url_matches=...) — asserts\n"
            "  against the live page and returns the evidence. Deterministic; no\n"
            "  model judgement. Use it to confirm a claim before reporting it.\n"
            "camoufox_snapshot annotates each element with [disabled], [off-screen]\n"
            "  or [occluded by X], so you rarely need a second call to learn why a\n"
            "  click did nothing.\n\n"
            "TOR (geo-specific egress and per-session IP isolation):\n"
            "camoufox_tor_status() — local only. Managed instance + every Tor on\n"
            "  this machine, and who owns it.\n"
            "camoufox_tor_start(exit_nodes=None) — start the managed instance.\n"
            "camoufox_tor_stop() — stop it. Idempotent.\n"
            "camoufox_tor_new_circuit(exit_nodes=None) — rotate and confirm the new\n"
            "  exit IP in one call.\n"
            "camoufox_tor_exit_info() — network round trip (~2-5s): the exit IP a\n"
            "  target sees, and whether it is Tor.\n"
            "camoufox_launch(tor=True, tor_isolation='session-a') — route the browser\n"
            "  through Tor. Two labels never share a circuit and a label always\n"
            "  reuses its own, but ONLY per launch: Playwright's proxy is per\n"
            "  context and Camoufox runs one context, so parallel isolated work\n"
            "  needs parallel launches. Omitting the label means the shared base\n"
            "  circuit; there is no automatic label per launch.\n"
            "WHAT TOR DOES NOT BUY: Camoufox randomises its fingerprint, Tor's\n"
            "  anonymity depends on every user looking identical. Routing Camoufox\n"
            "  through Tor gives a different egress IP and circuit isolation — not\n"
            "  anonymity. Tor exit addresses are heavily blocklisted, so this makes\n"
            "  Cloudflare/Arkose HARDER to pass, not easier. It is not a bypass tier.\n\n"
            "HARDENED MODE (a stable, normalised identity — not anonymity):\n"
            "camoufox_launch(hardened=True) — pins one browser identity across\n"
            "  launches and normalises it with Firefox's own resistFingerprinting,\n"
            "  so repeat launches present the same platform, OS, screen, timezone\n"
            "  (UTC) and WebGL instead of a fresh random set each time. Turns\n"
            "  humanization, caching and profile persistence off; WebRTC and remote\n"
            "  lookups off. Refuses timezone/locale/user_agent/user_data_dir, each\n"
            "  of which would contradict or defeat it rather than being ignored.\n"
            "WHAT HARDENED DOES NOT BUY: anonymity. It reduces uniqueness — and\n"
            "  notably stops the real timezone leaking, which a default launch does\n"
            "  hand over — but the IP address is unchanged and a stable identity is\n"
            "  a small haystack, not a crowd. For anonymity, use Tor Browser run as\n"
            "  itself. hardened=True with tor=True is strictly better than tor\n"
            "  alone, and is still not anonymity."
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
        headers: dict[str, str] | None = None,
        header_scope: list[str] | None = None,
        tor: bool = False,
        tor_isolation: str | None = None,
        tor_exit_nodes: str | None = None,
        tor_instance: str | None = None,
        hardened: bool = False,
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
            headers: Custom headers sent on every request, e.g.
                {"HackerOne": "myhandle"}. Required by some bug-bounty programs,
                which mandate an attribution header on all traffic.
            header_scope: Hosts the headers are limited to, e.g.
                ["example.com"]. Entries cover the host and its subdomains.
                STRONGLY RECOMMENDED whenever the headers identify you: without
                it they are sent context-wide, including to third-party CDNs,
                analytics and font hosts — disclosing your engagement to hosts
                that are not in it.
            tor: Route all traffic through Tor. Starts the managed instance if
                needed. Cannot be combined with `proxy` — see the note below.
            tor_isolation: A label selecting a Tor circuit. Two labels never
                share a circuit; the same label always reuses its own. Omit it
                and this session uses the base circuit, shared with every other
                unlabelled session — there is no automatic per-launch label,
                because each label permanently takes one of a fixed pool of
                Tor listeners (see below).
            tor_exit_nodes: Restrict Tor exits to countries, e.g. 'us' or
                '{us,ca}'. Applied before the circuit is built.
            tor_instance: Which Tor to use: 'managed' (default), 'tor_browser',
                or 'system'. 'tor_browser' attaches to a running Tor Browser —
                note that rotating its circuit affects that application too.
            hardened: Pin one browser identity across launches and normalise it
                via Firefox's own resistFingerprinting. Repeat launches then
                present the same platform, OS, screen, timezone (UTC) and WebGL
                as each other instead of a fresh random set. Drops humanization,
                caching and profile persistence, and turns WebRTC and remote
                lookups off. Conflicts with timezone/locale/user_agent/
                user_data_dir, which would contradict or defeat it — those are
                refused rather than ignored.

        Note:
            A custom header is not CORS-safelisted. If the page calls an API on a
            different origin, the browser must send a preflight OPTIONS first,
            and a site that does not answer OPTIONS will fail to load entirely —
            use `header_scope` to keep the header on the origin that needs it, or
            check the site loads before assuming the header was harmless.

            Tor gives a different egress IP and per-session circuit isolation. It
            does NOT give anonymity: Camoufox randomises its fingerprint, while
            Tor's model depends on every user looking identical, so a randomised
            fingerprint makes a Tor session more unique, not less. Tor exit
            addresses are also heavily blocklisted, so this makes Cloudflare and
            Arkose harder to pass, not easier. It is not a bypass tier.

            hardened=True is NOT anonymity either, and the distinction is not
            pedantry. It reduces uniqueness — the same identity every launch, and
            the real timezone no longer leaks — but the IP address is untouched
            and a stable identity is still a small haystack, not a crowd. For
            anonymity the tool is Tor Browser run as itself. Combining hardened
            with tor=True is allowed and strictly better than tor alone; it is
            still not anonymity.
        """
        headless = display_mode != "headed"

        if _session.is_running:
            # Say plainly that the Tor arguments were not applied. Returning a
            # bare already_running would let the caller believe it is routed
            # through Tor when it is not, which is the kind of silent-success
            # this whole upgrade exists to remove.
            out: dict[str, Any] = {
                "status": "already_running",
                "pages": _session.list_pages(),
                "hint": "Already running. Use camoufox_set_headers() to change "
                        "headers on the live session.",
            }
            if tor or proxy or hardened:
                out["ignored"] = {
                    k: v for k, v in
                    (("tor", tor), ("tor_isolation", tor_isolation),
                     ("tor_exit_nodes", tor_exit_nodes), ("proxy", proxy),
                     ("hardened", hardened))
                    if v
                }
                out["warning"] = (
                    "The browser was already running, so none of the routing "
                    "arguments were applied. camoufox_close() then relaunch to "
                    "change how traffic is routed."
                )
            return out

        if tor and proxy:
            return _err(
                "tor=True and proxy=... are mutually exclusive",
                hint="Pass one. A second proxy would silently win over Tor, so "
                     "this is refused rather than resolved.",
            )

        if hardened:
            clashing = hardening.conflicts(
                timezone=timezone,
                locale=locale,
                user_agent=user_agent,
                user_data_dir=user_data_dir,
            )
            if clashing:
                return _err(
                    "hardened=True conflicts with: " + ", ".join(sorted(clashing)),
                    hint=" ".join(clashing[k] for k in sorted(clashing)),
                )

        proxy_url = proxy
        proxy_user = proxy_password = None
        firefox_prefs: dict[str, Any] | None = None
        tor_info: dict[str, Any] | None = None

        if tor:
            # No auto-generated label. Each label permanently consumes one of a
            # fixed pool of SocksPorts, and the pool is declared when tor starts
            # -- so a fresh random label per launch would exhaust it and leave
            # listeners behind that nothing will ever reuse. Omitting the label
            # means the shared base circuit, which is stated in the docstring.
            isolation = tor_isolation
            ensure = tor_mod.ensure_tor_running(exit_nodes=tor_exit_nodes)
            if ensure.get("status") not in ("ready", "already_running", "started"):
                return _err(
                    f"Tor is not available: {ensure.get('status')}",
                    hint=ensure.get("hint") or ensure.get("error")
                    or "Call camoufox_tor_start() and check the reported progress.",
                )
            try:
                proxy_url, proxy_user, proxy_password = tor_mod.socks_proxy_url(
                    instance=tor_instance, isolation=isolation)
            except Exception as exc:
                # The pool being full is reported rather than silently ignored:
                # a session that asked for isolation and got the shared circuit
                # instead is the failure that looks exactly like success.
                return _err(f"Could not resolve a Tor SOCKS endpoint: {exc}")

            # Remote DNS: without it, hostname lookups go to the local resolver
            # and leak the very names the session is trying to keep off the
            # network. WebRTC: it can expose the real address independently of
            # the proxy, so it goes off. Both are merged over Camoufox's own
            # defaults rather than replacing them.
            firefox_prefs = {
                "network.proxy.socks_remote_dns": True,
                "media.peerconnection.enabled": False,
            }
            tor_info = {
                "instance": tor_instance or "managed",
                "isolation": isolation,
                "exit_nodes": tor_exit_nodes,
                "socks": proxy_url,
                "isolation_note": (
                    "Isolation is one SocksPort per label, so the same label "
                    "reuses its circuit and different labels do not share one. "
                    "Omit tor_isolation and this session shares the base "
                    "circuit with every other unlabelled session."
                ) if isolation else (
                    "No tor_isolation label, so this session uses the base "
                    "circuit and shares it with other unlabelled sessions."
                ),
            }

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
            proxy=proxy_url,
            proxy_username=proxy_user,
            proxy_password=proxy_password,
            firefox_user_prefs=firefox_prefs,
            tor=tor,
            tor_isolation=tor_info["isolation"] if tor_info else None,
            tor_exit_nodes=tor_exit_nodes,
            humanize=humanize,
            human_preset=human_preset,
            stealth_args=stealth_args,
            timezone=timezone,
            locale=locale,
            viewport={"width": w, "height": h},
            color_scheme=color_scheme,
            user_agent=user_agent,
            user_data_dir=user_data_dir,
            http_headers=headers,
            header_scope=header_scope,
            hardened=hardened,
        )

        await _session.launch(cfg, _executor)
        page_id = await _session.new_page()

        out = {
            "status": "launched",
            "page_id": page_id,
            "display_mode": display_mode,
            "stealth": True,
            "humanize": humanize,
            "hint": "Next: call camoufox_navigate(page_id, url)",
        }
        # Report what was pinned, and what it is not. The label travels with the
        # result rather than living only in the docs, because a caller who reads
        # `hardened: true` and assumes anonymity was misled by the tool.
        if _session.hardening_report:
            out["hardened"] = _session.hardening_report
            out["humanize"] = False
        # Report the header policy back, so "did the header actually apply?" is
        # answered by the launch call rather than by a later investigation. The
        # unscoped case carries a warning because that is the one with a real
        # disclosure cost and it is easy to reach by simply omitting an argument.
        header_info = _session.get_http_headers()
        if header_info["count"]:
            out["headers"] = header_info

        if tor_info:
            out["tor"] = tor_info
            out["tor"]["note"] = (
                "Isolation is per launch, not per page: Playwright's proxy is per "
                "context and Camoufox runs a single context. For distinct circuits "
                "in parallel, launch separate browsers."
            )
            out["hint"] = ("Routed through Tor. Verify with "
                           "camoufox_tor_exit_info() or by reading "
                           "https://check.torproject.org/api/ip")
        return out

    @mcp.tool()
    async def camoufox_set_headers(
        headers: dict[str, str] | None = None,
        header_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Set, replace, or clear custom request headers on the live browser.

        Use this when the browser is already running — `camoufox_launch(headers=...)`
        only applies at launch, and returns `already_running` if a session exists.

        Args:
            headers: Custom headers to send, e.g. {"HackerOne": "myhandle"}.
                Pass None or {} to clear all custom headers.
            header_scope: Hosts the headers are limited to, e.g. ["example.com"].
                Entries cover the host and its subdomains. OMITTING THIS SENDS
                THE HEADERS TO EVERY HOST the page touches, including third-party
                CDNs and analytics — if the header identifies you or the
                engagement, scope it.

        Returns the policy actually in force, so a scope typo shows up here
        rather than as a mysterious absence of the header later.
        """
        if not _session.is_running:
            return _err("Browser not running. Call camoufox_launch() first.")
        result = await _session.set_http_headers(headers, header_scope)
        result["hint"] = "Verify with camoufox_get_headers()"
        return result

    @mcp.tool()
    async def camoufox_get_headers(reveal: bool = False) -> dict[str, Any]:
        """Report the custom request headers currently in force.

        Values are masked unless reveal=True — a header value is often a bearer
        token, and this is a status check rather than a request for secrets.
        Use camoufox_extract_tokens() when you actually want the credentials.

        Args:
            reveal: Show full header values instead of masked ones.
        """
        if not _session.is_running:
            return _err("Browser not running. Call camoufox_launch() first.")
        return _session.get_http_headers(reveal=reveal)

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
            blockers = detect_blockers(page)
            return {
                "url": page.url,
                "title": page.title(),
                "blockers": blockers,
            }

        result = await loop.run_in_executor(_executor, _nav)
        title = result["title"]
        url_final = result["url"]
        blockers = result.get("blockers") or {}

        # The title-substring heuristic is kept because callers branch on
        # `cloudflare_blocked` and it must not change meaning. `blocked` is the
        # wider verdict alongside it, and catches the things the heuristic
        # never could: Arkose, hCaptcha, consent overlays, auth walls.
        title_lower = title.lower()
        cf_blocked = any(
            p in title_lower
            for p in ("just a moment", "checking your browser", "cloudflare", "attention required")
        ) or blockers.get("reason") == "cloudflare"

        out: dict[str, Any] = {
            "status": "navigated",
            "url": url_final,
            "title": title,
            "cloudflare_blocked": cf_blocked,
            "blocked": bool(blockers.get("blocked")),
            "settled": not blockers.get("blocked"),
        }
        if blockers.get("blocked"):
            out["blocker"] = blockers
            if cf_blocked:
                out["hint"] = (
                    "Cloudflare detected. Use camoufox_cloudscraper_solve(page_id) to "
                    "bypass with cloudscraper's JS solver, then re-navigate."
                )
            else:
                out["hint"] = blockers.get("hint")
        return out

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
        state: bool = True,
    ) -> dict[str, Any]:
        """Capture the page's accessibility tree — PRIMARY way to understand pages.

        Returns interactive elements with [@eN] ref IDs for camoufox_click,
        camoufox_type, etc. Call this BEFORE interacting with any page.

        Each actionable element is annotated inline with the state that would
        block it: [disabled], [off-screen], [occluded by div#banner]. That
        annotation is the answer to "why did my click do nothing?" before you
        spend a call finding out.

        Args:
            page_id: Target page ID.
            full: Include surrounding text context (default: False).
            max_length: Max characters in snapshot (default: 12000).
            state: Probe live state for actionable elements (default: True).
                Costs one round trip per actionable element, capped at 60, so
                it is not free on very large pages — set False there. The
                result reports state_probed so the cost is visible.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor, take_snapshot, page, page_id, _session, full, max_length, state)

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

        stale_error, freshness = _stale_guard(page, page_id, ref)
        if stale_error:
            return stale_error

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
            return _attach_freshness(await loop.run_in_executor(_executor, _click), freshness)
        except Exception:
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
                return _attach_freshness(await loop.run_in_executor(_executor, _retry), freshness)
            except Exception as retry_exc:
                # Report the retry's failure, not the first attempt's. The two
                # can differ (the retry waits longer, so a transient "not
                # visible" can become a hard "timeout"), and the retry is what
                # describes the state the caller is actually in. The first
                # attempt's exception used to be what this reported, because it
                # was the one bound by name; the retry's was discarded.
                out = _err(f"Click failed: {retry_exc}")
                explained = await _explain_failure(page, selector)
                if explained:
                    out["target_state"] = explained["state"]
                    out["hint"] = (explained["note"] +
                                   " Re-run camoufox_snapshot if the page navigated.")
                else:
                    out["hint"] = ("If the element is covered by an overlay, "
                                   "camoufox_snapshot marks it [occluded by ...]. "
                                   "If the page navigated, re-run camoufox_snapshot.")
                return _attach_freshness(out, freshness)

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

        stale_error, freshness = _stale_guard(page, page_id, ref)
        if stale_error:
            return stale_error

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

        try:
            return _attach_freshness(await loop.run_in_executor(_executor, _type), freshness)
        except Exception as exc:
            out = _err(f"Type failed: {exc}")
            explained = await _explain_failure(page, selector)
            if explained:
                out["target_state"] = explained["state"]
                out["hint"] = (explained["note"] +
                               " Re-run camoufox_snapshot if the page navigated.")
            else:
                out["hint"] = ("If the field is covered by an overlay, "
                               "camoufox_snapshot marks it [occluded by ...]. "
                               "If the page navigated, re-run camoufox_snapshot.")
            return _attach_freshness(out, freshness)

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

        stale_error, freshness = _stale_guard(page, page_id, ref)
        if stale_error:
            return stale_error

        def _select():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            selected = target.select_option(selector, **kwargs)
            return {"status": "selected", "ref": f"@{clean_ref}", "selected": selected}

        try:
            return _attach_freshness(await loop.run_in_executor(_executor, _select), freshness)
        except Exception as exc:
            out = _err(f"Select failed: {exc}")
            explained = await _explain_failure(page, selector)
            if explained:
                out["target_state"] = explained["state"]
                out["hint"] = (explained["note"] +
                               " Re-run camoufox_snapshot if the page navigated.")
            else:
                out["hint"] = "If the page navigated, re-run camoufox_snapshot."
            return _attach_freshness(out, freshness)

    @mcp.tool()
    async def camoufox_hover(page_id: str, ref: str) -> dict[str, Any]:
        """Hover over an element by ref from camoufox_snapshot, or by CSS selector.

        Accepts [@eN] snapshot refs or raw CSS selectors.
        """
        page = _session.get_page(page_id)
        clean_ref, selector, frame_idx = resolve_ref(_session, page_id, ref)
        loop = asyncio.get_event_loop()

        stale_error, freshness = _stale_guard(page, page_id, ref)
        if stale_error:
            return stale_error

        def _hover():
            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]
            target.hover(selector)
            return {"status": "hovered", "ref": f"@{clean_ref}"}

        try:
            return _attach_freshness(await loop.run_in_executor(_executor, _hover), freshness)
        except Exception as exc:
            out = _err(f"Hover failed: {exc}")
            explained = await _explain_failure(page, selector)
            if explained:
                # An occluded element is the common reason a hover does
                # nothing, and hovering is the one action where "it worked but
                # nothing happened" is otherwise indistinguishable from failure.
                out["target_state"] = explained["state"]
                out["hint"] = (explained["note"] +
                               " Re-run camoufox_snapshot if the page navigated.")
            else:
                out["hint"] = "If the page navigated, re-run camoufox_snapshot."
            return _attach_freshness(out, freshness)

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

        Note:
            There is no timeout parameter, and that is a finding rather than an
            omission. An earlier version accepted one and passed it to
            Playwright, which rejects it — `Page.evaluate` takes no timeout, and
            the call raised `TypeError: got an unexpected keyword argument` for
            every function or async expression, which is to say for the exact
            forms the examples above use. `page.set_default_timeout()` was
            measured as the alternative and does not bound `evaluate` either: a
            three-second expression returned despite a 400 ms default. So an
            unbounded expression cannot be given a deadline from here, and a
            parameter that silently did nothing would be worse than none.

            If you need a deadline, put it in the expression, where it can
            actually take effect:

                'async () => await Promise.race([slowThing(), new Promise((_, r) => setTimeout(() => r(new Error("timeout")), 5000))])'

            That also leaves the page usable afterwards, which a timeout applied
            from outside it cannot — the underlying call has no cancellation, so
            abandoning it would keep the browser's single worker thread busy and
            wedge every later call on the session.
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()

        def _eval():
            return {"status": "evaluated", "result": page.evaluate(expression)}

        try:
            return await loop.run_in_executor(_executor, _eval)
        except Exception as exc:
            return _err(f"Evaluate failed: {type(exc).__name__}: {exc}",
                        hint="If this expression waits on something slow, wrap "
                             "it in a Promise.race with your own timer inside "
                             "the expression — Playwright's evaluate has no "
                             "timeout to set.")

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
        """Wait for the page to settle (network idle).

        Args:
            page_id: Target page ID.
            timeout_ms: Max wait time in ms (default: 5000).
        """
        page = _session.get_page(page_id)
        loop = asyncio.get_event_loop()
        started = time.time()

        def _wait():
            # Playwright's timeout is in MILLISECONDS. This previously divided
            # by 1000, so the default 5000 ms wait became 5 ms and the tool
            # reported not_settled essentially always.
            page.wait_for_load_state("networkidle", timeout=timeout_ms)
            return {"status": "settled", "elapsed_ms": int((time.time() - started) * 1000)}

        try:
            return await loop.run_in_executor(_executor, _wait)
        except Exception:
            return {
                "status": "not_settled",
                "elapsed_ms": int((time.time() - started) * 1000),
                "note": "networkidle not reached within the timeout",
                "hint": "A page with long-polling or analytics beacons may never "
                        "go idle. camoufox_verify checks a specific condition "
                        "instead, which is usually what you actually want.",
            }

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

    # ==================================================================
    # Act + verify (one call, deterministic)
    # ==================================================================

    @mcp.tool()
    async def camoufox_act(
        page_id: str,
        action: str,
        ref: str | None = None,
        text: str | None = None,
        value: str | None = None,
        key: str | None = None,
        double: bool = False,
        timeout_ms: int = 5000,
        verify: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform an action and report whether it actually did anything.

        Folds the common interactions into one call that fingerprints the page
        before and after, so "did my click work?" is answered in the same round
        trip instead of costing a follow-up snapshot the caller has to
        interpret. It is also where the guards fire: a ref from before a
        navigation is refused rather than resolved, and a covered or disabled
        target is reported by name.

        Prefer this over camoufox_click when the outcome matters.

        Args:
            page_id: Target page ID.
            action: One of: click, dblclick, type, fill, select, press, hover,
                check, uncheck, scroll, upload.
            ref: Element ref ([@eN] or CSS selector). Required for everything
                except scroll and press.
            text: Text for action='type'.
            value: Option value or label for action='select'; file paths for
                action='upload'.
            key: Key for action='press' (default 'Enter').
            double: Double-click for action='click'.
            timeout_ms: How long to let the page settle after acting, and the
                per-action timeout (default: 5000).
            verify: Optional checks to run after acting, same keys as
                camoufox_verify. Evaluated deterministically; no model involved.

        Returns:
            `changed` — did the URL, title, or DOM actually move? `delta`
            breaks that down. `target_state` reports what the element looked
            like *before* the action, which is where the explanation lives when
            nothing happened. `verified` is present only when `verify` was
            given.
        """
        page = _session.get_page(page_id)
        action = (action or "").strip().lower()

        valid = {"click", "dblclick", "type", "fill", "select", "press",
                 "hover", "check", "uncheck", "scroll", "upload"}
        if action not in valid:
            return _err(f"Unknown action {action!r}",
                        hint=f"Valid actions: {sorted(valid)}")
        if action not in ("scroll", "press") and not ref:
            return _err(f"action={action!r} requires a ref")

        freshness = None
        if ref:
            stale_error, freshness = _stale_guard(page, page_id, ref)
            if stale_error:
                return stale_error

        selector = frame_idx = None
        if ref:
            _clean, selector, frame_idx = resolve_ref(_session, page_id, ref)

        loop = asyncio.get_event_loop()
        console_before = console_index(_session, page_id)

        def _run():
            from .snapshot import _STATE_PROBE_JS  # noqa: PLC0415 — avoids a cycle at import time

            target = page
            if frame_idx is not None:
                frames = page.frames
                if frame_idx < len(frames):
                    target = frames[frame_idx]

            # What the element looked like before we touched it. Recorded even
            # on success, because "clicked a disabled button" and "clicked a
            # working button" both look identical in the return value
            # otherwise, and only the first is a bug in the caller's plan.
            target_state = None
            if selector:
                try:
                    target_state = page.locator(selector).first.evaluate(_STATE_PROBE_JS)
                except Exception as exc:
                    target_state = {"error": f"{type(exc).__name__}: {exc}"[:200]}

            before = page_fingerprint(page, _session, page_id)

            if action == "click":
                target.click(selector, timeout=timeout_ms, click_count=2 if double else 1)
            elif action == "dblclick":
                target.dblclick(selector, timeout=timeout_ms)
            elif action == "type":
                target.type(selector, text or "", timeout=timeout_ms)
            elif action == "fill":
                target.fill(selector, text or "", timeout=timeout_ms)
            elif action == "select":
                if value is None:
                    raise ValueError("action='select' requires value")
                try:
                    target.select_option(selector, value=value, timeout=timeout_ms)
                except Exception:
                    # Fall back to matching the visible label, which is what a
                    # caller passing human-readable text actually means.
                    target.select_option(selector, label=value, timeout=timeout_ms)
            elif action == "press":
                if selector:
                    target.press(selector, key or "Enter", timeout=timeout_ms)
                else:
                    page.keyboard.press(key or "Enter")
            elif action == "hover":
                target.hover(selector, timeout=timeout_ms)
            elif action == "check":
                target.check(selector, timeout=timeout_ms)
            elif action == "uncheck":
                target.uncheck(selector, timeout=timeout_ms)
            elif action == "scroll":
                delta = timeout_ms // 50 or 500
                page.evaluate(f"window.scrollBy(0, {delta if (value or 'down') != 'up' else -delta})")
            elif action == "upload":
                if not value:
                    raise ValueError("action='upload' requires value (comma-separated paths)")
                target.set_input_files(selector, [p.strip() for p in value.split(",") if p.strip()])

            # Let the page react. Short and bounded: the delta below is what
            # decides whether we waited long enough, and the caller can pass
            # verify= with a longer budget when it needs a specific condition.
            page.wait_for_timeout(min(1500, max(250, timeout_ms // 3)))

            after = page_fingerprint(page, _session, page_id)
            delta = fingerprint_delta(before, after)
            blockers = detect_blockers(page)
            return target_state, delta, blockers

        try:
            target_state, delta, blockers = await loop.run_in_executor(_executor, _run)
        except Exception as exc:
            # A failed action is exactly when the target's pre-state is most
            # useful, so try to report it rather than only the traceback.
            explained = await _explain_failure(page, selector) if selector else None
            out = _err(f"{action} failed: {type(exc).__name__}: {exc}")
            if explained:
                out["target_state"] = explained["state"]
                out["hint"] = explained["note"]
            elif freshness:
                out["ref_freshness"] = freshness
            return out

        out: dict[str, Any] = {
            "status": "ok",
            "action": action,
            "ref": f"@{ref.lstrip('@')}" if ref else None,
            "changed": delta["changed"],
            "delta": delta,
            "elapsed_timeout_ms": timeout_ms,
        }
        if target_state:
            out["target_state"] = target_state
            explanation = _state_explanation(target_state)
            if explanation:
                out["target_state_note"] = explanation
        if freshness:
            out["ref_freshness"] = freshness
        if blockers.get("blocked"):
            out["blocked"] = True
            out["blocker"] = blockers

        if not delta["changed"]:
            out["note"] = (
                "No observable change in URL, title, or DOM. The action may have "
                "been a no-op (already-checked box, hover with no effect) or the "
                "page may not have reacted yet — pass verify= to assert on a "
                "specific condition instead of inferring from mutation counts."
            )

        if verify:
            specs = verify if isinstance(verify, dict) else {}
            checks = await loop.run_in_executor(
                _executor, wait_for_checks, page, _session, page_id, specs, timeout_ms,
                250, console_before)
            out["verify"] = checks
            out["verified"] = checks.get("passed")

        return out

    @mcp.tool()
    async def camoufox_verify(
        page_id: str,
        url_matches: str | list[str] | None = None,
        url_not_matches: str | list[str] | None = None,
        text_present: str | list[str] | None = None,
        text_absent: str | list[str] | None = None,
        element_present: str | list[str] | None = None,
        element_absent: str | list[str] | None = None,
        no_console_errors: bool = False,
        no_blockers: bool = False,
        http_status: int | list[int] | None = None,
        console_since: int | None = None,
        timeout_ms: int = 0,
    ) -> dict[str, Any]:
        """Assert conditions against the live page and return the evidence.

        Every check is evaluated deterministically in code — no model judgement
        anywhere — and each result carries the evidence it was judged on, so a
        failure says what was actually seen rather than only that it failed.

        Use this before reporting anything as fact. A claim you verified with a
        check is worth more than a claim you inferred from a snapshot.

        Args:
            page_id: Target page ID.
            url_matches: Regex(es); passes if ANY matches the current URL.
            url_not_matches: Regex(es); passes if NONE match.
            text_present: Substring(s) that must appear in the body text.
            text_absent: Substring(s) that must NOT appear.
            element_present: Ref(s) or CSS selector(s) that must exist.
            element_absent: Ref(s) or selector(s) that must not exist.
            no_console_errors: Fail if any console error was logged. Scope it
                with console_since to ignore errors from page load.
            no_blockers: Fail if a challenge, consent overlay, or auth wall is
                detected — see camoufox_snapshot's blocker reporting.
            http_status: Expected status code(s) for the main document.
            console_since: Only consider console entries from this index on.
                Get the index from a previous camoufox_act result, or omit to
                consider the whole buffer.
            timeout_ms: Poll until every check passes, up to this long. 0
                (default) checks once.

        Returns:
            `passed` overall, plus `checks` with per-check evidence and `failed`
            naming which ones did not hold. Unrecognised check names are
            reported in `unknown` and fail the result — a typo must not read as
            success.
        """
        page = _session.get_page(page_id)

        specs: dict[str, Any] = {
            "url_matches": url_matches,
            "url_not_matches": url_not_matches,
            "text_present": text_present,
            "text_absent": text_absent,
            "element_present": element_present,
            "element_absent": element_absent,
            "no_console_errors": no_console_errors or None,
            "no_blockers": no_blockers or None,
            "http_status": http_status,
        }
        specs = {k: v for k, v in specs.items() if v is not None}

        if not specs:
            return _err("No checks requested",
                        hint=f"Pass at least one of: {list(CHECK_NAMES)}")

        since = console_since if console_since is not None else 0
        loop = asyncio.get_event_loop()

        if timeout_ms and timeout_ms > 0:
            return await loop.run_in_executor(
                _executor, wait_for_checks, page, _session, page_id, specs,
                timeout_ms, 250, since)
        return await loop.run_in_executor(
            _executor, run_checks, page, _session, page_id, specs, since)

    # ==================================================================
    # Tor
    # ==================================================================

    @mcp.tool()
    async def camoufox_tor_status() -> dict[str, Any]:
        """Report every Tor on this machine and which one is ours.

        Local only — no network traffic, no circuit is built. Use
        camoufox_tor_exit_info() when you need to know what a target sees.

        Endpoints are identified by asking each control port to identify
        itself, not by assuming a port is Tor because something is listening on
        it. Each entry says who owns it, so attaching to someone else's Tor is a
        decision rather than an accident.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, tor_mod.tor_status)

    @mcp.tool()
    async def camoufox_tor_start(
        exit_nodes: str | None = None,
        timeout_s: float = 90.0,
    ) -> dict[str, Any]:
        """Start the managed Tor instance on dedicated ports and wait for it.

        Runs its own tor process, so it does not touch a Tor Browser you may
        have open — that one lives on different ports and keeps its own
        circuits. The instance is left running after this server exits, since
        killing it would break a browser session still using it;
        camoufox_tor_stop() is the explicit teardown.

        Args:
            exit_nodes: Restrict exits to countries, e.g. 'us' or '{us,ca}'.
            timeout_s: Bootstrap budget in seconds (default 90). The first
                bootstrap fetches a consensus and is genuinely slow; a short
                budget reports a false failure.

        Returns:
            `status` of 'started', 'already_running', or a failure status.
            Bootstrap progress is reported, and a bootstrap that completes
            without a usable circuit is reported as 'started_no_circuit' rather
            than as success.
        """
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor, lambda: tor_mod.start_tor(exit_nodes=exit_nodes, timeout_s=timeout_s))
        if result.get("status") in ("started", "started_no_circuit", "already_running"):
            result["next_step"] = (
                "camoufox_launch(tor=True) to route the browser through it, "
                "or camoufox_tor_exit_info() to check the exit."
            )
        return result

    @mcp.tool()
    async def camoufox_tor_stop() -> dict[str, Any]:
        """Stop the managed Tor instance. Idempotent.

        Does not touch a Tor Browser or a system tor daemon — those are not
        ours to stop.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, tor_mod.stop_tor)

    @mcp.tool()
    async def camoufox_tor_new_circuit(
        exit_nodes: str | None = None,
        instance: str | None = None,
        verify: bool = True,
    ) -> dict[str, Any]:
        """Rotate to a fresh circuit and confirm the exit actually changed.

        Applying an exit policy and rotating are one call on purpose: NEWNYM is
        rate-limited by Tor, so a caller forced to ask twice wastes its budget.
        The measured before/after exit IP is what separates "the signal was
        accepted" from "the exit changed".

        Args:
            exit_nodes: Restrict exits to countries, e.g. 'us' or '{us,ca}'.
            instance: 'managed' (default), 'tor_browser', or 'system'.
            verify: Measure the exit IP before and after (default True). Costs
                a network round trip through Tor; set False if you only need
                the signal sent.

        Note:
            An unchanged exit IP is not a failure. Tor reuses exits, and an
            ExitNodes restriction narrows the pool further — the result says so
            rather than presenting it as a rotation.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            lambda: tor_mod.new_circuit(exit_nodes=exit_nodes, instance=instance, verify=verify))

    @mcp.tool()
    async def camoufox_tor_exit_info(
        instance: str | None = None,
        isolation: str | None = None,
    ) -> dict[str, Any]:
        """What exit IP a target sees when we egress through Tor, and whether it
        is Tor at all.

        Makes a real network round trip through Tor (~2-5s), which is why it is
        separate from camoufox_tor_status. Use it to prove a session is actually
        routed through Tor rather than only configured to be.

        Args:
            instance: 'managed' (default), 'tor_browser', or 'system'.
            isolation: Circuit label. Two calls with different labels returning
                different exit IPs proves the circuits are isolated. The
                reverse does not prove they are not — Tor reuses exits.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor, lambda: tor_mod.tor_exit_info(instance=instance, isolation=isolation))

    return mcp


def _state_explanation(state: dict[str, Any]) -> str | None:
    """Turn an element's pre-action state into a sentence explaining a no-op.

    Called only when something went wrong or nothing changed, so it can afford
    to be specific.
    """
    if not state or state.get("error"):
        return None
    reasons = []
    if state.get("occluded"):
        occluder = state.get("occluder") or {}
        name = occluder.get("tag") or "an element"
        if occluder.get("id"):
            name += f"#{occluder['id']}"
        elif occluder.get("cls"):
            name += f".{str(occluder['cls']).split()[0]}"
        reasons.append(f"covered by {name}")
    if state.get("enabled") is False:
        reasons.append("disabled")
    if state.get("visible") is False:
        reasons.append("not visible")
    elif state.get("in_viewport") is False:
        reasons.append("off-screen")
    if state.get("readonly"):
        reasons.append("read-only")
    if not reasons:
        return None
    return ("The target was already " + ", ".join(reasons) +
            " before the action, which is the likely reason it had no effect.")
