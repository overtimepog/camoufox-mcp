"""Locate login / 2FA fields across the top page AND its iframes.

Many real logins live in an iframe: an embedded SSO widget, a payment-provider
challenge, a consent screen served from an identity domain. Playwright can run
code in any frame, same-origin or not, so finding the fields is the easy half.

The hard half is trust. Credentials belong to one account on one site. Handing
them to a third-party frame just because it is on the page would let any page
embed a hostile frame and harvest the password. So, in addition to the top-level
page having to be the account's site (checked by the caller):

  * a frame is searched only if its host is the account's site (or a subdomain),
    OR is one the user explicitly trusted for that account (``frame_hosts``);
  * every other visible frame is *reported* as skipped -- by host -- so the
    caller can say what was refused and how to allow it deliberately;
  * hidden frames are ignored (a zero-size frame is a classic way to slip a
    credential harvester onto a page).
"""

from __future__ import annotations

from typing import Any, Callable, Iterable
from urllib.parse import urlparse

from . import credentials as cred


def _visible(frame: Any) -> bool:
    try:
        return bool(frame.frame_element().is_visible())
    except Exception:  # noqa: BLE001 - detached / navigating frames
        return False


def allowed_frames(page: Any, site: str, trusted: Iterable[str] = ()) -> tuple[list[Any], list[str]]:
    """(frames we may fill, hosts of visible frames we refused).

    The main frame is always first; the caller has already confirmed the top
    page is the account's site.
    """
    trusted = list(trusted or [])
    main = page.main_frame
    ok: list[Any] = [main]
    skipped: list[str] = []
    for f in page.frames:
        if f is main:
            continue
        url = getattr(f, "url", "") or ""
        if not url.startswith(("http://", "https://")):
            continue  # about:blank / srcdoc / data: carry no site identity
        if not _visible(f):
            continue
        if cred.host_matches(url, site) or any(cred.host_matches(url, h) for h in trusted):
            ok.append(f)
        else:
            host = urlparse(url).hostname or url
            if host not in skipped:
                skipped.append(host)
    return ok, skipped


def locate(
    page: Any,
    js: str,
    site: str,
    trusted: Iterable[str],
    score: Callable[[Any], int],
) -> tuple[tuple[Any, Any] | None, list[str]]:
    """Run ``js`` in each allowed frame; return the best ``(frame, result)``.

    ``score(result)`` is 0 for "nothing here". The highest-scoring frame wins,
    earliest frame on ties (so the top page beats an iframe when both qualify).
    """
    frames, skipped = allowed_frames(page, site, trusted)
    best: tuple[Any, Any] | None = None
    best_score = 0
    for f in frames:
        try:
            r = f.evaluate(js)
        except Exception:  # noqa: BLE001
            continue
        s = score(r)
        if s > best_score:
            best, best_score = (f, r), s
    return best, skipped


def login_score(found: dict[str, Any]) -> int:
    return (2 if found.get("password") else 0) + (1 if found.get("user") else 0)


def otp_score(found: dict[str, Any]) -> int:
    return int(found.get("count", 0))


def frame_label(frame: Any, page: Any) -> str:
    return "top page" if frame is page.main_frame else (urlparse(frame.url).hostname or "iframe")
