"""Account vault — named, re-usable logins.

A "login" in a browser is its storage state: cookies plus localStorage. This
module keeps that state on disk under a name, so a session authenticated once
can be restored by name later instead of being driven through a login form
again.

What is stored, and what is not:
  * Stored: Playwright ``storage_state`` (cookies + localStorage per origin),
    plus descriptive metadata (site, username label, notes, timestamps).
  * Not stored: passwords. Nothing here asks for one, and a plaintext password
    file would be a worse artifact than the session it replaces. A saved
    session is still a credential -- anyone who can read the file can act as
    the account -- so files are 0600 inside a 0700 directory and are never
    echoed back by list/describe (only cookie *names* and counts are).

The vault directory is ``~/.camoufoxmcp/accounts`` and can be moved with
``CAMOUFOX_MCP_ACCOUNTS_DIR``.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ENV_DIR = "CAMOUFOX_MCP_ACCOUNTS_DIR"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AccountError(ValueError):
    """A vault operation that cannot proceed (bad name, missing, corrupt)."""


def vault_dir() -> Path:
    override = os.environ.get(ENV_DIR)
    return Path(override).expanduser() if override else Path.home() / ".camoufoxmcp" / "accounts"


def validate_name(name: str) -> str:
    """Names become filenames, so reject anything that could escape the vault."""
    if not isinstance(name, str) or not _NAME_RE.match(name) or name.endswith("."):
        raise AccountError(
            f"Invalid account name {name!r}. Use 1-64 characters from "
            "letters, digits, '.', '_' and '-', starting with a letter or digit."
        )
    return name


def _path(name: str) -> Path:
    return vault_dir() / f"{validate_name(name)}.json"


def _ensure_dir() -> Path:
    d = vault_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _normalise_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise AccountError("storage_state must be an object with 'cookies' and 'origins'.")
    cookies = state.get("cookies") or []
    origins = state.get("origins") or []
    if not isinstance(cookies, list) or not isinstance(origins, list):
        raise AccountError("storage_state 'cookies' and 'origins' must be lists.")
    return {"cookies": cookies, "origins": origins}


def _site_from(state: dict[str, Any]) -> str | None:
    """Best-effort guess at the site when the caller did not name one."""
    for o in state["origins"]:
        host = urlparse(o.get("origin", "")).hostname
        if host:
            return host
    for c in state["cookies"]:
        dom = (c.get("domain") or "").lstrip(".")
        if dom:
            return dom
    return None


def save(
    name: str,
    state: dict[str, Any],
    *,
    site: str | None = None,
    username: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Write (or refresh) an account. Metadata not passed is kept from before."""
    path = _path(name)
    state = _normalise_state(state)
    if not state["cookies"] and not state["origins"]:
        raise AccountError(
            "The session has no cookies or localStorage to save. Log in first, "
            "then save."
        )

    now = time.time()
    prior: dict[str, Any] = {}
    if path.exists():
        try:
            prior = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            prior = {}

    record = {
        "name": name,
        "site": site if site is not None else prior.get("site") or _site_from(state),
        "username": username if username is not None else prior.get("username"),
        "notes": notes if notes is not None else prior.get("notes"),
        "created": prior.get("created", now),
        "updated": now,
        "storage_state": state,
    }

    d = _ensure_dir()
    # Atomic: a crash mid-write must not leave a truncated session behind that
    # the next launch would read as the account's login.
    fd, tmp = tempfile.mkstemp(dir=d, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(record, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return describe_record(record)


def _read(name: str) -> dict[str, Any]:
    path = _path(name)
    if not path.exists():
        raise AccountError(f"No saved account named {name!r}.")
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AccountError(f"Account {name!r} is unreadable: {exc}") from exc
    if not isinstance(record, dict) or "storage_state" not in record:
        raise AccountError(f"Account {name!r} is not a valid account file.")
    return record


def load_state(name: str) -> dict[str, Any]:
    """The storage_state for ``name``, ready for ``new_context(storage_state=...)``."""
    return _normalise_state(_read(name)["storage_state"])


def describe_record(record: dict[str, Any]) -> dict[str, Any]:
    """Summary safe to show: names and counts, never cookie or storage values."""
    state = record.get("storage_state") or {}
    cookies = state.get("cookies") or []
    origins = state.get("origins") or []
    now = time.time()
    expiries = [c["expires"] for c in cookies
                if isinstance(c.get("expires"), (int, float)) and c["expires"] > 0]
    return {
        "name": record.get("name"),
        "site": record.get("site"),
        "username": record.get("username"),
        "notes": record.get("notes"),
        "created": record.get("created"),
        "updated": record.get("updated"),
        "cookie_count": len(cookies),
        "cookie_domains": sorted({(c.get("domain") or "").lstrip(".") for c in cookies} - {""}),
        "local_storage_origins": [o.get("origin") for o in origins],
        # Persistent cookies carry an expiry; session cookies (expires -1) die
        # with the browser but are still captured here, which is the point.
        "earliest_cookie_expiry": min(expiries) if expiries else None,
        "all_persistent_cookies_expired": bool(expiries) and max(expiries) < now,
    }


def describe(name: str) -> dict[str, Any]:
    return describe_record(_read(name))


def list_accounts(site: str | None = None) -> list[dict[str, Any]]:
    d = vault_dir()
    if not d.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.json")):
        try:
            record = json.loads(p.read_text())
            if not isinstance(record, dict) or "storage_state" not in record:
                continue
        except (OSError, json.JSONDecodeError):
            continue
        info = describe_record(record)
        if site and site.lower() not in (info["site"] or "").lower():
            continue
        out.append(info)
    return out


def delete(name: str) -> None:
    path = _path(name)
    if not path.exists():
        raise AccountError(f"No saved account named {name!r}.")
    path.unlink()


def local_storage_init_script(state: dict[str, Any]) -> str | None:
    """JS that restores localStorage on a live context, or None if there is none.

    ``storage_state`` can only be applied when a context is created. For a
    browser that is already running, cookies go in via ``add_cookies`` and
    localStorage has to be written from inside each origin -- this script does
    that, guarded by ``location.origin`` so one origin's data never lands in
    another.
    """
    origins = {o["origin"]: {i["name"]: i["value"] for i in o.get("localStorage", [])}
               for o in state.get("origins", []) if o.get("origin")}
    origins = {k: v for k, v in origins.items() if v}
    if not origins:
        return None
    # json.dumps output is valid JS; escape '</' so it can never close a tag.
    blob = json.dumps(origins).replace("</", "<\\/")
    return (
        "(() => { try { const d = " + blob + "[location.origin]; if (!d) return;"
        " for (const k in d) { if (localStorage.getItem(k) === null)"
        " localStorage.setItem(k, d[k]); } } catch (e) {} })();"
    )
