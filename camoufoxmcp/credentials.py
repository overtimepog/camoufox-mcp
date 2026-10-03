"""Credentials for autofill — passwords live in the OS keychain, nowhere else.

A saved *session* (see accounts.py) is enough until the site expires it. To log
back in without a human, the username and password have to be kept too. They
are stored in the operating system's secret store (macOS Keychain, Windows
Credential Locker, Secret Service/KWallet on Linux) through ``keyring`` --
never in the account vault's JSON files, never in logs, never in a tool result.

If no secure backend is available, saving is REFUSED. There is deliberately no
plaintext fallback: a silent downgrade to a readable file is exactly the
failure this module exists to avoid.

Autofill is bound to the account's site. A page whose host is not that site (or
a subdomain of it) is refused, because a lookalike page that persuades an agent
to "log in" would otherwise be handed the real password.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

SERVICE = "camoufox-mcp"


class CredentialError(RuntimeError):
    """A credential operation that cannot proceed."""


def _backend():
    try:
        import keyring
        from keyring.backends import fail
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise CredentialError(
            "The 'keyring' package is not installed (pip install keyring)."
        ) from exc
    kr = keyring.get_keyring()
    if isinstance(kr, fail.Keyring) or getattr(kr, "priority", 1) < 1:
        raise CredentialError(
            "No secure keychain backend is available on this system, so "
            "passwords cannot be stored safely. Refusing to fall back to a "
            "plaintext file."
        )
    # Return the backend we just vetted, not the `keyring` module: the module's
    # set_password() resolves its own global backend, which could differ from
    # the one checked above.
    return kr


def available() -> bool:
    try:
        _backend()
        return True
    except CredentialError:
        return False


def save(name: str, username: str, password: str) -> None:
    if not username or not password:
        raise CredentialError("Both a username and a password are required.")
    kr = _backend()
    try:
        kr.set_password(SERVICE, name, json.dumps({"u": username, "p": password}))
    except Exception as exc:  # noqa: BLE001 - backends raise assorted types
        raise CredentialError(f"Keychain refused to store the credential: {exc}") from exc


def load(name: str) -> tuple[str, str]:
    kr = _backend()
    try:
        raw = kr.get_password(SERVICE, name)
    except Exception as exc:  # noqa: BLE001
        raise CredentialError(f"Keychain read failed: {exc}") from exc
    if not raw:
        raise CredentialError(f"No saved credentials for account {name!r}.")
    try:
        d = json.loads(raw)
        return d["u"], d["p"]
    except (ValueError, KeyError, TypeError) as exc:
        raise CredentialError(f"Stored credentials for {name!r} are corrupt.") from exc


def delete(name: str) -> bool:
    """Remove the credential. True if one existed. Never raises on 'not found'."""
    try:
        kr = _backend()
    except CredentialError:
        return False
    try:
        kr.delete_password(SERVICE, name)
        return True
    except Exception:  # noqa: BLE001 - PasswordDeleteError when absent
        return False


def host_matches(page_url: str, site: str) -> bool:
    """True if the page's host is ``site`` or one of its subdomains.

    Exact-label match, not a suffix test on the raw string: ``evilexample.com``
    must not match ``example.com``.
    """
    host = (urlparse(page_url).hostname or "").lower().rstrip(".")
    s = site.lower().strip().lstrip(".").rstrip(".")
    if "://" in s:
        s = (urlparse(s).hostname or "").lower()
    if not host or not s:
        return False
    return host == s or host.endswith("." + s)


# Finds the login fields on the page and tags them so Playwright can address
# them by selector. Runs in the page; returns only which fields exist, never
# values. Handles single-page logins and the two-step flow (username page, then
# password page): whichever field is present is the one reported.
FIND_LOGIN_JS = """
() => {
  const vis = e => {
    const r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden'
      && s.display !== 'none' && !e.disabled && !e.readOnly;
  };
  document.querySelectorAll('[data-cmcp-user],[data-cmcp-pass]').forEach(e => {
    e.removeAttribute('data-cmcp-user'); e.removeAttribute('data-cmcp-pass');
  });
  const all = [...document.querySelectorAll('input')].filter(vis);
  const pw = all.find(e => e.type === 'password') || null;
  const textual = all.filter(e => ['text', 'email', 'tel', ''].includes(e.type));
  const hint = e => /user|login|email|mail|account|identifier|phone/i.test(
    [e.name, e.id, e.autocomplete, e.placeholder, e.getAttribute('aria-label')].join(' '));
  let user = null;
  if (pw) {
    const before = textual.filter(
      e => e.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    user = before.length ? before[before.length - 1] : null;
  } else {
    user = textual.find(hint) || (textual.length === 1 ? textual[0] : null);
  }
  if (user) user.setAttribute('data-cmcp-user', '1');
  if (pw) pw.setAttribute('data-cmcp-pass', '1');
  return {user: !!user, password: !!pw};
}
"""

READ_LOGIN_JS = """
() => {
  const u = document.querySelector('[data-cmcp-user]');
  const p = document.querySelector('[data-cmcp-pass]');
  return {username: u ? u.value : '', password: p ? p.value : ''};
}
"""

USER_SEL = "[data-cmcp-user]"
PASS_SEL = "[data-cmcp-pass]"


def describe(found: dict[str, Any]) -> str:
    if found.get("user") and found.get("password"):
        return "username+password"
    if found.get("password"):
        return "password"
    if found.get("user"):
        return "username"
    return "none"
