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
import base64
import hashlib
import hmac
import struct
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

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


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) — for logins that ask for an authenticator code
# ---------------------------------------------------------------------------

def _totp_key(name: str) -> str:
    # '#' cannot appear in an account name, so this never collides with one.
    return f"{name}#totp"


def parse_totp_secret(value: str) -> dict[str, Any]:
    """Accept a bare base32 secret or an otpauth:// URI; return the parameters."""
    value = (value or "").strip()
    params: dict[str, Any] = {"digits": 6, "period": 30, "algo": "SHA1"}
    secret = value
    if value.lower().startswith("otpauth://"):
        u = urlparse(value)
        if u.netloc.lower() != "totp":
            raise CredentialError("Only TOTP otpauth:// URIs are supported (not HOTP).")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        secret = q.get("secret", "")
        try:
            params["digits"] = int(q.get("digits", 6))
            params["period"] = int(q.get("period", 30))
        except ValueError as exc:
            raise CredentialError("Invalid digits/period in the otpauth URI.") from exc
        params["algo"] = q.get("algorithm", "SHA1").upper()
    secret = secret.replace(" ", "").replace("-", "").upper()
    if params["algo"] not in ("SHA1", "SHA256", "SHA512"):
        raise CredentialError(f"Unsupported TOTP algorithm {params['algo']}.")
    if params["digits"] not in (6, 7, 8) or not 10 <= params["period"] <= 120:
        raise CredentialError("Unsupported TOTP digits/period.")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8))
    except Exception as exc:  # noqa: BLE001
        raise CredentialError("The TOTP secret is not valid base32.") from exc
    if not secret:
        raise CredentialError("Empty TOTP secret.")
    params["secret"] = secret
    return params


def totp_code(params: dict[str, Any], at: float | None = None) -> str:
    key = base64.b32decode(params["secret"] + "=" * (-len(params["secret"]) % 8))
    counter = int((time.time() if at is None else at) // params["period"])
    digest = hmac.new(key, struct.pack(">Q", counter),
                      getattr(hashlib, params["algo"].lower())).digest()
    off = digest[-1] & 0x0F
    num = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** params["digits"]
    return str(num).zfill(params["digits"])


def seconds_left(params: dict[str, Any], at: float | None = None) -> float:
    now = time.time() if at is None else at
    return params["period"] - (now % params["period"])


def save_totp(name: str, params: dict[str, Any]) -> None:
    kr = _backend()
    try:
        kr.set_password(SERVICE, _totp_key(name), json.dumps(params))
    except Exception as exc:  # noqa: BLE001
        raise CredentialError(f"Keychain refused to store the TOTP secret: {exc}") from exc


def load_totp(name: str) -> dict[str, Any]:
    kr = _backend()
    try:
        raw = kr.get_password(SERVICE, _totp_key(name))
    except Exception as exc:  # noqa: BLE001
        raise CredentialError(f"Keychain read failed: {exc}") from exc
    if not raw:
        raise CredentialError(f"No TOTP secret saved for account {name!r}.")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise CredentialError(f"Stored TOTP secret for {name!r} is corrupt.") from exc


def delete_totp(name: str) -> bool:
    try:
        kr = _backend()
        kr.delete_password(SERVICE, _totp_key(name))
        return True
    except Exception:  # noqa: BLE001
        return False


# Tags the verification-code input(s). Handles a single field and the common
# "one digit per box" layout (a run of maxlength=1 inputs). Returns the count.
FIND_OTP_JS = """
() => {
  const vis = e => {
    const r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden'
      && s.display !== 'none' && !e.disabled && !e.readOnly;
  };
  document.querySelectorAll('[data-cmcp-otp]').forEach(e => e.removeAttribute('data-cmcp-otp'));
  const all = [...document.querySelectorAll('input')].filter(vis)
    .filter(e => !['password', 'hidden', 'checkbox', 'radio', 'submit', 'button', 'search']
      .includes(e.type));
  const boxes = all.filter(e => e.maxLength === 1);
  if (boxes.length >= 4) {
    boxes.forEach((e, i) => e.setAttribute('data-cmcp-otp', String(i)));
    return {count: boxes.length, split: true};
  }
  const hint = e => /otp|one-?time|code|token|2fa|mfa|verif|authenticator|totp/i.test(
    [e.name, e.id, e.autocomplete, e.placeholder, e.getAttribute('aria-label')].join(' '));
  const one = all.find(e => e.autocomplete === 'one-time-code')
    || all.find(hint)
    || all.find(e => e.inputMode === 'numeric' && e.maxLength >= 6 && e.maxLength <= 8);
  if (!one) return {count: 0, split: false};
  one.setAttribute('data-cmcp-otp', '0');
  return {count: 1, split: false};
}
"""
OTP_SEL = "[data-cmcp-otp]"
