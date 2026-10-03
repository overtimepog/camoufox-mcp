"""Tor integration — control protocol, managed instance, endpoint discovery.

Five things live here:

  1. `_TorControl` — a client for the real Tor control protocol (the
     ``ControlPort`` text protocol), including SAFECOOKIE authentication.
  2. `find_tor_endpoints()` — discovery. Never assumes a port is Tor just
     because something is listening on it.
  3. Managed instance lifecycle — `start_tor` / `stop_tor` /
     `ensure_tor_running`, driving our own tor process on dedicated ports so
     nothing we do disturbs a Tor Browser the operator is also browsing in.
  4. `_socks5_http_get()` — a minimal stdlib SOCKS5 client, which is what
     makes "did my circuit actually change?" answerable rather than assumed.
  5. Exit-node control and exit-IP verification built on the above.

Why no third-party dependency: the control protocol is line-oriented text
over a socket, the SOCKS5 handshake is a few fixed bytes, and libssl is in
the stdlib. `urllib.request` (used by the other bridges) cannot speak SOCKS,
so this module carries its own tiny client rather than taking on PySocks.
That keeps the install at zero new packages and CI unchanged.

WHAT TOR DOES AND DOES NOT BUY YOU HERE
---------------------------------------
Camoufox randomises its fingerprint. Tor's anonymity model depends on every
user looking *identical*. Those two goals are opposed: a randomised
fingerprint makes a Tor session MORE unique, not less. So routing Camoufox
through Tor gives you a different egress IP and per-session circuit isolation
— reachability and IP hygiene — and it does not give you anonymity.

Separately, Tor exit addresses are heavily blocklisted, so routing through
Tor generally makes Cloudflare, Arkose and friends *harder* to pass, not
easier. Tor is not a bypass tier. Do not treat it as one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("camoufoxmcp")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_SOCKS_PORT = int(os.getenv("CAMOUFOX_TOR_SOCKS_PORT", "19050"))
DEFAULT_CONTROL_PORT = int(os.getenv("CAMOUFOX_TOR_CONTROL_PORT", "19051"))

# Per-label circuit isolation. Tor isolates streams on *different SocksPorts*
# from one another by default, so a dedicated listener per label is the whole
# mechanism. The listeners have to be declared when tor starts: `SETCONF
# +SocksPort=...` is rejected (552 Unrecognized option) and repeating the key
# replaces the list rather than appending, both measured on 0.4.9.6. So the
# pool is fixed at startup and labels are assigned slots from it.
DEFAULT_ISOLATION_SLOTS = int(os.getenv("CAMOUFOX_TOR_ISOLATION_SLOTS", "8"))
# Slot i listens on socks_port + ISOLATION_PORT_STRIDE + i, which keeps the
# pool clear of the base port and of the control port next to it.
ISOLATION_PORT_STRIDE = 10

# Ports we will attach to but never manage. These belong to someone else --
# 9150/9151 are Tor Browser's, 9050 is a system tor daemon's.
TOR_BROWSER_SOCKS_PORT = 9150
TOR_BROWSER_CONTROL_PORT = 9151
SYSTEM_TOR_SOCKS_PORT = 9050
SYSTEM_TOR_CONTROL_PORT = 9051

TOR_DIR = Path(os.getenv("CAMOUFOX_TOR_DIR", str(Path.home() / ".camoufoxmcp" / "tor")))
TORRC_PATH = TOR_DIR / "torrc"
TOR_DATA_DIR = TOR_DIR / "data"
TOR_COOKIE_PATH = TOR_DIR / "control_auth_cookie"
TOR_PID_PATH = TOR_DIR / "tor.pid"
TOR_STATE_PATH = TOR_DIR / "instance.json"
TOR_LOG_PATH = TOR_DIR / "tor.log"
# Persisted label -> isolation slot assignments, so a label keeps its circuit
# across restarts instead of being reshuffled onto another one.
ISOLATION_STATE_PATH = TOR_DIR / "isolations.json"

DEFAULT_EXIT_PROBE_URL = os.getenv(
    "CAMOUFOX_TOR_EXIT_PROBE", "https://check.torproject.org/api/ip"
)

# Bootstrap is genuinely slow the first time (consensus fetch). The
# FlareSolverr bridge polls 15x2s; tor needs a longer budget or we would
# report a false failure on a cold start.
BOOTSTRAP_TIMEOUT_S = float(os.getenv("CAMOUFOX_TOR_BOOTSTRAP_TIMEOUT", "90"))
BOOTSTRAP_POLL_S = 1.0

# The exact HMAC keys from the Tor control spec. These are protocol
# constants, not tunables -- a typo here fails authentication with no useful
# error, so they are spelled out in full rather than abbreviated.
_SAFECOOKIE_SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
_SAFECOOKIE_CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"

# Country codes accepted by ExitNodes. Validated because a malformed
# ExitNodes value does not error -- it silently leaves you with no circuits.
_COUNTRY_RE = re.compile(r"^\{?([a-zA-Z]{2})\}?$")


class TorError(RuntimeError):
    """Tor control protocol or lifecycle failure."""


class TorNotRunning(ConnectionError):
    """No reachable Tor control port for the requested instance."""


class TorAuthError(TorError):
    """Authentication against the control port failed."""


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

_TOR_BINARY_HINTS = (
    "/opt/homebrew/bin/tor",   # Apple silicon Homebrew
    "/usr/local/bin/tor",      # Intel Homebrew
    "/usr/bin/tor",            # distro package
    "/usr/sbin/tor",
)


def tor_binary() -> str | None:
    """Locate the ``tor`` executable, or None.

    Checked in PATH first so an operator's own install wins, then the usual
    package-manager locations, because a GUI-launched MCP server frequently
    has a PATH that does not include /opt/homebrew/bin.
    """
    found = shutil.which("tor")
    if found:
        return found
    for candidate in _TOR_BINARY_HINTS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _tor_install_hint() -> str:
    return "Install Tor: brew install tor (macOS) or apt install tor (Debian/Ubuntu)."


# ---------------------------------------------------------------------------
# Control protocol client
# ---------------------------------------------------------------------------

class _TorControl:
    """A connection to a Tor control port.

    Speaks enough of the protocol to authenticate, read state, set exit
    policy, and rotate circuits. Deliberately synchronous and blocking -- the
    server pushes it onto its browser thread executor, matching how the other
    bridges are called.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_CONTROL_PORT,
                 password: str | None = None, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._file: Any = None
        self.protocol_info: dict[str, Any] = {}
        self.version: str | None = None
        self.auth_method: str | None = None
        self.events: list[str] = []

    # -- connection ------------------------------------------------------

    def connect(self) -> "_TorControl":
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            raise TorNotRunning(
                f"No Tor control port at {self.host}:{self.port} ({type(exc).__name__}). "
                "Call camoufox_tor_start() to start a managed instance."
            ) from exc
        self._sock.settimeout(self.timeout)
        # Buffered line reader. The protocol is line-oriented and the replies
        # can arrive in several reads, so a raw recv() loop would need its own
        # buffering anyway.
        self._file = self._sock.makefile("rwb")
        return self

    def close(self) -> None:
        for closer in (self._file, self._sock):
            try:
                if closer is not None:
                    closer.close()
            except Exception:
                pass
        self._file = None
        self._sock = None

    def __enter__(self) -> "_TorControl":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- framing ---------------------------------------------------------

    def _read_reply(self) -> list[tuple[str, str, str | None]]:
        """Read one complete reply.

        Tor's framing, all of which appears in practice:
          250-text      continuation line
          250 text      final line
          250+text      a data block follows, terminated by "." on its own line
          5xx text      error
          650 text      asynchronous event -- not a reply to anything

        The 650 case is why this loop exists rather than a single readline():
        an event arriving mid-command would otherwise be consumed as the
        command's reply and every subsequent command would read its
        predecessor's answer.
        """
        out: list[tuple[str, str, str | None]] = []
        while True:
            raw = self._file.readline()
            if not raw:
                raise TorError("Tor closed the control connection")
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if len(line) < 4:
                continue

            code, sep, text = line[:3], line[3], line[4:]

            if code == "650":
                self.events.append(text)
                logger.debug("tor event: %s", text)
                continue

            if sep == "+":
                body: list[str] = []
                while True:
                    data_line = self._file.readline()
                    if not data_line:
                        raise TorError("Tor closed the control connection mid data block")
                    decoded = data_line.decode("utf-8", "replace").rstrip("\r\n")
                    if decoded == ".":
                        break
                    body.append(decoded)
                out.append((code, text, "\n".join(body)))
                # The "250 OK" terminator still follows the data block.
                continue

            out.append((code, text, None))
            if sep == " ":
                return out

    def _command(self, cmd: str, allow_error: bool = False) -> list[tuple[str, str, str | None]]:
        if self._file is None:
            raise TorError("control connection is not open")
        logger.debug("tor control >>> %s", cmd.split(" ")[0])
        try:
            self._file.write((cmd + "\r\n").encode("utf-8"))
            self._file.flush()
        except OSError as exc:
            raise TorError(f"failed writing to control port: {exc}") from exc

        lines = self._read_reply()
        final = lines[-1][0] if lines else "000"
        if final.startswith("5") and not allow_error:
            detail = lines[-1][1] if lines else "unknown"
            raise TorError(f"Tor rejected {cmd.split(' ')[0]}: {final} {detail}")
        return lines

    @staticmethod
    def _parse_kv(lines: list[tuple[str, str, str | None]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for code, text, data in lines:
            if code != "250" or text == "OK":
                continue
            if "=" in text:
                key, _, inline = text.partition("=")
                out[key.strip()] = data if data is not None else inline
            elif text:
                out[text.strip()] = True
        return out

    # -- authentication --------------------------------------------------

    def protocolinfo(self) -> dict[str, Any]:
        lines = self._command("PROTOCOLINFO 1")
        info: dict[str, Any] = {"methods": [], "cookie_file": None, "version": None}
        for code, text, _data in lines:
            if code != "250":
                continue
            if text.startswith("AUTH"):
                methods = re.search(r"METHODS=([A-Z,]+)", text)
                if methods:
                    info["methods"] = methods.group(1).split(",")
                cookie = re.search(r'COOKIEFILE="([^"]+)"', text)
                if cookie:
                    info["cookie_file"] = cookie.group(1)
            elif text.startswith("VERSION"):
                version = re.search(r'Tor="([^"]+)"', text)
                if version:
                    info["version"] = version.group(1)
        self.protocol_info = info
        self.version = info.get("version")
        return info

    def authenticate(self) -> str:
        """Authenticate, preferring SAFECOOKIE.

        Order matters: SAFECOOKIE proves possession of the cookie without
        putting it on the wire, so it is preferred over COOKIE even though
        both need the same file. Falls through to COOKIE, then to a password
        if one was supplied, then to a bare AUTHENTICATE (which some builds
        allow for a null-auth control port).
        """
        info = self.protocol_info or self.protocolinfo()
        methods = info.get("methods") or []
        cookie_file = info.get("cookie_file")

        if "SAFECOOKIE" in methods and cookie_file:
            try:
                self._auth_safecookie(cookie_file)
                self.auth_method = "SAFECOOKIE"
                return self.auth_method
            except TorAuthError:
                # A failed server-hash verification is not "try something
                # else". It means the peer could not prove it holds the cookie,
                # i.e. this may not be the tor we think it is. Falling through
                # to a weaker method here would discard the one check that
                # distinguishes an impostor from a real control port, so it
                # propagates.
                raise
            except Exception as exc:
                # Anything else -- an unreadable cookie file, a malformed
                # challenge -- is a local problem, and COOKIE auth may still
                # work.
                logger.info("SAFECOOKIE unavailable (%s); trying COOKIE", exc)

        if "COOKIE" in methods and cookie_file:
            try:
                cookie = Path(cookie_file).read_bytes()
                self._command(f"AUTHENTICATE {cookie.hex()}")
                self.auth_method = "COOKIE"
                return self.auth_method
            except Exception as exc:
                logger.info("COOKIE auth failed (%s)", exc)

        if "HASHEDPASSWORD" in methods and self.password:
            self._command(f'AUTHENTICATE "{self.password}"')
            self.auth_method = "HASHEDPASSWORD"
            return self.auth_method

        # Last resort: let tor pick. Works on a control port with no auth
        # configured; raises with tor's own message otherwise.
        try:
            self._command("AUTHENTICATE")
            self.auth_method = "NULL"
            return self.auth_method
        except TorError as exc:
            raise TorAuthError(
                f"Could not authenticate to the Tor control port at "
                f"{self.host}:{self.port}. Methods offered: {methods or 'none'}. {exc}"
            ) from exc

    def _auth_safecookie(self, cookie_file: str) -> None:
        cookie = Path(cookie_file).read_bytes()
        client_nonce = secrets.token_bytes(32)
        lines = self._command(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        payload = lines[-1][1] if len(lines) == 1 else " ".join(t for _c, t, _d in lines)
        server_hash = re.search(r"SERVERHASH=([0-9A-Fa-f]+)", payload)
        server_nonce = re.search(r"SERVERNONCE=([0-9A-Fa-f]+)", payload)
        if not server_hash or not server_nonce:
            raise TorAuthError(f"AUTHCHALLENGE reply unparseable: {payload!r}")

        server_nonce_bytes = bytes.fromhex(server_nonce.group(1))
        material = cookie + client_nonce + server_nonce_bytes

        # Verify the server before sending anything derived from the cookie.
        # Skipping this check would authenticate us to an impostor.
        expected = hmac.new(_SAFECOOKIE_SERVER_KEY, material, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, bytes.fromhex(server_hash.group(1))):
            raise TorAuthError("SAFECOOKIE server hash mismatch — not talking to the real tor")

        client_hash = hmac.new(_SAFECOOKIE_CLIENT_KEY, material, hashlib.sha256).digest()
        self._command(f"AUTHENTICATE {client_hash.hex()}")

    # -- commands --------------------------------------------------------

    def getinfo(self, *keys: str) -> dict[str, Any]:
        if not keys:
            return {}
        return self._parse_kv(self._command("GETINFO " + " ".join(keys)))

    def getconf(self, *keys: str) -> dict[str, Any]:
        if not keys:
            return {}
        return self._parse_kv(self._command("GETCONF " + " ".join(keys)))

    def setconf(self, **kwargs: Any) -> None:
        if not kwargs:
            return
        pairs = " ".join(f"{k}={v}" for k, v in kwargs.items())
        self._command(f"SETCONF {pairs}")

    def resetconf(self, *keys: str) -> None:
        if not keys:
            return
        self._command("RESETCONF " + " ".join(keys))

    def signal(self, what: str) -> None:
        self._command(f"SIGNAL {what}")

    def bootstrap_progress(self) -> tuple[int, str]:
        """Return (percent, summary) for the bootstrap phase.

        tor reports this as a NOTICE-shaped line, e.g.
        ``NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"``.
        """
        info = self.getinfo("status/bootstrap-phase")
        raw = str(info.get("status/bootstrap-phase", ""))
        percent = re.search(r"PROGRESS=(\d+)", raw)
        summary = re.search(r'SUMMARY="([^"]*)"', raw)
        return (int(percent.group(1)) if percent else -1,
                summary.group(1) if summary else raw.strip())

    def circuit_established(self) -> bool:
        info = self.getinfo("status/circuit-established")
        return str(info.get("status/circuit-established", "0")) == "1"

    def ip_to_country(self, ip: str) -> str | None:
        """Best-effort exit country via tor's own GeoIP lookup.

        Returns None when the GeoIP database is unavailable or the IP is not
        in it -- this is enrichment, never a reason to fail a call.
        """
        try:
            info = self.getinfo(f"ip-to-country/{ip}")
        except TorError:
            return None
        value = info.get(f"ip-to-country/{ip}")
        if not value or str(value).lower() in {"unknown", "??"}:
            return None
        return str(value).lower()


def _control_connect(port: int, host: str = "127.0.0.1",
                     timeout: float = 10.0, password: str | None = None) -> _TorControl:
    """Connect and authenticate in one step."""
    ctrl = _TorControl(host=host, port=port, timeout=timeout, password=password).connect()
    try:
        ctrl.authenticate()
    except Exception:
        ctrl.close()
        raise
    return ctrl


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

def _probe_control(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> dict[str, Any] | None:
    """Ask a control port to identify itself. None if it is not Tor.

    PROTOCOLINFO needs no authentication, which is exactly why it is the
    right probe: it confirms this is Tor before we spend a cookie on it.
    """
    try:
        ctrl = _TorControl(host=host, port=port, timeout=timeout).connect()
    except Exception:
        return None
    try:
        info = ctrl.protocolinfo()
    except Exception:
        return None
    finally:
        ctrl.close()
    if not info.get("version"):
        return None
    return info


def _is_our_managed_instance() -> dict[str, Any] | None:
    """State of our own tor process, if it is alive."""
    if not TOR_STATE_PATH.exists():
        return None
    try:
        state = json.loads(TOR_STATE_PATH.read_text())
    except Exception:
        return None
    pid = state.get("pid")
    if not isinstance(pid, int) or not _process_is_tor(pid):
        return None
    return state


def _process_is_tor(pid: int) -> bool:
    """Whether pid is a live tor process.

    Guards against PID reuse: a stale pid file pointing at an unrelated
    process must not lead to us SIGTERM-ing it.
    """
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except Exception:
        return False
    return "tor" in os.path.basename(out).lower()


def find_tor_endpoints() -> list[dict[str, Any]]:
    """Every Tor we can see, best-first.

    Discovery is by PROTOCOLINFO, never by "something is listening on the
    port" -- 9150 and 9050 are ordinary ports that anything could hold.
    """
    endpoints: list[dict[str, Any]] = []
    managed = _is_our_managed_instance()

    candidates = [
        {
            "kind": "managed",
            "label": "managed instance",
            "socks_port": (managed or {}).get("socks_port", DEFAULT_SOCKS_PORT),
            "control_port": (managed or {}).get("control_port", DEFAULT_CONTROL_PORT),
            "running": managed is not None,
            "in_use_by": None,
        },
        {
            "kind": "tor_browser",
            "label": "Tor Browser",
            "socks_port": TOR_BROWSER_SOCKS_PORT,
            "control_port": TOR_BROWSER_CONTROL_PORT,
            "running": None,
            "in_use_by": "the Tor Browser application",
        },
        {
            "kind": "system",
            "label": "system tor daemon",
            "socks_port": SYSTEM_TOR_SOCKS_PORT,
            "control_port": SYSTEM_TOR_CONTROL_PORT,
            "running": None,
            "in_use_by": "another tor instance on this machine",
        },
    ]

    for cand in candidates:
        info = _probe_control(cand["control_port"])
        cand["control_reachable"] = info is not None
        if info:
            cand["version"] = info.get("version")
            cand["auth_methods"] = info.get("methods", [])
            cand["cookie_file"] = info.get("cookie_file")
            # A cookie under TorBrowser-Data identifies Tor Browser's own tor
            # without shelling out to a process list.
            if cand["cookie_file"] and "torbrowser" in cand["cookie_file"].lower():
                cand["in_use_by"] = "the Tor Browser application"
        else:
            cand["version"] = None
            cand["auth_methods"] = []
            cand["cookie_file"] = None

        if cand["running"] is None:
            cand["running"] = _port_open(cand["socks_port"])

        cand["usable_for_routing"] = bool(cand["running"] or cand["control_reachable"])
        cand["usable_for_circuits"] = bool(cand["control_reachable"])
        endpoints.append(cand)

    return endpoints


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Whether we could bind this port. Used to fail fast on a conflict."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _resolve_endpoint(instance: str | None = None) -> dict[str, Any]:
    """Pick a Tor endpoint by name, or auto-select the best one.

    ``instance`` accepts "managed", "tor_browser", "system" (aliases "browser"
    and "daemon" included for obviousness). Auto-selection prefers an endpoint
    that can actually control circuits, since routing without circuit control
    is a strictly weaker capability and the caller almost always wants both.
    """
    endpoints = find_tor_endpoints()
    aliases = {
        "managed": "managed",
        "auto": None,
        "tor_browser": "tor_browser",
        "tor-browser": "tor_browser",
        "browser": "tor_browser",
        "system": "system",
        "daemon": "system",
    }

    if instance:
        want = aliases.get(instance.lower(), instance.lower())
        for ep in endpoints:
            if ep["kind"] == want:
                return ep
        raise TorError(
            f"Unknown Tor instance {instance!r}. "
            f"Known kinds: {[e['kind'] for e in endpoints]}"
        )

    for ep in endpoints:
        if ep["kind"] == "managed" and ep["usable_for_routing"]:
            return ep
    for ep in endpoints:
        if ep["usable_for_circuits"] and ep.get("in_use_by") is None:
            return ep
    for ep in endpoints:
        if ep["usable_for_routing"]:
            return ep

    raise TorNotRunning(
        "No Tor endpoint available. Call camoufox_tor_start() to start a "
        "managed instance." + (" " + _tor_install_hint() if not tor_binary() else "")
    )


# ---------------------------------------------------------------------------
# Managed instance lifecycle
# ---------------------------------------------------------------------------

def _build_torrc(socks_port: int, control_port: int,
                 slots: int = DEFAULT_ISOLATION_SLOTS) -> str:
    """Generate the torrc for the managed instance.

    Two things here were arrived at by measurement rather than by reading, and
    both replaced a design that looked right and did nothing.

    **Isolation is one SocksPort per label, not a SOCKS credential.**
    ``IsolateSOCKSAuth`` used to carry this, on the reasoning that tor would
    read a username/password and pick a circuit from it. That cannot work from a
    browser: Playwright refuses to launch Firefox with SOCKS authentication
    ("Browser does not support socks5 proxy authentication") and Firefox has no
    ``network.proxy.socks_username`` pref at all -- checked against the strings
    in the shipped binary, absent. So the credentials could never be sent, and
    the launch failed outright rather than silently un-isolating.

    What does work is tor's own default. From the man page for ``SessionGroup``:
    "By default, streams received on different SocksPorts, TransPorts, etc are
    always isolated from one another." Measured on a scratch instance with two
    listeners, four rounds: the two exits differed in 4/4. So each label gets a
    listener and no credentials are involved anywhere.

    **Hence the listeners are declared here, at startup.** They cannot be added
    to a running tor: ``SETCONF +SocksPort=...`` comes back ``552 Unrecognized
    option``, and repeating the key (``SETCONF SocksPort=A SocksPort=B``) is
    accepted but *replaces* the list -- ``GETCONF`` afterwards reports ``B``
    alone. Both measured on 0.4.9.6. So the pool size is fixed for the life of
    the process, and changing it needs a restart, which drops every live circuit.

    ``KeepAliveIsolateSOCKSAuth`` is deliberately *not* set. It was a real
    option, but tor removed it -- ``--list-torrc-options`` on 0.4.9.6 has no
    entry for it, and passing it makes tor refuse the whole config with
    "Unknown option".
    """
    listeners = [f"SocksPort 127.0.0.1:{socks_port}"]
    for slot in range(max(0, slots)):
        listeners.append(
            f"SocksPort 127.0.0.1:{socks_port + ISOLATION_PORT_STRIDE + slot}"
            f"   # isolation slot {slot}")
    return (
        "# Generated by camoufox-mcp. Edits will be overwritten.\n"
        + "\n".join(listeners)
        + f"""
ControlPort 127.0.0.1:{control_port}
CookieAuthentication 1
CookieAuthFile {TOR_COOKIE_PATH}
DataDirectory {TOR_DATA_DIR}
Log notice file {TOR_LOG_PATH}
"""
    )


def _write_torrc(socks_port: int, control_port: int,
                 slots: int = DEFAULT_ISOLATION_SLOTS) -> str:
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TOR_DATA_DIR, 0o700)
    except OSError:
        pass
    content = _build_torrc(socks_port, control_port, slots)
    TORRC_PATH.write_text(content)
    return content


# ---------------------------------------------------------------------------
# Per-label circuit isolation
# ---------------------------------------------------------------------------

def _load_isolations() -> dict[str, int]:
    """The persisted label -> slot table. A corrupt file means "no labels yet"."""
    try:
        table = json.loads(ISOLATION_STATE_PATH.read_text())
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError, ValueError):
        logger.warning("isolation table at %s is unreadable; starting a new one",
                       ISOLATION_STATE_PATH)
        return {}
    if not isinstance(table, dict):
        return {}
    return {k: v for k, v in table.items() if isinstance(k, str) and isinstance(v, int)}


def _save_isolations(table: dict[str, int]) -> None:
    try:
        TOR_DIR.mkdir(parents=True, exist_ok=True)
        ISOLATION_STATE_PATH.write_text(json.dumps(table, indent=1, sort_keys=True))
    except OSError as exc:
        # Not fatal: the assignment still holds for this process, it just will
        # not survive a restart. Losing it silently would mean a later run
        # reuses a slot for a different label and shares its circuit.
        logger.warning("could not persist the isolation table: %s", exc)


def isolation_slot(label: str, slots: int | None = None) -> int:
    """The pool slot for a label, assigning and persisting one on first use.

    Assignment is persisted rather than derived from a hash of the label, so a
    label keeps its circuit across restarts, and sequential rather than hashed
    so two labels cannot collide onto one slot -- a collision would silently put
    two "isolated" sessions on the same circuit, which is the failure mode this
    whole mechanism exists to prevent and the one that looks like success.
    """
    slots = DEFAULT_ISOLATION_SLOTS if slots is None else slots
    if slots <= 0:
        raise TorError(
            "Circuit isolation is disabled: CAMOUFOX_TOR_ISOLATION_SLOTS is 0, "
            "so no isolation listeners are configured."
        )

    table = _load_isolations()
    slot = table.get(label)
    if slot is not None:
        if slot >= slots:
            raise TorError(
                f"Label {label!r} is assigned slot {slot}, but the pool was "
                f"reduced to {slots}. Restarting the managed instance is the "
                "only way to reapply the pool size."
            )
        return slot

    used = set(table.values())
    for candidate in range(slots):
        if candidate not in used:
            table[label] = candidate
            _save_isolations(table)
            return candidate

    raise TorError(
        f"All {slots} isolation slots are in use "
        f"({', '.join(sorted(table))}). Delete {ISOLATION_STATE_PATH} to "
        "reassign them, or raise CAMOUFOX_TOR_ISOLATION_SLOTS and restart the "
        "managed instance."
    )


def isolation_port(label: str, socks_port: int | None = None,
                   slots: int | None = None) -> int:
    """The SocksPort carrying a label's circuit."""
    base = socks_port if socks_port is not None else DEFAULT_SOCKS_PORT
    return base + ISOLATION_PORT_STRIDE + isolation_slot(label, slots)


def isolation_table() -> dict[str, Any]:
    """The pool and its assignments, for reporting. Never raises."""
    slots = DEFAULT_ISOLATION_SLOTS
    table = _load_isolations()
    return {
        "slots": slots,
        "assigned": dict(sorted(table.items())),
        "free": slots - len([s for s in table.values() if s < slots]),
    }


def is_tor_running() -> bool:
    """Whether our managed tor process is alive. Never raises."""
    return _is_our_managed_instance() is not None


def tor_healthy() -> bool:
    """Whether our managed tor answers on its control port. Never raises."""
    state = _is_our_managed_instance()
    if not state:
        return False
    return _probe_control(int(state.get("control_port", DEFAULT_CONTROL_PORT))) is not None


def check_tor_health() -> dict[str, Any]:
    """Agent-facing health report for the managed instance."""
    state = _is_our_managed_instance()
    if not state:
        return {
            "status": "not_running",
            "error": "Managed Tor instance is not running",
            "hint": "camoufox_tor_start() to start one; camoufox_tor_status() to "
                    "see other Tor endpoints on this machine",
        }
    try:
        ctrl = _control_connect(int(state["control_port"]))
    except Exception as exc:
        return {
            "status": "unreachable",
            "error": f"{type(exc).__name__}: {exc}",
            "pid": state.get("pid"),
            "hint": f"Check {TOR_LOG_PATH}",
        }
    try:
        percent, summary = ctrl.bootstrap_progress()
        return {
            "status": "ok",
            "pid": state.get("pid"),
            "version": ctrl.version,
            "auth_method": ctrl.auth_method,
            "socks_port": state.get("socks_port"),
            "control_port": state.get("control_port"),
            "bootstrap_progress": percent,
            "bootstrap_summary": summary,
            "circuit_established": ctrl.circuit_established(),
        }
    finally:
        ctrl.close()


def start_tor(exit_nodes: str | None = None,
              socks_port: int = DEFAULT_SOCKS_PORT,
              control_port: int = DEFAULT_CONTROL_PORT,
              timeout_s: float = BOOTSTRAP_TIMEOUT_S) -> dict[str, Any]:
    """Start the managed tor instance and wait for it to bootstrap.

    Idempotent in the same way ``start_flaresolverr`` is: an already-running
    healthy instance returns ``already_running`` rather than starting a
    second one.
    """
    state = _is_our_managed_instance()
    if state:
        health = check_tor_health()
        if health.get("status") == "ok":
            return {
                "status": "already_running",
                "pid": state.get("pid"),
                "socks_port": state.get("socks_port"),
                "control_port": state.get("control_port"),
                "bootstrap_progress": health.get("bootstrap_progress"),
                "message": "Managed Tor instance is already running and bootstrapped",
            }

    binary = tor_binary()
    if not binary:
        return {
            "status": "error",
            "error": "The 'tor' executable was not found",
            "hint": _tor_install_hint(),
        }

    # Fail fast on a port conflict rather than spawning a tor that dies during
    # bootstrap and reporting an opaque timeout. The isolation pool is checked
    # too: tor treats a SocksPort it cannot bind as fatal, so one busy slot port
    # would take the whole instance down, and the message would name the pool
    # rather than the base port the operator configured.
    targets = [("socks", socks_port), ("control", control_port)]
    targets += [
        ("isolation slot %d" % slot, socks_port + ISOLATION_PORT_STRIDE + slot)
        for slot in range(max(0, DEFAULT_ISOLATION_SLOTS))
    ]
    for label, port in targets:
        if not _port_available(port):
            return {
                "status": "error",
                "error": f"Port {port} ({label}) is already in use",
                "hint": "Set CAMOUFOX_TOR_SOCKS_PORT / CAMOUFOX_TOR_CONTROL_PORT "
                        "to free ports, lower CAMOUFOX_TOR_ISOLATION_SLOTS, or "
                        "attach to the existing Tor with "
                        "camoufox_tor_new_circuit(instance='tor_browser')",
            }

    torrc = _write_torrc(socks_port, control_port)
    if exit_nodes:
        cleaned = _validate_exit_nodes(exit_nodes)
        if cleaned is None:
            return {
                "status": "error",
                "error": f"Invalid exit_nodes {exit_nodes!r}",
                "hint": "Use two-letter country codes, e.g. 'us' or '{us,ca}'",
            }
        torrc += f"ExitNodes {cleaned}\nStrictNodes 1\n"
        TORRC_PATH.write_text(torrc)

    # Catch config errors before spawning, so a bad torrc surfaces as a
    # message from tor rather than as a bootstrap timeout.
    check = subprocess.run(
        [binary, "--verify-config", "-f", str(TORRC_PATH)],
        capture_output=True, text=True, timeout=20,
    )
    if check.returncode != 0:
        return {
            "status": "error",
            "error": "tor rejected the generated configuration",
            "stderr": (check.stderr or check.stdout or "").strip()[-800:],
            "hint": f"Inspect {TORRC_PATH}",
        }

    logger.info("Starting managed Tor on socks=%d control=%d", socks_port, control_port)
    try:
        log_handle = open(TOR_LOG_PATH, "ab")
    except OSError:
        log_handle = subprocess.DEVNULL  # type: ignore[assignment]

    try:
        proc = subprocess.Popen(
            [binary, "-f", str(TORRC_PATH)],
            stdout=log_handle,
            stderr=log_handle,
            stdin=subprocess.DEVNULL,
            # Detach: tor is a daemon and must outlive this MCP process, since
            # killing it would break a browser session that is still running.
            start_new_session=True,
        )
    except OSError as exc:
        return {"status": "error", "error": f"Failed to spawn tor: {exc}"}

    TOR_DIR.mkdir(parents=True, exist_ok=True)
    TOR_PID_PATH.write_text(str(proc.pid))
    TOR_STATE_PATH.write_text(json.dumps({
        "pid": proc.pid,
        "socks_port": socks_port,
        "control_port": control_port,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    deadline = time.time() + timeout_s
    last_percent, last_summary, last_error = -1, "", ""
    while time.time() < deadline:
        if proc.poll() is not None:
            _clear_state()
            return {
                "status": "error",
                "error": f"tor exited during bootstrap with code {proc.returncode}",
                "hint": f"Check {TOR_LOG_PATH}",
                "log_tail": _log_tail(),
            }
        try:
            ctrl = _control_connect(control_port, timeout=5.0)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(BOOTSTRAP_POLL_S)
            continue
        try:
            percent, summary = ctrl.bootstrap_progress()
            last_percent, last_summary = percent, summary
            if percent >= 100:
                established = ctrl.circuit_established()
                result = {
                    "status": "started",
                    "pid": proc.pid,
                    "socks_port": socks_port,
                    "control_port": control_port,
                    "version": ctrl.version,
                    "auth_method": ctrl.auth_method,
                    "bootstrap_progress": 100,
                    "circuit_established": established,
                    "torrc": str(TORRC_PATH),
                    "message": "Managed Tor instance started and bootstrapped",
                }
                if not established:
                    # Bootstrap "done" without a circuit means we cannot reach
                    # the network yet; saying "started" alone would be a lie.
                    result["status"] = "started_no_circuit"
                    result["hint"] = "Bootstrap finished but no circuit is established yet."
                return result
        finally:
            ctrl.close()
        time.sleep(BOOTSTRAP_POLL_S)

    return {
        "status": "started_unbootstrapped",
        "pid": proc.pid,
        "socks_port": socks_port,
        "control_port": control_port,
        "bootstrap_progress": last_percent,
        "bootstrap_summary": last_summary,
        "error": f"tor did not bootstrap within {int(timeout_s)}s",
        "last_control_error": last_error or None,
        "hint": f"Check {TOR_LOG_PATH} — a network that blocks Tor bridges/directory "
                "authorities will stall here",
        "log_tail": _log_tail(),
    }


def _clear_state() -> None:
    for path in (TOR_PID_PATH, TOR_STATE_PATH):
        try:
            path.unlink()
        except OSError:
            pass


def _log_tail(lines: int = 12) -> str:
    try:
        content = TOR_LOG_PATH.read_text(errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except OSError:
        return ""


def stop_tor() -> dict[str, Any]:
    """Stop the managed tor instance. Idempotent."""
    state = _is_our_managed_instance()
    if not state:
        _clear_state()
        return {
            "status": "not_running",
            "message": "Managed Tor instance was not running",
        }

    pid = int(state["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _clear_state()
        return {"status": "not_running", "message": "tor had already exited"}

    # Give it a moment to shut the control port down cleanly before we report.
    for _ in range(20):
        if not _process_is_tor(pid):
            _clear_state()
            return {"status": "stopped", "pid": pid, "message": "Managed Tor instance stopped"}
        time.sleep(0.25)

    _clear_state()
    return {
        "status": "stopped",
        "pid": pid,
        "message": "SIGTERM sent; tor had not exited within 5s",
    }


def ensure_tor_running(exit_nodes: str | None = None) -> dict[str, Any]:
    """Health-check the managed instance, auto-starting if needed.

    Called before any Tor-routed launch. The caller gates on the status being
    in ("ready", "already_running", "started") -- the same triple the
    FlareSolverr bridge uses, and for the same reason: a partially-started
    instance must not read as success.
    """
    health = check_tor_health()
    if health.get("status") == "ok" and health.get("bootstrap_progress") == 100:
        return {"status": "ready", "message": "Managed Tor instance is running",
                **{k: health.get(k) for k in ("pid", "socks_port", "control_port")}}

    logger.info("Managed Tor not ready (%s), auto-starting", health.get("status"))
    return start_tor(exit_nodes=exit_nodes)


# ---------------------------------------------------------------------------
# Circuit control
# ---------------------------------------------------------------------------

def _validate_exit_nodes(value: str) -> str | None:
    """Normalise an exit-node spec to tor's ``{cc}`` form, or None if invalid.

    Accepts "us", "{us}", "us,ca", "{us,ca}". Rejected rather than passed
    through because tor treats a malformed ExitNodes as an empty set and
    silently gives you no circuits at all.
    """
    raw = value.strip()
    if raw.startswith("{") and raw.endswith("}"):
        raw = raw[1:-1]
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return None
    codes = []
    for part in parts:
        m = _COUNTRY_RE.match(part)
        if not m:
            return None
        codes.append(m.group(1).lower())
    return "{" + ",".join(codes) + "}"


def _with_control(instance: str | None = None) -> tuple[_TorControl, dict[str, Any]]:
    ep = _resolve_endpoint(instance)
    if not ep.get("control_reachable"):
        raise TorNotRunning(
            f"Tor endpoint {ep['kind']!r} has no reachable control port "
            f"({ep.get('control_port')}), so circuit control is unavailable. "
            "Routing still works. Use instance='managed' for full control."
        )
    ctrl = _control_connect(int(ep["control_port"]))
    return ctrl, ep


def set_exit_nodes(countries: str, instance: str | None = None) -> dict[str, Any]:
    """Constrain exits to a set of countries. Takes effect on the next circuit."""
    cleaned = _validate_exit_nodes(countries)
    if cleaned is None:
        return {
            "status": "error",
            "error": f"Invalid exit_nodes {countries!r}",
            "hint": "Two-letter country codes, e.g. 'us' or '{us,ca}'",
        }
    try:
        ctrl, ep = _with_control(instance)
    except (TorError, TorNotRunning) as exc:
        return {"status": "error", "error": str(exc)}
    try:
        ctrl.setconf(ExitNodes=cleaned, StrictNodes="1")
        return {
            "status": "ok",
            "instance": ep["kind"],
            "exit_nodes": cleaned,
            "hint": "Call camoufox_tor_new_circuit() to build a circuit that uses it",
        }
    finally:
        ctrl.close()


def clear_exit_nodes(instance: str | None = None) -> dict[str, Any]:
    """Remove an exit-node restriction."""
    try:
        ctrl, ep = _with_control(instance)
    except (TorError, TorNotRunning) as exc:
        return {"status": "error", "error": str(exc)}
    try:
        ctrl.resetconf("ExitNodes", "StrictNodes")
        return {"status": "ok", "instance": ep["kind"], "exit_nodes": None}
    finally:
        ctrl.close()


def new_circuit(exit_nodes: str | None = None,
                instance: str | None = None,
                verify: bool = True) -> dict[str, Any]:
    """Rotate to a fresh circuit and report the new exit IP.

    Applying an exit policy and rotating are one operation on purpose:
    ``NEWNYM`` is rate-limited by tor, so a caller that sets a policy and then
    has to ask again for a circuit wastes its own budget. The measured
    before/after exit IP is what distinguishes "the signal was accepted" from
    "the exit actually changed".

    **``NEWNYM`` is global.** It marks every circuit dirty, so it rotates the
    base circuit *and* every isolation label's circuit at once -- there is no
    per-label rotation in the control protocol. An isolation label keeps two
    sessions apart from each other; it does not protect one of them from this
    call.
    """
    try:
        ep = _resolve_endpoint(instance)
    except TorError as exc:
        return {"status": "error", "error": str(exc)}

    socks_port = int(ep["socks_port"])

    before = _probe_exit_ip(socks_port, probe_url=DEFAULT_EXIT_PROBE_URL) if verify else None

    try:
        ctrl, ep = _with_control(instance)
    except (TorError, TorNotRunning) as exc:
        return {"status": "error", "error": str(exc)}

    try:
        applied = None
        if exit_nodes:
            cleaned = _validate_exit_nodes(exit_nodes)
            if cleaned is None:
                return {
                    "status": "error",
                    "error": f"Invalid exit_nodes {exit_nodes!r}",
                    "hint": "Two-letter country codes, e.g. 'us' or '{us,ca}'",
                }
            ctrl.setconf(ExitNodes=cleaned, StrictNodes="1")
            applied = cleaned

        ctrl.signal("NEWNYM")
    except TorError as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        ctrl.close()

    result: dict[str, Any] = {
        "status": "rotated",
        "instance": ep["kind"],
        "exit_nodes": applied,
        "previous_exit_ip": (before or {}).get("ip") if before else None,
    }

    if not verify:
        result["hint"] = "verify=False, so the new exit was not measured"
        return result

    # NEWNYM returns immediately; the new circuit takes a moment to build.
    # Probe briefly rather than reporting the old exit as the new one.
    after = None
    for _ in range(10):
        time.sleep(0.6)
        after = _probe_exit_ip(socks_port, probe_url=DEFAULT_EXIT_PROBE_URL)
        if after and after.get("ip") and after.get("ip") != (before or {}).get("ip"):
            break

    result["exit_ip"] = (after or {}).get("ip")
    result["is_tor"] = (after or {}).get("is_tor")
    result["previous_exit_ip"] = (before or {}).get("ip") if before else None

    if after is None:
        result["status"] = "rotated_unverified"
        result["hint"] = "Circuit signal sent, but the exit probe did not answer."
    elif result["exit_ip"] == result["previous_exit_ip"] and result["exit_ip"]:
        # Not an error: tor reuses exits, especially under an ExitNodes
        # restriction that narrows the pool. Worth saying plainly.
        result["note"] = ("Exit IP is unchanged. Tor reuses exits, and an "
                          "ExitNodes restriction narrows the pool further.")
    return result


# ---------------------------------------------------------------------------
# Exit-IP verification
# ---------------------------------------------------------------------------

def _socks5_http_get(socks_host: str, socks_port: int, url: str,
                     username: str | None = None, password: str | None = None,
                     timeout: float = 30.0) -> dict[str, Any]:
    """GET a URL through a SOCKS5 proxy, using only the stdlib.

    Needed because ``urllib`` cannot speak SOCKS and pulling in PySocks for
    one probe is not worth a dependency. Handles the RFC 1928 handshake, the
    RFC 1929 username/password sub-negotiation (which is how Tor circuit
    isolation is selected), and TLS via the stdlib ssl module.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TorError(f"unsupported scheme {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise TorError(f"no host in {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    try:
        # Greeting. When credentials are supplied we offer ONLY user/pass:
        # falling back to no-auth would silently drop the isolation and put
        # this session on whatever circuit the previous one used.
        if username:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")

        reply = _recv_exact(sock, 2)
        if reply[0] != 5:
            raise TorError(f"bad SOCKS version in greeting reply: {reply[0]}")
        method = reply[1]
        if method == 0xFF:
            raise TorError("SOCKS proxy rejected all offered auth methods")
        if method == 0x02:
            if not username:
                raise TorError("SOCKS proxy demands credentials but none were configured")
            u = username.encode()
            p = (password or "").encode()
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            auth_reply = _recv_exact(sock, 2)
            if auth_reply[1] != 0:
                raise TorError(f"SOCKS authentication failed (status {auth_reply[1]})")
        elif method != 0x00:
            raise TorError(f"unsupported SOCKS auth method {method}")

        # CONNECT with a domain-name address so DNS resolution happens at the
        # proxy — resolving locally would leak the name we are asking for.
        host_bytes = host.encode()
        sock.sendall(
            b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes
            + port.to_bytes(2, "big")
        )
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise TorError(f"SOCKS CONNECT failed (reply {head[1]})")
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        else:
            raise TorError(f"unknown SOCKS address type {atyp}")

        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: camoufox-mcp/tor-probe\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())

        chunks = []
        while True:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
        status, headers, body = _parse_http_response(raw)
        return {"status_code": status, "headers": headers, "body": body}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise TorError("SOCKS proxy closed the connection mid-handshake")
        buf += chunk
    return buf


def _parse_http_response(raw: bytes) -> tuple[int | None, dict[str, str], str]:
    """Split a raw HTTP/1.1 response, de-chunking if needed."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        bits = lines[0].split(" ")
        if len(bits) > 1 and bits[1].isdigit():
            status = int(bits[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk(body)

    return status, headers, body.decode("utf-8", "replace")


def _dechunk(body: bytes) -> bytes:
    out = b""
    while True:
        line, _, rest = body.partition(b"\r\n")
        if not line:
            break
        size_token = line.split(b";")[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out


def _probe_exit_ip(socks_port: int, username: str | None = None,
                   password: str | None = None,
                   probe_url: str = DEFAULT_EXIT_PROBE_URL) -> dict[str, Any] | None:
    """Ask an external service what IP our traffic exits from.

    Returns None when the probe is unreachable. A failed probe is reported as
    "unverified", never as an error, because a Tor session that works fine
    must not be reported as broken just because check.torproject.org is down.
    """
    try:
        response = _socks5_http_get(
            "127.0.0.1", socks_port, probe_url, username, password,
        )
    except Exception as exc:
        logger.info("exit-IP probe failed: %s", exc)
        return None

    text = response.get("body", "")
    ip = None
    is_tor = None
    try:
        parsed = json.loads(text)
        ip = parsed.get("IP") or parsed.get("ip") or parsed.get("origin")
        is_tor = parsed.get("IsTor")
    except Exception:
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m:
            ip = m.group(1)

    return {
        "ip": ip,
        "is_tor": is_tor,
        "status_code": response.get("status_code"),
        "probe_url": probe_url,
        "raw": text[:500],
    }


# ---------------------------------------------------------------------------
# Agent-facing entry points
# ---------------------------------------------------------------------------

def tor_status() -> dict[str, Any]:
    """Report every Tor endpoint on this machine. Local only, no network."""
    endpoints = find_tor_endpoints()
    binary = tor_binary()
    managed = _is_our_managed_instance()

    warnings = []
    for ep in endpoints:
        if ep.get("in_use_by") and ep["kind"] != "managed" and ep["usable_for_circuits"]:
            warnings.append(
                f"{ep['label']} (control port {ep['control_port']}) belongs to "
                f"{ep['in_use_by']}. Rotating its circuit would affect that "
                f"application, not just this server."
            )

    return {
        "status": "ok",
        "tor_binary": binary,
        "managed_instance": {
            "running": managed is not None,
            "pid": (managed or {}).get("pid"),
            "socks_port": (managed or {}).get("socks_port", DEFAULT_SOCKS_PORT),
            "control_port": (managed or {}).get("control_port", DEFAULT_CONTROL_PORT),
            "data_dir": str(TOR_DIR),
        },
        "isolation": isolation_table(),
        "endpoints": endpoints,
        "warnings": warnings,
        "hint": (
            "camoufox_tor_start() to start a managed instance; "
            "camoufox_launch(tor=True) to route the browser through it."
        ),
    }


def tor_exit_info(instance: str | None = None,
                  isolation: str | None = None,
                  probe_url: str = DEFAULT_EXIT_PROBE_URL) -> dict[str, Any]:
    """What IP a target sees when we egress through Tor, and whether it is Tor.

    This makes a network round trip (~2-5s through Tor) which is why it is a
    separate tool from camouflage_tor_status().

    With an ``isolation`` label, the probe goes out through that label's own
    SocksPort, so the reported exit is the one that label's browser session
    would use -- not the base circuit's.
    """
    t0 = time.time()
    try:
        ep = _resolve_endpoint(instance)
        socks_port = int(ep["socks_port"])
        if isolation:
            socks_port = isolation_port(isolation, socks_port)
    except TorError as exc:
        return {"status": "error", "error": str(exc),
                "elapsed_ms": int((time.time() - t0) * 1000)}

    probe = _probe_exit_ip(socks_port, probe_url=probe_url)
    elapsed = int((time.time() - t0) * 1000)

    if probe is None:
        return {
            "status": "unverified",
            "instance": ep["kind"],
            "socks_port": socks_port,
            "isolation": isolation,
            "error": f"Exit probe {probe_url} did not answer",
            "hint": "The Tor instance may still be bootstrapping, or the probe "
                    "host may be unreachable. Routing is unaffected.",
            "elapsed_ms": elapsed,
        }

    country = None
    if probe.get("ip") and ep.get("control_reachable"):
        try:
            ctrl = _control_connect(int(ep["control_port"]))
            try:
                country = ctrl.ip_to_country(probe["ip"])
            finally:
                ctrl.close()
        except Exception:
            country = None

    return {
        "status": "ok",
        "instance": ep["kind"],
        "socks_port": socks_port,
        "isolation": isolation,
        "exit_ip": probe.get("ip"),
        "is_tor": probe.get("is_tor"),
        "exit_country": country,
        "probe_url": probe_url,
        "elapsed_ms": elapsed,
        "note": (
            "A different exit IP than another session's proves the circuits are "
            "isolated; the same IP does not prove they are not — Tor reuses exits."
        ),
    }


def socks_proxy_url(instance: str | None = None,
                    isolation: str | None = None) -> tuple[str, str | None, str | None]:
    """Return (proxy_url, username, password) for routing a browser through Tor.

    The username and password are always ``None``, and that is the finding
    rather than an omission. Circuit isolation used to be carried by a SOCKS
    credential that tor's ``IsolateSOCKSAuth`` would hash; a browser cannot send
    one. Playwright refuses the launch outright -- "Browser does not support
    socks5 proxy authentication" -- and Firefox has no ``network.proxy.socks_username``
    pref to fall back on (checked against the strings in the shipped binary:
    absent). Isolation is now the SocksPort itself, which needs no credential.

    The tuple shape is kept because the caller passes the parts to Playwright's
    documented ``username``/``password`` proxy fields, and because a credential
    that never arrives is the failure this signature was invented to avoid.
    """
    ep = _resolve_endpoint(instance)
    socks_port = int(ep["socks_port"])
    if isolation:
        socks_port = isolation_port(isolation, socks_port)
    return f"socks5://127.0.0.1:{socks_port}", None, None
