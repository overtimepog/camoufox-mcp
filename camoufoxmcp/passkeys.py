"""A software passkey (WebAuthn) authenticator.

Why software: Firefox exposes no virtual authenticator that Playwright can
drive, and a real platform authenticator needs a human touching a sensor. What a
password manager's browser extension does -- and what this does -- is replace
``navigator.credentials.create/get`` for ``publicKey`` requests with an
implementation that holds the keys itself.

The split of responsibilities:
  * The page-side shim (``MAIN_SHIM_JS`` + ``BRIDGE_JS``, see "Page side")
    only reshapes the WebAuthn API: it converts ArrayBuffers to base64url,
    forwards the request to a Playwright binding, and wraps the reply in
    PublicKeyCredential-shaped objects. It holds no secrets.
  * Everything that matters is here, in Python: key generation, the
    authenticator data, CBOR, signing, and -- importantly -- *whether to answer
    at all*. The origin is taken from the browser-reported frame URL, never from
    anything the page claims.

Security properties:
  * Private keys (PKCS#8) live only in the OS keychain, one JSON blob per
    account. If no secure keychain exists, creating a passkey is refused.
  * Credentials are only created or used for origins that are the account's site
    (or a host the user trusted for that account). Any other origin gets
    ``NotAllowedError``, as if the user had cancelled.
  * ``rpId`` must be the origin's host or a parent domain of it (the WebAuthn
    rule), so a page cannot ask for a credential scoped to a domain it is not on.
  * Attestation is ``none``; the authenticator reports user-verified, because
    the agent enabling it for an account is the consent step. It does NOT claim
    to be a hardware key, so a relying party that *requires* hardware
    attestation (some enterprise policies) will reject it -- by design, not a
    bug to work around.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import ipaddress
import json
import os
import struct
import time
from typing import Any
from urllib.parse import urlparse

from . import credentials as cred

# Most recent decisions (granted AND refused), newest last. Never holds key
# material or challenges -- it exists so "why did the passkey not work?" has an
# answer other than guessing.
EVENTS: collections.deque[dict[str, Any]] = collections.deque(maxlen=25)


def _event(kind: str, outcome: str, origin: str = "", detail: str = "") -> None:
    EVENTS.append({"t": round(time.time()), "kind": kind, "outcome": outcome,
                   "origin": origin, "detail": detail})


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cbor(obj: Any) -> bytes:
    """Minimal CBOR encoder: ints, bytes, text, lists, dicts (insertion order).

    Enough for COSE keys and attestation objects; callers pass dicts already in
    CTAP2 canonical key order.
    """
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        if n < 256:
            return bytes([major << 5 | 24, n])
        if n < 65536:
            return bytes([major << 5 | 25]) + struct.pack(">H", n)
        if n < 2 ** 32:
            return bytes([major << 5 | 26]) + struct.pack(">I", n)
        return bytes([major << 5 | 27]) + struct.pack(">Q", n)

    if isinstance(obj, bool):
        raise TypeError("bool not supported")
    if isinstance(obj, int):
        return head(0, obj) if obj >= 0 else head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode()
        return head(3, len(raw)) + raw
    if isinstance(obj, list):
        return head(4, len(obj)) + b"".join(cbor(x) for x in obj)
    if isinstance(obj, dict):
        return head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    raise TypeError(f"cannot CBOR-encode {type(obj).__name__}")


# ---------------------------------------------------------------------------
# Origin / rpId rules
# ---------------------------------------------------------------------------

class PasskeyRefused(Exception):
    """Carries a DOMException name and a message for the page."""

    def __init__(self, name: str, message: str) -> None:
        super().__init__(message)
        self.name = name
        self.message = message


def _origin_of(url: str) -> tuple[str, str]:
    """(origin, host) for an http(s) URL, or refuse."""
    u = urlparse(url or "")
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not host:
        raise PasskeyRefused("NotAllowedError", "Not a web origin.")
    # WebAuthn needs a secure context. localhost counts; plain http elsewhere
    # does not, and a passkey over it could be read by anyone on the path.
    if u.scheme == "http" and host != "localhost" and not host.endswith(".localhost"):
        raise PasskeyRefused("SecurityError", "WebAuthn requires a secure context (https).")
    port = f":{u.port}" if u.port and u.port not in (80, 443) else ""
    return f"{u.scheme}://{host}{port}", host


def valid_rp_id(rp_id: str, host: str) -> bool:
    """rpId must equal the origin's host or be a parent domain of it, and not an IP."""
    rp_id = (rp_id or "").lower().rstrip(".")
    if not rp_id:
        return False
    try:
        ipaddress.ip_address(rp_id)
        return False
    except ValueError:
        pass
    if "." not in rp_id and rp_id != "localhost":
        return False  # a bare TLD-like label is never a legitimate rpId
    return host == rp_id or host.endswith("." + rp_id)


# ---------------------------------------------------------------------------
# Storage (keychain)
# ---------------------------------------------------------------------------

def _key(name: str) -> str:
    return f"{name}#passkeys"


def load_all(name: str) -> list[dict[str, Any]]:
    kr = cred._backend()
    try:
        raw = kr.get_password(cred.SERVICE, _key(name))
    except Exception as exc:  # noqa: BLE001
        raise cred.CredentialError(f"Keychain read failed: {exc}") from exc
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except ValueError as exc:
        raise cred.CredentialError(f"Stored passkeys for {name!r} are corrupt.") from exc


def save_all(name: str, items: list[dict[str, Any]]) -> None:
    kr = cred._backend()
    try:
        if items:
            kr.set_password(cred.SERVICE, _key(name), json.dumps(items))
        else:
            kr.delete_password(cred.SERVICE, _key(name))
    except Exception as exc:  # noqa: BLE001
        raise cred.CredentialError(f"Keychain refused the passkey store: {exc}") from exc


def delete_all(name: str) -> bool:
    try:
        cred._backend().delete_password(cred.SERVICE, _key(name))
        return True
    except Exception:  # noqa: BLE001
        return False


def public_info(item: dict[str, Any]) -> dict[str, Any]:
    """Safe-to-show view: never the private key."""
    return {"credential_id": item["id"], "rp_id": item["rp_id"],
            "user_name": item.get("user_name"), "created": item.get("created")}


# ---------------------------------------------------------------------------
# The authenticator
# ---------------------------------------------------------------------------

_FLAG_UP, _FLAG_UV, _FLAG_AT = 0x01, 0x04, 0x40


def _client_data(kind: str, challenge: str, origin: str, cross_origin: bool) -> bytes:
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin,
                       "crossOrigin": cross_origin}, separators=(",", ":")).encode()


def _cose_es256(pub) -> bytes:
    nums = pub.public_numbers()
    # CTAP2 canonical order: 1, 3, -1, -2, -3
    return cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})


def _check_request(url: str, allowed_hosts: list[str], rp_id: str | None) -> tuple[str, str, str]:
    origin, host = _origin_of(url)
    if not any(cred.host_matches(url, h) for h in allowed_hosts if h):
        raise PasskeyRefused(
            "NotAllowedError",
            f"{host} is not this account's site, so the passkey authenticator declined.")
    rp = rp_id or host
    if not valid_rp_id(rp, host):
        raise PasskeyRefused("SecurityError", f"rpId {rp!r} is not valid for {host}.")
    return origin, host, rp.lower().rstrip(".")


def create(name: str, url: str, allowed_hosts: list[str], options: dict[str, Any],
           cross_origin: bool = False) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    origin, host, rp_id = _check_request(url, allowed_hosts, (options.get("rp") or {}).get("id"))
    algs = [p.get("alg") for p in options.get("pubKeyCredParams") or []]
    if algs and -7 not in algs:
        raise PasskeyRefused("NotSupportedError", "Only ES256 (alg -7) is supported.")
    user = options.get("user") or {}
    if not options.get("challenge") or not user.get("id"):
        raise PasskeyRefused("TypeError", "Missing challenge or user.id.")

    existing = load_all(name)
    excluded = {e.get("id") for e in options.get("excludeCredentials") or []}
    if any(c["rp_id"] == rp_id and c["id"] in excluded for c in existing):
        raise PasskeyRefused("InvalidStateError", "A matching passkey already exists.")

    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = os.urandom(32)
    auth_data = (hashlib.sha256(rp_id.encode()).digest()
                 + bytes([_FLAG_UP | _FLAG_UV | _FLAG_AT]) + struct.pack(">I", 0)
                 + bytes(16)                       # AAGUID: all zeros = "no model claimed"
                 + struct.pack(">H", len(cred_id)) + cred_id
                 + _cose_es256(key.public_key()))
    attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client = _client_data("webauthn.create", options["challenge"], origin, cross_origin)
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())

    existing.append({
        "id": b64u(cred_id), "rp_id": rp_id, "user_handle": user["id"],
        "user_name": user.get("name"), "pkcs8": b64u(pkcs8), "created": round(time.time()),
    })
    save_all(name, existing)  # persist BEFORE answering: a lost key = a locked-out account
    _event("create", "granted", origin)
    return {"id": b64u(cred_id), "clientDataJSON": b64u(client),
            "attestationObject": b64u(attestation), "authData": b64u(auth_data),
            "publicKey": b64u(spki), "publicKeyAlg": -7}


def get(name: str, url: str, allowed_hosts: list[str], options: dict[str, Any],
        cross_origin: bool = False) -> dict[str, Any]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    origin, host, rp_id = _check_request(url, allowed_hosts, options.get("rpId"))
    if not options.get("challenge"):
        raise PasskeyRefused("TypeError", "Missing challenge.")
    allowed_ids = {c.get("id") for c in options.get("allowCredentials") or []}
    candidates = [c for c in load_all(name)
                  if c["rp_id"] == rp_id and (not allowed_ids or c["id"] in allowed_ids)]
    if not candidates:
        raise PasskeyRefused("NotAllowedError", "No matching passkey for this site.")
    chosen = max(candidates, key=lambda c: c.get("created", 0))  # newest discoverable credential

    key = serialization.load_der_private_key(unb64u(chosen["pkcs8"]), password=None)
    auth_data = (hashlib.sha256(rp_id.encode()).digest()
                 + bytes([_FLAG_UP | _FLAG_UV]) + struct.pack(">I", 0))
    client = _client_data("webauthn.get", options["challenge"], origin, cross_origin)
    sig = key.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    _event("get", "granted", origin)
    return {"id": chosen["id"], "clientDataJSON": b64u(client), "authenticatorData": b64u(auth_data),
            "signature": b64u(sig), "userHandle": chosen.get("user_handle")}


def handle(name: str | None, url: str, allowed_hosts: list[str], payload: dict[str, Any],
           cross_origin: bool) -> dict[str, Any]:
    """Entry point for the page binding. Never raises; returns a JSON-able reply.

    ``{"fallback": True}`` tells the shim to use the browser's native API (no
    account is enabled), anything with ``error`` becomes a DOMException.
    """
    kind = payload.get("kind")
    if kind == "status":
        return {"enabled": bool(name)}
    if not name:
        return {"fallback": True}
    try:
        if kind == "create":
            return {"ok": create(name, url, allowed_hosts, payload["options"], cross_origin)}
        if kind == "get":
            return {"ok": get(name, url, allowed_hosts, payload["options"], cross_origin)}
        return {"error": "NotSupportedError", "message": f"Unknown request {kind!r}."}
    except PasskeyRefused as exc:
        _event(str(kind), "refused", url, exc.message)
        return {"error": exc.name, "message": exc.message}
    except cred.CredentialError as exc:
        _event(str(kind), "refused", url, str(exc))
        return {"error": "NotAllowedError", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - never let a bug hang the page's promise
        _event(str(kind), "error", url, f"{type(exc).__name__}")
        return {"error": "UnknownError", "message": "Authenticator error."}


# ---------------------------------------------------------------------------
# Page side
# ---------------------------------------------------------------------------
#
# Camoufox runs Playwright init scripts and exposed bindings in an ISOLATED
# world: the DOM is shared but JavaScript globals are not, so a page script
# cannot see `window.__cmcpPasskey`, nor a `navigator.credentials` patched from
# there. Verified on Camoufox 152, along with these dead ends:
#   * a <script> element injected from the isolated world never executes;
#   * `wrappedJSObject.eval` works but a strict page CSP (no 'unsafe-eval' --
#     GitHub-style) blocks it;
#   * functions assigned from the sandbox are opaque to the page ("Permission
#     denied"), and exportFunction / cloneInto do not exist there.
# What works, including under a strict CSP: launch with Camoufox's
# `main_world_eval=True`, after which an init script prefixed "mw:" runs in the
# page's own world at document start, before any page script. So:
#
#   MAIN_SHIM_JS  ("mw:" init script) replaces the WebAuthn API in the page
#                 world. It holds no secrets and cannot reach the binding; it
#                 talks to the bridge with window.postMessage.
#   BRIDGE_JS     (ordinary init script, isolated world) owns the binding and
#                 relays those messages to Python.
#
# Messages are accepted only from the window's own origin. (`ev.source ===
# window` cannot be used: across the two worlds the wrappers differ.) Origin and
# policy are decided in Python from the browser-reported frame URL, so a page
# forging bridge messages gains nothing it could not already do by calling
# navigator.credentials itself, and replies go only to the requesting window.

MAIN_SHIM_JS = r"""
(() => {
  if (window.__cmcpPasskeyShim || !navigator.credentials) return;
  Object.defineProperty(window, '__cmcpPasskeyShim', {value: true});
  const u8 = v => v instanceof ArrayBuffer ? new Uint8Array(v)
    : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const enc = v => { let s = ''; u8(v).forEach(b => s += String.fromCharCode(b));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const dec = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
    const r = atob(s), a = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) a[i] = r.charCodeAt(i); return a.buffer; };
  const ids = l => (l || []).map(c => ({id: enc(c.id), type: c.type}));

  const pending = new Map();
  let seq = 0;
  window.addEventListener('message', ev => {
    const d = ev.origin === window.location.origin && ev.data;
    if (d && d.__cmcpR && pending.has(d.__cmcpR)) {
      const done = pending.get(d.__cmcpR); pending.delete(d.__cmcpR); done(JSON.parse(d.body));
    }
  });
  const call = payload => new Promise(res => {
    const id = (++seq) + '.' + Math.random().toString(36).slice(2);
    pending.set(id, res);
    window.postMessage({__cmcp: id, body: JSON.stringify(payload)}, '*');
  });
  const fail = r => { throw new DOMException(r.message || r.error, r.error); };
  const credProto = (window.PublicKeyCredential || {}).prototype || Object.prototype;
  const own = (o, props) => { for (const k in props)
    Object.defineProperty(o, k, {value: props[k], enumerable: true, configurable: true});
    return o; };

  const nCreate = navigator.credentials.create.bind(navigator.credentials);
  const nGet = navigator.credentials.get.bind(navigator.credentials);

  navigator.credentials.create = async function (opts) {
    const pk = opts && opts.publicKey;
    if (!pk) return nCreate(opts);
    const r = await call({kind: 'create', options: {
      rp: pk.rp, user: {id: enc(pk.user.id), name: pk.user.name, displayName: pk.user.displayName},
      challenge: enc(pk.challenge), pubKeyCredParams: pk.pubKeyCredParams,
      excludeCredentials: ids(pk.excludeCredentials)}});
    if (r.fallback) return nCreate(opts);
    if (r.error) fail(r);
    const d = r.ok;
    const response = own(Object.create(
      (window.AuthenticatorAttestationResponse || {}).prototype || Object.prototype), {
      clientDataJSON: dec(d.clientDataJSON), attestationObject: dec(d.attestationObject),
      getTransports: () => ['internal'], getAuthenticatorData: () => dec(d.authData),
      getPublicKey: () => dec(d.publicKey), getPublicKeyAlgorithm: () => d.publicKeyAlg});
    return own(Object.create(credProto), {
      id: d.id, rawId: dec(d.id), type: 'public-key', authenticatorAttachment: 'platform',
      response, getClientExtensionResults: () => ({}),
      toJSON: () => ({id: d.id, rawId: d.id, type: 'public-key', authenticatorAttachment: 'platform',
        clientExtensionResults: {}, response: {clientDataJSON: d.clientDataJSON,
        attestationObject: d.attestationObject, authenticatorData: d.authData,
        transports: ['internal'], publicKeyAlgorithm: d.publicKeyAlg, publicKey: d.publicKey}})});
  };

  navigator.credentials.get = async function (opts) {
    const pk = opts && opts.publicKey;
    if (!pk) return nGet(opts);
    const r = await call({kind: 'get', options: {
      rpId: pk.rpId, challenge: enc(pk.challenge), allowCredentials: ids(pk.allowCredentials)}});
    if (r.fallback) return nGet(opts);
    if (r.error) fail(r);
    const d = r.ok;
    const response = own(Object.create(
      (window.AuthenticatorAssertionResponse || {}).prototype || Object.prototype), {
      clientDataJSON: dec(d.clientDataJSON), authenticatorData: dec(d.authenticatorData),
      signature: dec(d.signature), userHandle: d.userHandle ? dec(d.userHandle) : null});
    return own(Object.create(credProto), {
      id: d.id, rawId: dec(d.id), type: 'public-key', authenticatorAttachment: 'platform',
      response, getClientExtensionResults: () => ({}),
      toJSON: () => ({id: d.id, rawId: d.id, type: 'public-key', authenticatorAttachment: 'platform',
        clientExtensionResults: {}, response: {clientDataJSON: d.clientDataJSON,
        authenticatorData: d.authenticatorData, signature: d.signature,
        userHandle: d.userHandle || null}})});
  };

  const PKC = window.PublicKeyCredential;
  if (PKC) {
    const nUv = PKC.isUserVerifyingPlatformAuthenticatorAvailable
      && PKC.isUserVerifyingPlatformAuthenticatorAvailable.bind(PKC);
    const nCond = PKC.isConditionalMediationAvailable && PKC.isConditionalMediationAvailable.bind(PKC);
    PKC.isUserVerifyingPlatformAuthenticatorAvailable = async () =>
      (await call({kind: 'status'})).enabled ? true : (nUv ? nUv() : false);
    PKC.isConditionalMediationAvailable = async () =>
      (await call({kind: 'status'})).enabled ? true : (nCond ? nCond() : false);
  }
})();
"""

BRIDGE_JS = r"""
(() => {
  if (window.__cmcpBridge) return;
  window.__cmcpBridge = true;
  window.addEventListener('message', async ev => {
    const d = ev.origin === window.location.origin && ev.data;
    if (!d || !d.__cmcp || typeof d.body !== 'string') return;
    let reply;
    try { reply = await window.__cmcpPasskey(JSON.parse(d.body)); }
    catch (e) { reply = {error: 'NotAllowedError', message: 'Authenticator unavailable.'}; }
    window.postMessage({__cmcpR: d.__cmcp, body: JSON.stringify(reply)}, '*');
  });
})();
"""

# Camoufox's prefix for "run in the page's own world".
MAIN_INIT_JS = "mw:" + MAIN_SHIM_JS
