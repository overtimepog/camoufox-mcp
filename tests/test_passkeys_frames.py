"""Offline tests: passkey authenticator protocol + cross-origin frame handling.

The passkey tests include an independent relying-party verifier -- it parses the
attestation object and checks assertion signatures the way a real server would,
rather than trusting our own encoder to agree with itself.
"""

import asyncio
import hashlib
import json
import struct

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from camoufoxmcp import accounts, credentials as cred, frames, passkeys as pk
from camoufoxmcp import server as srv


class MemKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        self.d = {}

    def get_password(self, s, u):
        return self.d.get((s, u))

    def set_password(self, s, u, p):
        self.d[(s, u)] = p

    def delete_password(self, s, u):
        if (s, u) not in self.d:
            raise PasswordDeleteError("nope")
        del self.d[(s, u)]


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv(accounts.ENV_DIR, str(tmp_path / "vault"))
    kr = MemKeyring()
    monkeypatch.setattr(keyring, "get_keyring", lambda: kr)
    pk.EVENTS.clear()
    return kr


# ---------------------------------------------------------------- RP verifier

def cbor_decode(b, i=0):
    ib = b[i]; major, info = ib >> 5, ib & 31; i += 1
    if info < 24: n = info
    elif info == 24: n = b[i]; i += 1
    elif info == 25: n = struct.unpack(">H", b[i:i + 2])[0]; i += 2
    elif info == 26: n = struct.unpack(">I", b[i:i + 4])[0]; i += 4
    else: raise ValueError
    if major == 0: return n, i
    if major == 1: return -1 - n, i
    if major == 2: return b[i:i + n], i + n
    if major == 3: return b[i:i + n].decode(), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = cbor_decode(b, i); out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = cbor_decode(b, i); v, i = cbor_decode(b, i); out[k] = v
        return out, i
    raise ValueError


def verify_registration(reg, rp_id, origin, challenge):
    client = json.loads(pk.unb64u(reg["clientDataJSON"]))
    assert client == {"type": "webauthn.create", "challenge": challenge,
                      "origin": origin, "crossOrigin": False}
    att, _ = cbor_decode(pk.unb64u(reg["attestationObject"]))
    assert att["fmt"] == "none" and att["attStmt"] == {}
    ad = att["authData"]
    assert ad[:32] == hashlib.sha256(rp_id.encode()).digest()
    flags = ad[32]
    assert flags & 0x01 and flags & 0x04 and flags & 0x40       # UP, UV, AT
    cid_len = struct.unpack(">H", ad[53:55])[0]
    cid = ad[55:55 + cid_len]
    assert pk.b64u(cid) == reg["id"]
    cose, end = cbor_decode(ad, 55 + cid_len)
    assert end == len(ad)                                        # nothing trailing
    assert cose[1] == 2 and cose[3] == -7 and cose[-1] == 1
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()
    ).public_key()


def verify_assertion(pub, asr, rp_id, origin, challenge):
    cd = pk.unb64u(asr["clientDataJSON"])
    c = json.loads(cd)
    assert c["type"] == "webauthn.get" and c["challenge"] == challenge and c["origin"] == origin
    ad = pk.unb64u(asr["authenticatorData"])
    assert ad[:32] == hashlib.sha256(rp_id.encode()).digest() and ad[32] & 0x05 == 0x05
    pub.verify(pk.unb64u(asr["signature"]), ad + hashlib.sha256(cd).digest(),
               ec.ECDSA(hashes.SHA256()))


URL = "https://login.example.com/passkeys"
ORIGIN = "https://login.example.com"
CREATE = {"rp": {"id": "example.com", "name": "Ex"},
          "user": {"id": pk.b64u(b"user-1"), "name": "al", "displayName": "Al"},
          "challenge": pk.b64u(b"c" * 32), "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}


class TestCbor:
    @pytest.mark.parametrize("v", [0, 23, 24, 255, 256, 65535, 65536, -1, -24, -25, -257,
                                   b"", b"abc", "héllo", [1, [2]], {1: 2, "a": b"x", -3: -4}])
    def test_roundtrip_with_independent_decoder(self, v):
        assert cbor_decode(pk.cbor(v))[0] == v


class TestRpId:
    @pytest.mark.parametrize("rp,host,ok", [
        ("example.com", "example.com", True), ("example.com", "login.example.com", True),
        ("evilexample.com", "example.com", False), ("example.com", "example.com.evil.io", False),
        ("com", "example.com", False), ("127.0.0.1", "127.0.0.1", False),
        ("localhost", "localhost", True), ("", "example.com", False)])
    def test_cases(self, rp, host, ok):
        assert pk.valid_rp_id(rp, host) is ok


class TestAuthenticator:
    def test_register_then_sign_in_verifies_like_a_real_rp(self):
        reg = pk.create("al", URL, ["example.com"], CREATE)
        pub = verify_registration(reg, "example.com", ORIGIN, CREATE["challenge"])
        ch = pk.b64u(b"n" * 32)
        asr = pk.get("al", URL, ["example.com"], {"rpId": "example.com", "challenge": ch})
        assert asr["id"] == reg["id"] and asr["userHandle"] == CREATE["user"]["id"]
        verify_assertion(pub, asr, "example.com", ORIGIN, ch)

    def test_private_key_only_in_keychain_and_not_in_replies(self, env):
        reg = pk.create("al", URL, ["example.com"], CREATE)
        stored = json.loads(env.d[(cred.SERVICE, "al#passkeys")])[0]
        assert stored["pkcs8"] and stored["pkcs8"] not in json.dumps(reg)
        assert "pkcs8" not in json.dumps(pk.public_info(stored))

    def test_wrong_origin_refused_with_not_allowed(self):
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.create("al", "https://evilexample.com/", ["example.com"], CREATE)
        assert e.value.name == "NotAllowedError"
        assert pk.load_all("al") == []

    def test_rpid_for_a_domain_the_page_is_not_on_is_refused(self):
        bad = dict(CREATE, rp={"id": "other.com", "name": "x"})
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.create("al", "https://example.com/", ["example.com", "other.com"], bad)
        assert e.value.name == "SecurityError"

    def test_insecure_http_refused_but_localhost_ok(self):
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.create("al", "http://example.com/", ["example.com"], CREATE)
        assert e.value.name == "SecurityError"
        opts = dict(CREATE, rp={"id": "localhost", "name": "x"})
        pk.create("al", "http://localhost:8000/", ["localhost"], opts)

    def test_es256_required_exclude_honoured_and_get_filters(self):
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.create("al", URL, ["example.com"], dict(CREATE, pubKeyCredParams=[{"alg": -257}]))
        assert e.value.name == "NotSupportedError"
        reg = pk.create("al", URL, ["example.com"], CREATE)
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.create("al", URL, ["example.com"], dict(CREATE, excludeCredentials=[{"id": reg["id"]}]))
        assert e.value.name == "InvalidStateError"
        with pytest.raises(pk.PasskeyRefused):
            pk.get("al", URL, ["example.com"], {"rpId": "example.com", "challenge": "x",
                                                "allowCredentials": [{"id": "nope"}]})

    def test_get_with_no_credentials_is_not_allowed(self):
        with pytest.raises(pk.PasskeyRefused) as e:
            pk.get("al", URL, ["example.com"], {"rpId": "example.com", "challenge": "x"})
        assert e.value.name == "NotAllowedError"

    def test_newest_discoverable_credential_wins(self, monkeypatch):
        a = pk.create("al", URL, ["example.com"], CREATE)
        items = pk.load_all("al"); items[0]["created"] -= 100; pk.save_all("al", items)
        b = pk.create("al", URL, ["example.com"], dict(CREATE, user=dict(CREATE["user"], id=pk.b64u(b"u2"))))
        got = pk.get("al", URL, ["example.com"], {"rpId": "example.com", "challenge": "x"})
        assert got["id"] == b["id"] != a["id"]

    def test_handle_contract(self):
        assert pk.handle(None, URL, [], {"kind": "create"}, False) == {"fallback": True}
        assert pk.handle(None, URL, [], {"kind": "status"}, False) == {"enabled": False}
        assert pk.handle("al", URL, ["example.com"], {"kind": "status"}, False) == {"enabled": True}
        r = pk.handle("al", "https://evil.com/", ["example.com"], {"kind": "create", "options": CREATE}, False)
        assert r["error"] == "NotAllowedError"
        assert pk.EVENTS[-1]["outcome"] == "refused"
        assert "pkcs8" not in json.dumps(list(pk.EVENTS))
        ok = pk.handle("al", URL, ["example.com"], {"kind": "create", "options": CREATE}, True)
        cd = json.loads(pk.unb64u(ok["ok"]["clientDataJSON"]))
        assert cd["crossOrigin"] is True

    def test_refuses_without_secure_keychain(self, monkeypatch):
        from keyring.backends import fail
        monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
        r = pk.handle("al", URL, ["example.com"], {"kind": "create", "options": CREATE}, False)
        assert r["error"] == "NotAllowedError"


# ------------------------------------------------------------------- frames

class Frame:
    def __init__(self, url, result=None, visible=True):
        self.url, self.result, self._v = url, result, visible
        self.filled, self.pressed = {}, []

    def frame_element(self):
        outer = self
        class El:
            def is_visible(self_): return outer._v
        return El()

    def evaluate(self, js):
        return self.result

    def fill(self, s, v): self.filled[s] = v

    def press(self, s, k): self.pressed.append((s, k))


class Page:
    def __init__(self, main, *subs):
        self.main_frame = main
        self.frames = [main, *subs]
        self.url = main.url


BOTH, USER, NONE = ({"user": True, "password": True}, {"user": True, "password": False},
                    {"user": False, "password": False})


class TestFrames:
    def test_same_site_subdomain_frame_is_searched_third_party_is_refused(self):
        main = Frame("https://example.com/", NONE)
        own = Frame("https://login.example.com/f", BOTH)
        evil = Frame("https://evil.io/f", BOTH)
        best, skipped = frames.locate(Page(main, own, evil), "js", "example.com", [], frames.login_score)
        assert best[0] is own and skipped == ["evil.io"]

    def test_trusted_third_party_host_is_searched(self):
        main = Frame("https://example.com/", NONE)
        sso = Frame("https://auth.sso-vendor.com/f", BOTH)
        best, skipped = frames.locate(Page(main, sso), "js", "example.com", ["sso-vendor.com"], frames.login_score)
        assert best[0] is sso and skipped == []

    def test_hidden_and_blank_frames_ignored(self):
        main = Frame("https://example.com/", NONE)
        hidden = Frame("https://example.com/h", BOTH, visible=False)
        blank = Frame("about:blank", BOTH)
        best, skipped = frames.locate(Page(main, hidden, blank), "js", "example.com", [], frames.login_score)
        assert best is None and skipped == []

    def test_password_frame_beats_username_only_and_top_wins_ties(self):
        main = Frame("https://example.com/", USER)
        pw = Frame("https://example.com/p", BOTH)
        best, _ = frames.locate(Page(main, pw), "js", "example.com", [], frames.login_score)
        assert best[0] is pw
        a, b = Frame("https://example.com/", BOTH), Frame("https://example.com/x", BOTH)
        best, _ = frames.locate(Page(a, b), "js", "example.com", [], frames.login_score)
        assert best[0] is a

    def test_lookalike_frame_host_not_matched(self):
        main = Frame("https://example.com/", NONE)
        fake = Frame("https://evilexample.com/f", BOTH)
        best, skipped = frames.locate(Page(main, fake), "js", "example.com", [], frames.login_score)
        assert best is None and skipped == ["evilexample.com"]


def _call(name, args):
    res = asyncio.run(srv.create_server().call_tool(name, args))
    blocks = res[0] if isinstance(res, tuple) else res
    return json.loads(blocks[0].text)


class FakeSession:
    is_running = True
    account_name = None
    passkey_account = None
    main_world_enabled = True
    active_page_id = "p1"

    def __init__(self, page):
        self.page = page

    def get_page(self, pid):
        return self.page


class TestFrameTools:
    def _acct(self):
        cred.save("al", "alice", "s3cret")
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)

    def test_autofill_fills_inside_same_site_iframe(self, monkeypatch):
        self._acct()
        main = Frame("https://example.com/", NONE)
        own = Frame("https://login.example.com/f", BOTH)
        monkeypatch.setattr(srv, "_session", FakeSession(Page(main, own)))
        out = _call("camoufox_autofill", {"name": "al", "submit": True})
        assert out["status"] == "filled" and out["in"] == "login.example.com"
        assert own.filled == {cred.USER_SEL: "alice", cred.PASS_SEL: "s3cret"} and not main.filled
        assert "s3cret" not in json.dumps(out)

    def test_third_party_frame_refused_then_allowed_then_removed(self, monkeypatch):
        self._acct()
        main = Frame("https://example.com/", NONE)
        sso = Frame("https://auth.sso-vendor.com/f", BOTH)
        monkeypatch.setattr(srv, "_session", FakeSession(Page(main, sso)))
        out = _call("camoufox_autofill", {"name": "al"})
        assert out["status"] == "error" and "sso-vendor.com" in out["hint"]
        assert "camoufox_allow_login_frame" in out["hint"] and sso.filled == {}
        assert _call("camoufox_allow_login_frame", {"name": "al", "host": "https://Auth.SSO-vendor.com/x"}
                     )["trusted_frame_hosts"] == ["auth.sso-vendor.com"]
        assert _call("camoufox_autofill", {"name": "al"})["status"] == "filled"
        assert sso.filled
        _call("camoufox_allow_login_frame", {"name": "al", "host": "auth.sso-vendor.com", "remove": True})
        sso.filled.clear()
        assert _call("camoufox_autofill", {"name": "al"})["status"] == "error" and not sso.filled

    def test_top_page_must_still_be_the_site_even_if_frame_is_trusted(self, monkeypatch):
        self._acct()
        accounts.set_field("al", "frame_hosts", ["example.com"])
        main = Frame("https://evil.io/", NONE)
        inner = Frame("https://example.com/f", BOTH)
        monkeypatch.setattr(srv, "_session", FakeSession(Page(main, inner)))
        out = _call("camoufox_autofill", {"name": "al"})
        assert out["status"] == "error" and not inner.filled

    def test_allow_frame_rejects_junk_hosts_and_unknown_account(self):
        self._acct()
        assert _call("camoufox_allow_login_frame", {"name": "al", "host": "a b;rm"})["status"] == "error"
        assert _call("camoufox_allow_login_frame", {"name": "ghost", "host": "a.com"})["status"] == "error"

    def test_totp_in_iframe(self, monkeypatch):
        self._acct()
        cred.save_totp("al", cred.parse_totp_secret("JBSWY3DPEHPK3PXP"))
        monkeypatch.setattr(cred, "seconds_left", lambda p, at=None: 20)
        main = Frame("https://example.com/", {"count": 0, "split": False})
        own = Frame("https://example.com/2fa", {"count": 1, "split": False})
        monkeypatch.setattr(srv, "_session", FakeSession(Page(main, own)))
        out = _call("camoufox_autofill_totp", {"name": "al"})
        assert out["status"] == "filled" and out["in"] == "example.com" and own.filled


class TestPasskeyTools:
    def _acct(self):
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)

    def test_enable_requires_running_account_and_site(self, monkeypatch):
        s = FakeSession(Page(Frame("https://example.com/")))
        s.installed = None
        s.install_passkeys_sync = lambda h: setattr(s, "installed", h)
        monkeypatch.setattr(srv, "_session", s)
        assert _call("camoufox_passkey_enable", {"name": "ghost"})["status"] == "error"
        self._acct()
        out = _call("camoufox_passkey_enable", {"name": "al"})
        assert out["status"] == "enabled" and s.passkey_account == "al" and s.installed
        assert _call("camoufox_passkey_enable", {})["status"] == "disabled" and s.passkey_account is None

    def test_enable_refused_when_not_launched_with_passkeys(self, monkeypatch):
        self._acct()
        s = FakeSession(Page(Frame("https://example.com/")))
        s.main_world_enabled = False
        monkeypatch.setattr(srv, "_session", s)
        out = _call("camoufox_passkey_enable", {"name": "al"})
        assert out["status"] == "error" and "passkeys=True" in out["hint"]
        assert s.passkey_account is None

    def test_binding_uses_frame_url_not_payload_and_flags_account(self, monkeypatch):
        self._acct()
        s = FakeSession(Page(Frame("https://example.com/")))
        s.passkey_account = "al"
        monkeypatch.setattr(srv, "_session", s)
        captured = {}
        s.install_passkeys_sync = lambda h: captured.setdefault("h", h)
        monkeypatch.setattr(srv, "_session", s)
        _call("camoufox_passkey_enable", {"name": "al"})
        binding = captured["h"]
        top = Frame("https://example.com/login")
        Src = {"frame": top, "page": Page(top)}   # Playwright passes a dict
        # a hostile payload cannot override the origin: it has no field for it
        r = binding(Src, {"kind": "create", "options": dict(CREATE, rp={"id": "example.com", "name": "x"}),
                          "origin": "https://evil.io"})
        assert "ok" in r and accounts.describe("al")["has_passkeys"] is True
        evil = Frame("https://evil.io/")
        Src2 = {"frame": evil, "page": Page(evil)}
        assert binding(Src2, {"kind": "get", "options": {"challenge": "x"}})["error"] == "NotAllowedError"
        # iframe => crossOrigin true
        inner = Frame("https://example.com/i")
        Src3 = {"frame": inner, "page": Page(Frame("https://example.com/"), inner)}
        ok = binding(Src3, {"kind": "get", "options": {"rpId": "example.com", "challenge": "x"}})
        assert json.loads(pk.unb64u(ok["ok"]["clientDataJSON"]))["crossOrigin"] is True

    def test_list_delete_and_delete_account_cleanup(self, monkeypatch):
        self._acct()
        monkeypatch.setattr(srv, "_session", FakeSession(Page(Frame("https://example.com/"))))
        reg = pk.create("al", URL, ["example.com"], CREATE)
        out = _call("camoufox_passkey_list", {"name": "al"})
        assert out["passkeys"][0]["credential_id"] == reg["id"] and "pkcs8" not in json.dumps(out)
        assert _call("camoufox_passkey_delete", {"name": "al", "credential_id": "nope"})["status"] == "error"
        assert _call("camoufox_passkey_delete", {"name": "al", "credential_id": reg["id"]})["remaining"] == 0
        pk.create("al", URL, ["example.com"], CREATE)
        _call("camoufox_delete_account", {"name": "al"})
        assert pk.load_all("al") == []
