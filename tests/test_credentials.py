"""Offline tests for keychain credentials and autofill."""

import asyncio
import json

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from camoufoxmcp import accounts, credentials as cred
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
    return kr


class TestHostMatch:
    @pytest.mark.parametrize("url,site,ok", [
        ("https://example.com/login", "example.com", True),
        ("https://accounts.example.com/x", "example.com", True),
        ("https://evilexample.com/", "example.com", False),
        ("https://example.com.evil.io/", "example.com", False),
        ("https://example.com/", "https://example.com", True),
        ("https://example.com/", "", False),
        ("about:blank", "example.com", False),
    ])
    def test_cases(self, url, site, ok):
        assert cred.host_matches(url, site) is ok


class TestStore:
    def test_roundtrip_delete(self):
        cred.save("a", "alice", "pw")
        assert cred.load("a") == ("alice", "pw")
        assert cred.delete("a") is True and cred.delete("a") is False
        with pytest.raises(cred.CredentialError):
            cred.load("a")

    def test_refuses_without_secure_backend(self, monkeypatch):
        from keyring.backends import fail
        monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
        assert cred.available() is False
        with pytest.raises(cred.CredentialError):
            cred.save("a", "u", "p")

    def test_requires_both(self):
        with pytest.raises(cred.CredentialError):
            cred.save("a", "u", "")


class FakePage:
    def __init__(self, url, found=None, values=None):
        self.url = url
        self.found = found or {"user": True, "password": True}
        self.values = values or {"username": "alice", "password": "s3cret"}
        self.filled, self.pressed = {}, []

    def evaluate(self, js):
        return self.found if js is cred.FIND_LOGIN_JS else self.values

    def fill(self, sel, v):
        self.filled[sel] = v

    def press(self, sel, key):
        self.pressed.append((sel, key))


class FakeSession:
    is_running = True
    account_name = None
    active_page_id = "p1"

    def __init__(self, page):
        self.page = page

    def get_page(self, pid):
        return self.page


def _call(name, args):
    res = asyncio.run(srv.create_server().call_tool(name, args))
    blocks = res[0] if isinstance(res, tuple) else res
    return json.loads(blocks[0].text)


class TestTools:
    def test_save_from_page_then_autofill(self, monkeypatch, env):
        page = FakePage("https://example.com/login")
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        out = _call("camoufox_save_credentials", {"name": "al"})
        assert out["status"] == "saved" and out["site"] == "example.com"
        assert "s3cret" not in json.dumps(out)
        assert cred.load("al") == ("alice", "s3cret")
        rec = json.dumps(accounts._read("al"))
        assert "s3cret" not in rec and accounts.describe("al")["has_credentials"]

        page.filled.clear()
        out = _call("camoufox_autofill", {"name": "al", "submit": True})
        assert out["filled"] == ["username", "password"] and "s3cret" not in json.dumps(out)
        assert page.filled == {cred.USER_SEL: "alice", cred.PASS_SEL: "s3cret"}
        assert page.pressed == [(cred.PASS_SEL, "Enter")]

    def test_autofill_refuses_wrong_host(self, monkeypatch):
        cred.save("al", "alice", "pw")
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)
        page = FakePage("https://evilexample.com/login")
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        out = _call("camoufox_autofill", {"name": "al"})
        assert out["status"] == "error" and "not example.com" in out["error"]
        assert page.filled == {}

    def test_two_step_username_only(self, monkeypatch):
        cred.save("al", "alice", "pw")
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)
        page = FakePage("https://example.com/", found={"user": True, "password": False})
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        out = _call("camoufox_autofill", {"name": "al"})
        assert out["filled"] == ["username"] and "again" in out["hint"]
        assert page.filled == {cred.USER_SEL: "alice"}

    def test_no_fields(self, monkeypatch):
        cred.save("al", "alice", "pw")
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)
        page = FakePage("https://example.com/", found={"user": False, "password": False})
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        assert _call("camoufox_autofill", {"name": "al"})["status"] == "error"

    def test_save_from_page_needs_both_values(self, monkeypatch):
        page = FakePage("https://example.com/", values={"username": "alice", "password": ""})
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        out = _call("camoufox_save_credentials", {"name": "al"})
        assert out["status"] == "error"
        with pytest.raises(cred.CredentialError):
            cred.load("al")

    def test_save_refused_without_keychain(self, monkeypatch):
        from keyring.backends import fail
        monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
        monkeypatch.setattr(srv, "_session", FakeSession(FakePage("https://example.com/")))
        out = _call("camoufox_save_credentials", {"name": "al"})
        assert out["status"] == "error" and "refusing" in out["error"].lower()
        assert accounts.list_accounts() == []

    def test_resave_session_keeps_credentials_flag(self):
        accounts.save("al", {"cookies": [], "origins": []}, site="e.com", allow_empty=True)
        accounts.set_credentials_flag("al", True)
        st = {"cookies": [{"name": "s", "value": "v", "domain": "e.com", "path": "/"}], "origins": []}
        assert accounts.save("al", st)["has_credentials"] is True

    def test_delete_account_removes_keychain_entry_and_forget_keeps_session(self, monkeypatch):
        monkeypatch.setattr(srv, "_session", FakeSession(FakePage("https://example.com/")))
        _call("camoufox_save_credentials", {"name": "al"})
        out = _call("camoufox_forget_credentials", {"name": "al"})
        assert out["status"] == "forgotten" and accounts.describe("al")["has_credentials"] is False
        _call("camoufox_save_credentials", {"name": "al"})
        assert _call("camoufox_delete_account", {"name": "al"})["credentials_removed"] is True
        with pytest.raises(cred.CredentialError):
            cred.load("al")
