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


# RFC 6238 appendix B vectors (SHA1/SHA256/SHA512, 8 digits).
RFC_SECRETS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC_VECTORS = [
    (59, "SHA1", "94287082"), (59, "SHA256", "46119246"), (59, "SHA512", "90693936"),
    (1111111109, "SHA1", "07081804"), (1234567890, "SHA1", "89005924"),
    (20000000000, "SHA512", "47863826"),
]


class TestTotp:
    @pytest.mark.parametrize("at,algo,expected", RFC_VECTORS)
    def test_rfc6238_vectors(self, at, algo, expected):
        import base64
        p = {"secret": base64.b32encode(RFC_SECRETS[algo]).decode(), "digits": 8,
             "period": 30, "algo": algo}
        assert cred.totp_code(p, at=at) == expected

    def test_parse_bare_and_uri(self):
        p = cred.parse_totp_secret("jbsw y3dp ehpk 3pxp")
        assert p["secret"] == "JBSWY3DPEHPK3PXP" and p["digits"] == 6
        q = cred.parse_totp_secret(
            "otpauth://totp/x:al?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=sha256")
        assert (q["digits"], q["period"], q["algo"]) == (8, 60, "SHA256")

    @pytest.mark.parametrize("bad", ["", "not base32!!", "otpauth://hotp/x?secret=JBSWY3DP",
                                     "otpauth://totp/x?secret=JBSWY3DP&digits=3"])
    def test_parse_rejects(self, bad):
        with pytest.raises(cred.CredentialError):
            cred.parse_totp_secret(bad)

    def test_seconds_left(self):
        assert cred.seconds_left({"period": 30}, at=59) == 1


class OtpPage(FakePage):
    def __init__(self, url, found):
        super().__init__(url)
        self.otp = found

    def evaluate(self, js):
        return self.otp if js is cred.FIND_OTP_JS else super().evaluate(js)


class TestTotpTools:
    def _acct(self):
        accounts.save("al", {"cookies": [], "origins": []}, site="example.com", allow_empty=True)

    def test_save_requires_account_and_never_echoes_secret(self, monkeypatch):
        monkeypatch.setattr(srv, "_session", FakeSession(FakePage("https://example.com/")))
        assert _call("camoufox_save_totp", {"name": "al", "secret": "JBSWY3DPEHPK3PXP"})["status"] == "error"
        self._acct()
        out = _call("camoufox_save_totp", {"name": "al", "secret": "JBSWY3DPEHPK3PXP"})
        assert out["status"] == "saved" and "JBSWY3DP" not in json.dumps(out)
        assert accounts.describe("al")["has_totp"] is True
        assert "JBSWY3DP" not in json.dumps(accounts._read("al"))

    def test_single_field_fill_does_not_return_code(self, monkeypatch):
        self._acct()
        cred.save_totp("al", cred.parse_totp_secret("JBSWY3DPEHPK3PXP"))
        page = OtpPage("https://example.com/2fa", {"count": 1, "split": False})
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        monkeypatch.setattr(cred, "seconds_left", lambda p, at=None: 20)
        out = _call("camoufox_autofill_totp", {"name": "al", "submit": True})
        code = page.filled[cred.OTP_SEL]
        assert out["status"] == "filled" and len(code) == 6 and code.isdigit()
        assert code not in json.dumps(out) and page.pressed == [(cred.OTP_SEL, "Enter")]

    def test_split_boxes_get_one_digit_each(self, monkeypatch):
        self._acct()
        cred.save_totp("al", cred.parse_totp_secret("JBSWY3DPEHPK3PXP"))
        page = OtpPage("https://example.com/2fa", {"count": 6, "split": True})
        monkeypatch.setattr(srv, "_session", FakeSession(page))
        monkeypatch.setattr(cred, "seconds_left", lambda p, at=None: 20)
        _call("camoufox_autofill_totp", {"name": "al"})
        assert sorted(page.filled) == [f'[data-cmcp-otp="{i}"]' for i in range(6)]
        assert all(len(v) == 1 for v in page.filled.values())

    def test_refuses_wrong_host_and_missing_field(self, monkeypatch):
        self._acct()
        cred.save_totp("al", cred.parse_totp_secret("JBSWY3DPEHPK3PXP"))
        bad = OtpPage("https://evilexample.com/2fa", {"count": 1, "split": False})
        monkeypatch.setattr(srv, "_session", FakeSession(bad))
        assert "not example.com" in _call("camoufox_autofill_totp", {"name": "al"})["error"]
        assert bad.filled == {}
        none = OtpPage("https://example.com/", {"count": 0, "split": False})
        monkeypatch.setattr(srv, "_session", FakeSession(none))
        assert _call("camoufox_autofill_totp", {"name": "al"})["status"] == "error"

    def test_forget_and_delete_remove_totp(self, monkeypatch):
        self._acct()
        cred.save_totp("al", cred.parse_totp_secret("JBSWY3DPEHPK3PXP"))
        accounts.set_credentials_flag("al", True, key="totp")
        out = _call("camoufox_forget_credentials", {"name": "al"})
        assert out["totp_removed"] is True and accounts.describe("al")["has_totp"] is False
        with pytest.raises(cred.CredentialError):
            cred.load_totp("al")
