"""Offline tests for the account vault and its tool wiring."""

import asyncio
import json
import os
import stat

import pytest

from camoufoxmcp import accounts
from camoufoxmcp import server as srv

STATE = {
    "cookies": [{"name": "sid", "value": "SECRET-COOKIE", "domain": ".example.com",
                 "path": "/", "expires": -1}],
    "origins": [{"origin": "https://example.com",
                 "localStorage": [{"name": "tok", "value": "SECRET-LS"}]}],
}


@pytest.fixture(autouse=True)
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv(accounts.ENV_DIR, str(tmp_path / "vault"))
    return tmp_path / "vault"


class TestVault:
    def test_roundtrip_and_site_guess(self):
        info = accounts.save("alice", STATE)
        assert info["site"] == "example.com"
        assert accounts.load_state("alice") == STATE

    def test_permissions_are_private(self, vault):
        accounts.save("alice", STATE)
        assert stat.S_IMODE(os.stat(vault).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(vault / "alice.json").st_mode) == 0o600

    def test_describe_never_leaks_values(self):
        accounts.save("alice", STATE, username="alice")
        dumped = json.dumps(accounts.list_accounts())
        assert "SECRET-COOKIE" not in dumped and "SECRET-LS" not in dumped
        assert "example.com" in dumped

    @pytest.mark.parametrize("bad", ["../x", "a/b", "", ".hidden", "x" * 65, "a b", "a."])
    def test_bad_names_rejected(self, bad):
        with pytest.raises(accounts.AccountError):
            accounts.save(bad, STATE)

    def test_empty_session_refused(self):
        with pytest.raises(accounts.AccountError):
            accounts.save("alice", {"cookies": [], "origins": []})

    def test_resave_keeps_metadata_and_created(self):
        a = accounts.save("alice", STATE, username="al", notes="n")
        b = accounts.save("alice", STATE)
        assert b["username"] == "al" and b["notes"] == "n"
        assert b["created"] == a["created"]

    def test_missing_and_delete(self):
        with pytest.raises(accounts.AccountError):
            accounts.load_state("nope")
        accounts.save("alice", STATE)
        accounts.delete("alice")
        assert accounts.list_accounts() == []

    def test_corrupt_file_is_skipped_in_list_and_errors_on_load(self, vault):
        accounts.save("ok", STATE)
        (vault / "bad.json").write_text("{not json")
        assert [a["name"] for a in accounts.list_accounts()] == ["ok"]
        with pytest.raises(accounts.AccountError):
            accounts.load_state("bad")

    def test_site_filter(self):
        accounts.save("a", STATE)
        assert accounts.list_accounts("example") and not accounts.list_accounts("other")

    def test_local_storage_script_is_origin_guarded_and_safe(self):
        js = accounts.local_storage_init_script(
            {"origins": [{"origin": "https://e.com",
                          "localStorage": [{"name": "k", "value": "</script>"}]}]})
        assert "location.origin" in js and "</script>" not in js
        assert accounts.local_storage_init_script({"origins": []}) is None


def _call(name, args):
    res = asyncio.run(srv.create_server().call_tool(name, args))
    blocks = res[0] if isinstance(res, tuple) else res
    return json.loads(blocks[0].text)


class FakeSession:
    is_running = True
    account_name = None

    def __init__(self):
        self.imported = None

    def export_storage_state(self):
        return STATE

    def import_storage_state(self, state):
        self.imported = state
        return {"cookies": len(state["cookies"]), "local_storage_origins": 1}


class TestTools:
    def test_save_binds_session_then_list_and_load(self, monkeypatch):
        fake = FakeSession()
        monkeypatch.setattr(srv, "_session", fake)
        out = _call("camoufox_save_account", {"name": "alice", "username": "al"})
        assert out["status"] == "saved" and fake.account_name == "alice"
        assert _call("camoufox_list_accounts", {})["count"] == 1
        fake.account_name = None
        out = _call("camoufox_load_account", {"name": "alice"})
        assert out["status"] == "loaded" and fake.imported == STATE
        assert fake.account_name == "alice"

    def test_save_requires_running_browser(self, monkeypatch):
        fake = FakeSession()
        fake.is_running = False
        monkeypatch.setattr(srv, "_session", fake)
        assert _call("camoufox_save_account", {"name": "a"})["status"] == "error"

    def test_load_unknown_account_errors(self, monkeypatch):
        monkeypatch.setattr(srv, "_session", FakeSession())
        assert _call("camoufox_load_account", {"name": "ghost"})["status"] == "error"

    def test_delete_unbinds_active_account(self, monkeypatch):
        fake = FakeSession()
        monkeypatch.setattr(srv, "_session", fake)
        _call("camoufox_save_account", {"name": "alice"})
        out = _call("camoufox_delete_account", {"name": "alice"})
        assert out["status"] == "deleted" and fake.account_name is None

    def test_launch_unknown_account_errors_before_launching(self, monkeypatch):
        class Idle(FakeSession):
            is_running = False
        monkeypatch.setattr(srv, "_session", Idle())
        out = _call("camoufox_launch", {"account": "ghost"})
        assert out["status"] == "error" and "ghost" in out["error"]

    def test_launch_account_and_user_data_dir_conflict(self, monkeypatch):
        class Idle(FakeSession):
            is_running = False
        monkeypatch.setattr(srv, "_session", Idle())
        accounts.save("alice", STATE)
        out = _call("camoufox_launch", {"account": "alice", "user_data_dir": "/tmp/x"})
        assert out["status"] == "error" and "mutually exclusive" in out["error"]
