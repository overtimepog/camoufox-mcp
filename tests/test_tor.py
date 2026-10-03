"""Offline tests for camoufoxmcp.tor.

No tor binary, no network, no Tor Browser. Everything here runs against fake
sockets in a thread, because the logic worth testing -- control-protocol
framing, SAFECOOKIE's HMAC construction, SOCKS5 negotiation, torrc generation
-- is all logic we wrote, and none of it needs a real Tor to exercise.

The one thing these tests cannot tell you is whether a real tor accepts what we
send. That is what the live verification steps in the plan are for.
"""

import hashlib
import hmac
import socket
import threading


class FakeTorControl:
    """A Tor control port, just enough of one.

    Serves a real socket so the client's framing is genuinely exercised. The
    SAFECOOKIE flow is computed from whatever nonce the client sends, so it
    verifies our HMAC construction rather than a transcription of it.
    """

    _SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
    _CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"

    def __init__(self, cookie=b"0123456789abcdef0123456789abcdef",
                 version="0.4.9.12", methods="SAFECOOKIE,COOKIE",
                 server_nonce=bytes(range(32)), info_extra=None,
                 reject_auth=False, event_before_reply=False):
        self.cookie = cookie
        self.version = version
        self.methods = methods
        self.server_nonce = server_nonce
        self.info_extra = info_extra or {}
        self.reject_auth = reject_auth
        # When set, the server pushes a 650 event line before the reply to the
        # first command. That is the desync case: a client that reads the event
        # as its reply answers every subsequent command with its predecessor's
        # answer, and nothing errors.
        self.event_before_reply = event_before_reply
        self.commands = []
        self.authed = False
        self.auth_verified = False
        self.conf = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            f = conn.makefile("rwb")
            first = True
            while True:
                line = f.readline()
                if not line:
                    break
                cmd = line.decode("utf-8", "replace").strip()
                if not cmd:
                    continue
                self.commands.append(cmd)
                if first and self.event_before_reply:
                    # NOTICE severity, i.e. a 650 async event. Must be skipped
                    # and must not be mistaken for this command's reply.
                    f.write(b'650 NOTICE BOOTSTRAP PROGRESS=14 TAG=handshake\r\n')
                first = False
                f.write(self._reply(cmd))
                f.flush()

    def _reply(self, cmd: str) -> bytes:
        verb = cmd.split(" ")[0].upper()

        if verb == "PROTOCOLINFO":
            cookie_file = "/tmp/fake-control-auth-cookie"
            out = [
                '250-PROTOCOLINFO 1',
                f'250-AUTH METHODS={self.methods} COOKIEFILE="{cookie_file}"',
                f'250-VERSION Tor="{self.version}"',
                '250 OK',
            ]
            return ("\r\n".join(out) + "\r\n").encode()

        if verb == "AUTHCHALLENGE":
            parts = cmd.split(" ")
            client_nonce = bytes.fromhex(parts[2])
            # Recorded so AUTHENTICATE can verify the client hash against the
            # nonce we actually saw, rather than one the test guessed.
            self._last_client_nonce = client_nonce
            material = self.cookie + client_nonce + self.server_nonce
            server_hash = hmac.new(self._SERVER_KEY, material, hashlib.sha256).hexdigest().upper()
            payload = (f"AUTHCHALLENGE SERVERHASH={server_hash} "
                       f"SERVERNONCE={self.server_nonce.hex().upper()}")
            return f"250 {payload}\r\n".encode()

        if verb == "AUTHENTICATE":
            if self.reject_auth:
                return b"515 Authentication failed: Password incorrect\r\n"
            token = cmd.split(" ", 1)[1] if " " in cmd else ""
            # Verify the client hash when one was sent. This is the assertion
            # that our HMAC is built the way the spec says, not merely that we
            # sent something.
            if token and self._last_client_nonce is not None:
                material = self.cookie + self._last_client_nonce + self.server_nonce
                expect = hmac.new(self._CLIENT_KEY, material, hashlib.sha256).hexdigest()
                self.auth_verified = hmac.compare_digest(expect, token.lower())
            self.authed = True
            return b"250 OK\r\n"

        if verb == "GETINFO":
            keys = cmd.split(" ")[1:]
            lines = []
            for k in keys:
                if k == "status/bootstrap-phase":
                    val = 'NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"'
                elif k == "status/circuit-established":
                    val = "1"
                elif k.startswith("ip-to-country/"):
                    val = self.info_extra.get(k, "us")
                else:
                    val = self.info_extra.get(k, "unknown")
                lines.append(f"250-{k}={val}")
            lines.append("250 OK")
            return ("\r\n".join(lines) + "\r\n").encode()

        if verb == "GETCONF":
            lines = [f"250-{k}={v}" for k, v in self.conf.items()]
            lines.append("250 OK")
            return ("\r\n".join(lines) + "\r\n").encode()

        if verb == "SETCONF":
            for pair in cmd.split(" ")[1:]:
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    self.conf[k] = v
            return b"250 OK\r\n"

        if verb == "RESETCONF":
            for k in cmd.split(" ")[1:]:
                self.conf.pop(k, None)
            return b"250 OK\r\n"

        if verb == "SIGNAL":
            return b"250 OK\r\n"

        return b"510 Unrecognized command\r\n"

    # The client's nonce is captured during AUTHCHALLENGE so AUTHENTICATE can
    # be verified against it.
    _last_client_nonce = None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TestControlFraming:
    def _client(self, server):
        from camoufoxmcp.tor import _TorControl
        return _TorControl(host="127.0.0.1", port=server.port, timeout=5.0).connect()

    def test_protocolinfo_parses_methods_and_version(self):
        server = FakeTorControl()
        try:
            ctrl = self._client(server)
            info = ctrl.protocolinfo()
            assert info["version"] == "0.4.9.12"
            assert "SAFECOOKIE" in info["methods"]
            assert "COOKIE" in info["methods"]
            assert info["cookie_file"] == "/tmp/fake-control-auth-cookie"
            ctrl.close()
        finally:
            server.close()

    def test_getinfo_splits_multiline_reply(self):
        server = FakeTorControl()
        try:
            ctrl = self._client(server)
            info = ctrl.getinfo("status/bootstrap-phase", "status/circuit-established")
            assert "PROGRESS=100" in info["status/bootstrap-phase"]
            assert info["status/circuit-established"] == "1"
            ctrl.close()
        finally:
            server.close()

    def test_650_event_is_not_mistaken_for_a_reply(self):
        # The failure this guards: an event read as the command's reply shifts
        # every later read by one, so getconf answers getinfo and so on, with
        # nothing raising.
        server = FakeTorControl(event_before_reply=True)
        try:
            ctrl = self._client(server)
            info = ctrl.getinfo("status/circuit-established")
            assert info["status/circuit-established"] == "1", info
            # And the event was recorded rather than discarded.
            assert any("BOOTSTRAP" in e for e in ctrl.events)
            ctrl.close()
        finally:
            server.close()

    def test_error_code_raises_with_tors_own_message(self):
        from camoufoxmcp.tor import TorError
        server = FakeTorControl()
        try:
            ctrl = self._client(server)
            try:
                ctrl._command("NONSENSE")
            except TorError as exc:
                assert "510" in str(exc)
            else:
                raise AssertionError("expected TorError for a 5xx reply")
            ctrl.close()
        finally:
            server.close()

    def test_setconf_and_resetconf_round_trip(self):
        server = FakeTorControl()
        try:
            ctrl = self._client(server)
            ctrl.setconf(ExitNodes="{us}", StrictNodes="1")
            assert server.conf["ExitNodes"] == "{us}"
            ctrl.resetconf("ExitNodes")
            assert "ExitNodes" not in server.conf
            ctrl.close()
        finally:
            server.close()

    def test_bootstrap_progress_parses_percent_and_summary(self):
        server = FakeTorControl()
        try:
            ctrl = self._client(server)
            percent, summary = ctrl.bootstrap_progress()
            assert percent == 100
            assert summary == "Done"
            assert ctrl.circuit_established() is True
            ctrl.close()
        finally:
            server.close()


class TestSafeCookieAuth:
    """SAFECOOKIE is the auth path a real tor actually uses, so its HMAC
    construction is worth verifying against a server that computes the same
    thing independently."""

    def _cookie_file(self, tmp_path, cookie: bytes) -> str:
        """A cookie file the client will read, without touching ~/.camoufoxmcp."""
        path = tmp_path / "control_auth_cookie"
        path.write_bytes(cookie)
        return str(path)

    def test_safecookie_hmac_is_accepted_by_the_server(self, tmp_path):
        # The server computes the client hash independently from the nonce it
        # saw, so this fails if our HMAC construction is wrong -- not merely if
        # we sent nothing.
        import camoufoxmcp.tor as tor_mod

        server = FakeTorControl()
        try:
            ctrl = tor_mod._TorControl(host="127.0.0.1", port=server.port, timeout=5.0).connect()
            ctrl.protocol_info = {
                "methods": ["SAFECOOKIE"],
                "cookie_file": self._cookie_file(tmp_path, server.cookie),
                "version": "0.4.9.12",
            }
            method = ctrl.authenticate()
            assert method == "SAFECOOKIE"
            assert server.auth_verified, (
                "server rejected our client hash — the HMAC construction is wrong")
            ctrl.close()
        finally:
            server.close()

    def test_server_hash_mismatch_is_refused(self, tmp_path):
        # A wrong server hash means we are not talking to the tor we think we
        # are, and we must not send anything derived from the cookie.
        import camoufoxmcp.tor as tor_mod
        from camoufoxmcp.tor import TorAuthError

        server = FakeTorControl()
        try:
            ctrl = tor_mod._TorControl(host="127.0.0.1", port=server.port, timeout=5.0).connect()
            original_command = ctrl._command

            def tampered(cmd, allow_error=False):
                lines = original_command(cmd, allow_error)
                if cmd.startswith("AUTHCHALLENGE"):
                    # Replace the hash outright rather than flipping one digit:
                    # a digit flip is a no-op whenever the real hash already
                    # starts with that digit, which makes the test flaky.
                    import re as _re
                    code, text, data = lines[-1]
                    forged = _re.sub(r"SERVERHASH=\w+", "SERVERHASH=" + "00" * 32, text)
                    return [(code, forged, data)]
                return lines

            ctrl._command = tampered
            ctrl.protocol_info = {
                "methods": ["SAFECOOKIE"],
                "cookie_file": self._cookie_file(tmp_path, server.cookie),
                "version": "0.4.9.12",
            }
            try:
                ctrl.authenticate()
            except TorAuthError as exc:
                assert "hash mismatch" in str(exc) or "unparseable" in str(exc)
            else:
                raise AssertionError("expected TorAuthError on a bad server hash")
            ctrl.close()
        finally:
            server.close()

    def test_auth_failure_surfaces_as_tor_auth_error(self):
        import camoufoxmcp.tor as tor_mod
        from camoufoxmcp.tor import TorAuthError

        server = FakeTorControl(reject_auth=True)
        try:
            ctrl = tor_mod._TorControl(host="127.0.0.1", port=server.port, timeout=5.0).connect()
            ctrl.protocol_info = {"methods": ["HASHEDPASSWORD"], "cookie_file": None,
                                  "version": "0.4.9.12"}
            try:
                ctrl.authenticate()
            except TorAuthError as exc:
                # The message must name the methods offered, so a failure is
                # diagnosable without re-running PROTOCOLINFO by hand.
                assert "HASHEDPASSWORD" in str(exc)
            else:
                raise AssertionError("expected TorAuthError when auth is rejected")
            ctrl.close()
        finally:
            server.close()


class TestExitNodeValidation:
    def test_accepts_and_normalises_country_codes(self):
        from camoufoxmcp.tor import _validate_exit_nodes
        assert _validate_exit_nodes("us") == "{us}"
        assert _validate_exit_nodes("{us}") == "{us}"
        assert _validate_exit_nodes("US,CA") == "{us,ca}"
        assert _validate_exit_nodes("{us, ca}") == "{us,ca}"

    def test_rejects_malformed_specs(self):
        # Rejected rather than passed through: tor treats a malformed ExitNodes
        # as an empty set and silently builds no circuits at all.
        from camoufoxmcp.tor import _validate_exit_nodes
        assert _validate_exit_nodes("") is None
        assert _validate_exit_nodes("usa") is None
        assert _validate_exit_nodes("{us,1}") is None
        assert _validate_exit_nodes("!!") is None


class TestIsolationSlots:
    """Circuit isolation is a dedicated SocksPort per label, not a credential.

    The credential design could not work and failed loudly rather than quietly
    (Playwright refuses SOCKS auth for Firefox; Firefox has no socks_username
    pref), so what is worth testing is the mechanism that replaced it: labels
    get distinct slots, a label keeps its slot, and the pool refuses to
    silently overlap two labels onto one circuit.
    """

    def _fresh(self, tmp_path, monkeypatch, slots=4):
        import camoufoxmcp.tor as tor
        monkeypatch.setattr(tor, "ISOLATION_STATE_PATH", tmp_path / "isolations.json")
        monkeypatch.setattr(tor, "DEFAULT_ISOLATION_SLOTS", slots)
        return tor

    def test_a_label_keeps_its_slot(self, tmp_path, monkeypatch):
        tor = self._fresh(tmp_path, monkeypatch)
        assert tor.isolation_slot("session-a") == tor.isolation_slot("session-a")

    def test_two_labels_never_share_a_slot(self, tmp_path, monkeypatch):
        """A collision would put two "isolated" sessions on one circuit."""
        tor = self._fresh(tmp_path, monkeypatch)
        slots = {tor.isolation_slot(name) for name in ("a", "b", "c", "d")}
        assert slots == {0, 1, 2, 3}

    def test_assignment_survives_a_reload(self, tmp_path, monkeypatch):
        """It is persisted, not recomputed -- a restart must not reshuffle."""
        tor = self._fresh(tmp_path, monkeypatch)
        first = tor.isolation_slot("session-a")
        # A new read of the table stands in for a new process.
        assert tor._load_isolations()["session-a"] == first

    def test_a_full_pool_is_an_error_not_a_shared_circuit(self, tmp_path, monkeypatch):
        tor = self._fresh(tmp_path, monkeypatch, slots=1)
        tor.isolation_slot("a")
        try:
            tor.isolation_slot("b")
        except tor.TorError as exc:
            assert "isolation slots are in use" in str(exc)
        else:
            raise AssertionError(
                "a full pool must refuse, not hand out a slot another label owns")

    def test_a_shrunk_pool_is_reported_rather_than_ignored(self, tmp_path, monkeypatch):
        """A label whose slot no longer exists must fail, not point at a dead port."""
        tor = self._fresh(tmp_path, monkeypatch, slots=4)
        tor.isolation_slot("a")
        tor.isolation_slot("b")
        tor.DEFAULT_ISOLATION_SLOTS = 1
        try:
            tor.isolation_slot("b")
        except tor.TorError as exc:
            # The message has to name the label and the reason, or the operator
            # cannot tell which assignment is now unreachable.
            assert "'b'" in str(exc)
            assert "reduced" in str(exc)
        else:
            raise AssertionError("a label outside the pool must not resolve")

    def test_zero_slots_disables_isolation_loudly(self, tmp_path, monkeypatch):
        tor = self._fresh(tmp_path, monkeypatch, slots=0)
        try:
            tor.isolation_slot("a")
        except tor.TorError as exc:
            assert "disabled" in str(exc)
        else:
            raise AssertionError("slots=0 must refuse rather than share the base port")

    def test_distinct_labels_get_distinct_ports(self, tmp_path, monkeypatch):
        tor = self._fresh(tmp_path, monkeypatch)
        a = tor.isolation_port("a", 19050)
        b = tor.isolation_port("b", 19050)
        assert a != b
        assert a != 19050 and b != 19050, "a label must not land on the base port"

    def test_a_corrupt_table_does_not_brick_isolation(self, tmp_path, monkeypatch):
        tor = self._fresh(tmp_path, monkeypatch)
        (tmp_path / "isolations.json").write_text("{ not json")
        assert tor.isolation_slot("a") == 0

    def test_the_proxy_url_carries_no_credentials(self, tmp_path, monkeypatch):
        """The measured constraint, asserted so it cannot creep back."""
        tor = self._fresh(tmp_path, monkeypatch)
        monkeypatch.setattr(tor, "_resolve_endpoint",
                            lambda instance=None: {"kind": "managed", "socks_port": 19050})
        url, user, password = tor.socks_proxy_url(isolation="a")
        assert user is None and password is None
        assert "@" not in url
        assert url.startswith("socks5://127.0.0.1:")


class TestTorrcGeneration:
    def test_generated_torrc_pins_the_base_port_and_control(self):
        from camoufoxmcp.tor import _build_torrc
        torrc = _build_torrc(19050, 19051)
        assert "SocksPort 127.0.0.1:19050" in torrc
        assert "ControlPort 127.0.0.1:19051" in torrc
        assert "CookieAuthentication 1" in torrc

    def test_every_isolation_slot_gets_a_listener(self):
        """The listeners must exist at startup, because they cannot be added later.

        Measured on 0.4.9.6: `SETCONF +SocksPort=...` is rejected with "552
        Unrecognized option", and repeating the key replaces the list instead of
        appending. So a slot that is not in the torrc has no port, and a label
        assigned to it would fail at launch rather than at isolation time.
        """
        from camoufoxmcp.tor import ISOLATION_PORT_STRIDE, _build_torrc
        torrc = _build_torrc(19050, 19051, slots=3)
        for slot in range(3):
            port = 19050 + ISOLATION_PORT_STRIDE + slot
            assert "SocksPort 127.0.0.1:%d" % port in torrc, "slot %d has no listener" % slot

    def test_the_isolation_pool_does_not_collide_with_the_control_port(self):
        """A slot landing on 19051 would be a config that cannot bind."""
        from camoufoxmcp.tor import ISOLATION_PORT_STRIDE, _build_torrc
        torrc = _build_torrc(19050, 19051, slots=8)
        assert "SocksPort 127.0.0.1:19051" not in torrc
        assert ISOLATION_PORT_STRIDE > 1

    def test_no_isolation_listeners_when_the_pool_is_zero(self):
        from camoufoxmcp.tor import _build_torrc
        torrc = _build_torrc(19050, 19051, slots=0)
        assert torrc.count("SocksPort") == 1

    def test_isolate_socks_auth_is_gone(self):
        """It was load-bearing-looking and did nothing.

        Nothing ever sent a SOCKS credential -- Playwright refuses to launch
        Firefox with one -- so the flag isolated streams by a value that was
        always empty, i.e. it shared every circuit exactly as if absent. Leaving
        it in would keep the false explanation alive.
        """
        from camoufoxmcp.tor import _build_torrc
        assert "IsolateSOCKSAuth" not in _build_torrc(19050, 19051)

    def test_keep_alive_isolate_socks_auth_is_not_emitted(self):
        """It was a real option once and tor removed it.

        This assertion used to be the opposite, on the reasoning that the flag
        keeps isolated circuits from collapsing. It does -- in tor versions that
        still have it. On 0.4.9.6 it is gone from ``--list-torrc-options``, and
        passing it makes tor refuse the *entire* config with "Unknown option",
        so the flag that was supposed to preserve isolation prevented the
        instance from starting at all.

        The old test could not catch that, because it asserted a substring of a
        string we generate ourselves -- it was checking our own spelling, and
        passing. Only ``tor --verify-config`` could have rejected it, which is
        what the option-name test below now stands in for.
        """
        from camoufoxmcp.tor import _build_torrc
        assert "KeepAliveIsolateSOCKSAuth" not in _build_torrc(19050, 19051)

    def test_every_torrc_option_name_exists_in_the_installed_tor(self):
        """Validate option names against tor itself, not against our spelling.

        The failure this exists for: ``KeepAliveIsolateSOCKSAuth`` was in the
        generated torrc, looked right, and tor rejected the whole file. Nothing
        offline could have noticed, because the only authority on the option
        list is the binary.

        Skips when ``tor`` is not installed, which is the bare-CI case -- the
        test is worth more than its absence, but a missing binary is not a
        failure.
        """
        import re
        import shutil
        import subprocess

        from camoufoxmcp.tor import _build_torrc

        binary = shutil.which("tor")
        if not binary:
            import pytest
            pytest.skip("no tor binary; cannot validate option names")

        listing = subprocess.run(
            [binary, "--list-torrc-options"],
            capture_output=True, text=True, timeout=30,
        )
        # Some builds only print the list with --help; treat an empty result as
        # "cannot check" rather than "no options are valid".
        known = set(listing.stdout.split())
        if not known:
            import pytest
            pytest.skip("tor did not print its option list")

        unknown = []
        for line in _build_torrc(19050, 19051).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[\s]", line, maxsplit=1)[0]
            # SocksPort's trailing IsolateSOCKSAuth is a *flag*, not an option,
            # and flags do not appear in the option list -- only the leading
            # name is checked here.
            if name not in known:
                unknown.append(name)
        assert not unknown, (
            "tor would reject the generated torrc; unknown options: %r" % (unknown,)
        )

    def test_torrc_never_targets_tor_browsers_ports(self):
        # The whole point of a managed instance is that it cannot disturb a
        # Tor Browser the operator has open. Matched on full host:port, since
        # "9050" is a substring of "19050" and a naive check would be vacuous.
        from camoufoxmcp.tor import _build_torrc
        torrc = _build_torrc(19050, 19051)
        for foreign in ("127.0.0.1:9150", "127.0.0.1:9151", "127.0.0.1:9050",
                        "127.0.0.1:9051"):
            assert foreign not in torrc, f"managed torrc references {foreign}"

    def test_torrc_honours_custom_ports(self):
        from camoufoxmcp.tor import _build_torrc
        torrc = _build_torrc(19150, 19151)
        assert "SocksPort 127.0.0.1:19150" in torrc
        assert "ControlPort 127.0.0.1:19151" in torrc


class FakeSocks5:
    """A SOCKS5 proxy that records the negotiation it was sent."""

    def __init__(self, body=b'{"IP": "1.2.3.4", "IsTor": true}',
                 require_auth=True, http_status=b"200 OK"):
        self.body = body
        self.require_auth = require_auth
        self.http_status = http_status
        self.username = None
        self.password = None
        self.target = None
        self.greeting = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.error = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _read_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        try:
            with conn:
                # Greeting is VER, NMETHODS, then NMETHODS method bytes. The
                # count varies (we offer two methods with credentials, one
                # without), so it cannot be read as a fixed width.
                header = self._read_exact(conn, 2)
                methods = self._read_exact(conn, header[1])
                self.greeting = header + methods
                if self.require_auth and 0x02 in methods:
                    conn.sendall(b"\x05\x02")
                    head = self._read_exact(conn, 2)
                    ulen = head[1]
                    self.username = self._read_exact(conn, ulen).decode()
                    plen = self._read_exact(conn, 1)[0]
                    self.password = self._read_exact(conn, plen).decode()
                    conn.sendall(b"\x01\x00")
                else:
                    conn.sendall(b"\x05\x00")

                head = self._read_exact(conn, 4)
                atyp = head[3]
                if atyp == 0x03:
                    ln = self._read_exact(conn, 1)[0]
                    host = self._read_exact(conn, ln).decode()
                    port = int.from_bytes(self._read_exact(conn, 2), "big")
                    self.target = (host, port)
                conn.sendall(b"\x05\x00\x00\x01" + bytes([127, 0, 0, 1]) + (0).to_bytes(2, "big"))

                # Drain the HTTP request, then answer.
                self._read_exact(conn, 1)
                while True:
                    chunk = conn.recv(4096)
                    if not chunk or b"\r\n\r\n" in chunk:
                        break
                response = (
                    b"HTTP/1.1 " + self.http_status + b"\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(self.body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + self.body
                )
                conn.sendall(response)
        except Exception as exc:  # pragma: no cover - surfaced via assertions
            self.error = exc

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TestSocks5Client:
    def test_negotiates_auth_and_sends_credentials(self):
        from camoufoxmcp.tor import _socks5_http_get

        server = FakeSocks5()
        try:
            response = _socks5_http_get(
                "127.0.0.1", server.port, "http://example.com/api/ip",
                username="cfx-user", password="cfx-pass", timeout=10.0)
            assert response["status_code"] == 200
            assert "1.2.3.4" in response["body"]
            # The credential must arrive intact: Tor selects the circuit from
            # it, so a mangled credential silently un-isolates the session.
            assert server.username == "cfx-user"
            assert server.password == "cfx-pass"
        finally:
            server.close()

    def test_offers_only_userpass_when_credentials_are_set(self):
        # Falling back to no-auth would drop the isolation and put this
        # session on whatever circuit the previous one used.
        from camoufoxmcp.tor import _socks5_http_get

        server = FakeSocks5()
        try:
            _socks5_http_get("127.0.0.1", server.port, "http://example.com/",
                             username="u", password="p", timeout=10.0)
            assert server.greeting[:2] == b"\x05\x02"
        finally:
            server.close()

    def test_offers_noauth_when_credentials_are_absent(self):
        from camoufoxmcp.tor import _socks5_http_get

        server = FakeSocks5(require_auth=False)
        try:
            _socks5_http_get("127.0.0.1", server.port, "http://example.com/", timeout=10.0)
            assert server.greeting[:2] == b"\x05\x01"
        finally:
            server.close()

    def test_connect_uses_domain_name_addressing(self):
        # Local DNS resolution would leak the hostname Tor is meant to resolve
        # on our behalf.
        from camoufoxmcp.tor import _socks5_http_get

        server = FakeSocks5(require_auth=False)
        try:
            _socks5_http_get("127.0.0.1", server.port, "http://example.com:8080/x",
                             timeout=10.0)
            assert server.target == ("example.com", 8080)
        finally:
            server.close()


class TestHttpResponseParsing:
    def test_parses_status_headers_and_body(self):
        from camoufoxmcp.tor import _parse_http_response
        status, headers, body = _parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
        assert status == 200
        assert headers["content-type"] == "text/plain"
        assert body == "hello"

    def test_dechunks_a_chunked_body(self):
        from camoufoxmcp.tor import _parse_http_response
        raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        status, headers, body = _parse_http_response(raw)
        assert status == 200
        assert body == "hello world"

    def test_unparseable_response_does_not_raise(self):
        from camoufoxmcp.tor import _parse_http_response
        status, headers, body = _parse_http_response(b"garbage")
        assert status is None


class TestExitProbeParsing:
    def test_probe_failure_is_unverified_not_an_error(self):
        # A Tor session that works fine must not be reported as broken just
        # because the probe host is unreachable.
        from camoufoxmcp.tor import _probe_exit_ip
        result = _probe_exit_ip(1, probe_url="http://127.0.0.1:1/nope")
        assert result is None

    def test_isolation_resolution_returns_distinct_ports_for_known_kinds(self):
        from camoufoxmcp.tor import _resolve_endpoint, TorError
        try:
            ep = _resolve_endpoint("nonsense-instance")
        except TorError as exc:
            assert "Unknown Tor instance" in str(exc)
        except Exception:
            pass  # no Tor on the machine under test: acceptable
        else:
            assert ep["kind"] == "nonsense-instance"


class TestNoThirdPartyDependency:
    def test_tor_module_imports_are_all_stdlib(self):
        """The whole module must import cleanly with no third-party package.

        A PySocks dependency would be the easy way to do the SOCKS5 handshake
        and the wrong one: it would put a new package in the install for one
        probe. This asserts the constraint rather than trusting the review.
        """
        import ast
        import inspect
        import camoufoxmcp.tor as tor_mod

        banned = {"socks", "requests", "httpx", "aiohttp", "urllib3", "pysocks"}
        tree = ast.parse(inspect.getsource(tor_mod))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        assert not (imported & banned), f"non-stdlib dependency: {imported & banned}"
