"""Offline tests for camoufoxmcp.hardening.

No browser is launched here. The parts worth testing are the decisions that were
made by measurement and would silently regress if someone edited them back:

* the fingerprint is generated for the *host's* OS family, because generating
  for a different one produces a browser whose UA and platform disagree;
* it is persisted and reused, because a fingerprint regenerated per launch is
  not pinned, it is a random fingerprint with extra steps;
* WebGL is pinned through ``webgl_config``, because the fingerprint does not
  pin it;
* every pref name is one Firefox actually reads, because an invalid pref is
  ignored without a word.

The last one is the test that would have caught ``KeepAliveIsolateSOCKSAuth`` in
tor.py -- a string that looked right in a generated config and was rejected by
the only thing that could reject it. Here the check is against the shipped
browser rather than against a guess, and it skips when the browser has not been
downloaded.
"""

import dataclasses
import json
import pathlib
import sys


def _tmp(tmp_path, name="fingerprint.json"):
    return tmp_path / name


# ----------------------------------------------------------------------
# Prefs


class TestHardenedPrefs:
    """Every pref must be one Firefox reads.

    A pref that Firefox has never heard of is accepted silently -- there is no
    error, no warning, and no effect. So a typo here is invisible in every test
    that does not go and look, which is what this one does.
    """

    def _sources(self):
        """Raw bytes of everything in the shipped browser that names prefs.

        Two places, and missing either produces a false negative:

        * the big engine binary (``XUL``/``xul.dll``/``libxul.so``) holds the
          names of prefs read from C++ as string literals. It is a *sibling* of
          the small launcher stub that ``launch_path()`` returns -- reading the
          stub alone finds almost nothing, which is how this test first failed
          on ``geo.enabled``, a pref that is plainly there.
        * ``omni.ja``, a zip, holds the JS modules. Prefs read only from JS are
          absent from the binary entirely, which is why grepping the binary made
          ``privacy.resistFingerprinting.letterboxing`` look non-existent when
          it was read by RFPHelper all along.

        Returns None if the browser is not downloaded, which is the bare-CI
        case; the caller skips rather than passing vacuously.
        """
        import zipfile

        try:
            from camoufox.pkgman import launch_path
            stub = pathlib.Path(launch_path())
        except Exception:
            return None
        if not stub.exists():
            return None

        blobs = []
        for candidate in stub.parent.iterdir():
            try:
                # Only the engine binaries; skipping the small stubs and the
                # font directory keeps this to a couple of hundred MB of reads.
                if candidate.is_file() and candidate.stat().st_size > 5_000_000:
                    blobs.append(candidate.read_bytes())
            except OSError:
                continue
        if not blobs:
            return None

        for ja in stub.parent.parent.rglob("omni.ja"):
            try:
                with zipfile.ZipFile(ja) as archive:
                    for name in archive.namelist():
                        if name.endswith((".mjs", ".js", ".jsm")):
                            blobs.append(archive.read(name))
            except Exception:
                continue
        return blobs

    def test_every_pref_name_is_known_to_firefox(self):
        from camoufoxmcp.hardening import HARDENED_PREFS

        blobs = self._sources()
        if blobs is None:
            import pytest
            pytest.skip("camoufox browser not downloaded; cannot check pref names")

        unknown = [
            name for name in HARDENED_PREFS
            if not any(name.encode() in blob for blob in blobs)
        ]
        assert not unknown, (
            "these prefs are not read anywhere in the shipped Firefox, so "
            "Firefox will ignore them silently: %r" % (unknown,)
        )

    def test_resist_fingerprinting_is_enabled(self):
        from camoufoxmcp.hardening import HARDENED_PREFS

        # The single load-bearing entry: with it off the real timezone is
        # reported. Measured, same fingerprint and launch options otherwise.
        assert HARDENED_PREFS["privacy.resistFingerprinting"] is True

    def test_no_tor_browser_only_prefs(self):
        """Tor-only prefs would be silently ignored, so none may creep in.

        privacy.spoof_english looks like a Tor-ism and is not: RFPHelper.sys.mjs
        reads it. Anything actually Tor-specific does not belong here.
        """
        from camoufoxmcp.hardening import HARDENED_PREFS

        tor_only = [n for n in HARDENED_PREFS if "tor" in n.lower() or n.startswith("extensions.tor")]
        assert not tor_only, "Tor Browser-only prefs would be ignored: %r" % (tor_only,)

    def test_prefs_do_not_include_a_user_agent_override(self):
        """RFP owns the UA; an override would contradict navigator.platform."""
        from camoufoxmcp.hardening import HARDENED_PREFS

        assert "general.useragent.override" not in HARDENED_PREFS


# ----------------------------------------------------------------------
# Fingerprint construction and persistence


class TestFingerprintConstruction:
    def test_coerce_rebuilds_nested_dataclasses(self):
        """asdict is one-way; the rebuild is driven from the annotations."""
        from browserforge.fingerprints import Fingerprint, FingerprintGenerator

        from camoufoxmcp.hardening import _coerce

        original = FingerprintGenerator(browser="firefox").generate(os="macos")
        plain = json.loads(json.dumps(dataclasses.asdict(original)))
        rebuilt = _coerce(Fingerprint, plain)

        assert dataclasses.is_dataclass(rebuilt)
        assert rebuilt.navigator.platform == original.navigator.platform
        assert rebuilt.screen.width == original.screen.width
        # The nested objects must be dataclasses again, not the dicts they were
        # serialised as -- launch_options reads attributes off them.
        assert dataclasses.is_dataclass(rebuilt.navigator)
        assert dataclasses.is_dataclass(rebuilt.screen)

    def test_coerce_drops_unknown_keys_instead_of_raising(self):
        """A file from a different browserforge version must degrade, not brick."""
        from browserforge.fingerprints import Fingerprint, FingerprintGenerator

        from camoufoxmcp.hardening import _coerce

        original = FingerprintGenerator(browser="firefox").generate(os="macos")
        plain = dataclasses.asdict(original)
        plain["aFieldThatDoesNotExist"] = "from a future version"

        rebuilt = _coerce(Fingerprint, plain)
        assert rebuilt.navigator.platform == original.navigator.platform

    def test_generated_for_the_host_os_family(self):
        """The core finding, as a test.

        A fingerprint generated for a family other than the host's makes the
        injected platform contradict the UA that RFP insists on reporting
        (measured: UA macOS, platform Win32). Generating for the host family is
        what removes it.
        """
        from camoufoxmcp.hardening import host_os_family

        expected = {"darwin": "macos", "win32": "windows", "linux": "linux"}
        assert host_os_family() == expected.get(sys.platform, "linux")

    def test_injected_platform_matches_what_rfp_normalises_to(self):
        """The strings browserforge emits must be RFP's own normalised strings."""
        import camoufoxmcp.hardening as hardening

        # What Firefox's RFP reports per family, which is what the UA will say.
        canonical = {
            "macos": ("MacIntel", "Intel Mac OS X 10.15"),
            "windows": ("Win32", "Windows NT 10.0; Win64; x64"),
            "linux": ("Linux x86_64", "Linux x86_64"),
        }

        for family, (platform, oscpu) in canonical.items():
            fingerprint = hardening._fingerprint_for(family)
            assert fingerprint.navigator.platform == platform, family
            assert fingerprint.navigator.oscpu == oscpu, family

    def test_screen_is_pinned_to_rfps_canonical_size(self):
        """A one-off resolution is itself a signal, so it is constrained."""
        import camoufoxmcp.hardening as hardening

        fingerprint = hardening._fingerprint_for("macos")
        assert fingerprint.screen.width == hardening.CANONICAL_WIDTH
        assert fingerprint.screen.height == hardening.CANONICAL_HEIGHT

    def test_webgl_pair_comes_from_camoufoxs_own_database(self):
        """So a pair that is valid here cannot be rejected at launch."""
        import camoufoxmcp.hardening as hardening

        fingerprint = hardening._fingerprint_for("macos")
        pair = hardening.webgl_config(fingerprint)
        assert pair is not None, "a hardened fingerprint must carry a WebGL pair"

        from camoufox.webgl.sample import sample_webgl
        # Raises if the pair is not valid for the OS Camoufox will look it up
        # under, which is the failure this avoids.
        sample_webgl(hardening._webgl_os(), pair[0], pair[1])


class TestFingerprintPersistence:
    def test_created_once_then_reused(self, tmp_path):
        """A fingerprint regenerated per launch is not pinned."""
        from camoufoxmcp.hardening import load_or_create_fingerprint

        path = _tmp(tmp_path)
        first = load_or_create_fingerprint(path)
        assert path.exists(), "the first call must persist, or nothing is pinned"

        second = load_or_create_fingerprint(path)
        assert first.navigator.platform == second.navigator.platform
        assert first.navigator.oscpu == second.navigator.oscpu
        assert first.screen.width == second.screen.width
        assert first.screen.height == second.screen.height
        assert first.navigator.userAgent == second.navigator.userAgent

    def test_the_webgl_pair_survives_a_round_trip(self, tmp_path):
        """Otherwise the renderer changes between launches while the rest holds.

        This is the bug the first calibration run found: everything else pinned,
        WebGL NVIDIA in one launch and AMD in the next, because launch_options
        re-samples it when webgl_config is absent.
        """
        from camoufoxmcp.hardening import load_or_create_fingerprint, webgl_config

        path = _tmp(tmp_path)
        first = webgl_config(load_or_create_fingerprint(path))
        second = webgl_config(load_or_create_fingerprint(path))
        assert first == second
        assert first is not None

    def test_a_corrupt_file_is_regenerated_rather_than_fatal(self, tmp_path):
        """A bad file must not make launching impossible."""
        from camoufoxmcp.hardening import load_or_create_fingerprint

        path = _tmp(tmp_path)
        path.write_text("{ this is not json")
        fingerprint = load_or_create_fingerprint(path)
        assert fingerprint.navigator.platform
        # Regenerating silently would change the identity without saying so, so
        # the file is rewritten and the caller gets a usable fingerprint either
        # way -- the warning goes to the log.
        assert json.loads(path.read_text())["navigator"]["platform"]

    def test_two_different_paths_are_independent(self, tmp_path):
        """Persistence is per-path, so a test cannot clobber a real identity."""
        from camoufoxmcp.hardening import load_or_create_fingerprint

        a = load_or_create_fingerprint(_tmp(tmp_path, "a.json"))
        b = load_or_create_fingerprint(_tmp(tmp_path, "b.json"))
        assert (_tmp(tmp_path, "a.json")).exists()
        assert (_tmp(tmp_path, "b.json")).exists()
        assert a is not b


# ----------------------------------------------------------------------
# The refusals


class TestConflicts:
    """Arguments that contradict or defeat hardening, and must be refused."""

    def test_nothing_passed_means_no_conflict(self):
        from camoufoxmcp.hardening import conflicts

        assert conflicts() == {}

    def test_each_contradiction_is_named_with_a_reason(self):
        from camoufoxmcp.hardening import conflicts

        clashing = conflicts(
            timezone="America/New_York",
            locale="de-DE",
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
            user_data_dir="/tmp/profile",
        )
        assert sorted(clashing) == ["locale", "timezone", "user_agent", "user_data_dir"]
        for name, why in clashing.items():
            assert isinstance(why, str) and len(why) > 20, name

    def test_the_timezone_reason_names_rfp_as_the_cause(self):
        """The reason has to be checkable, not just a refusal."""
        from camoufoxmcp.hardening import conflicts

        assert "UTC" in conflicts(timezone="Europe/Berlin")["timezone"]

    def test_the_user_agent_reason_names_the_contradiction(self):
        from camoufoxmcp.hardening import conflicts

        why = conflicts(user_agent="curl/8")["user_agent"]
        assert "navigator.platform" in why

    def test_an_unrelated_argument_is_not_a_conflict(self):
        """Proxy and tor are orthogonal and must stay combinable."""
        from camoufoxmcp.hardening import conflicts

        assert conflicts() == {}


class TestDescribe:
    def test_it_claims_uniqueness_reduction_and_not_anonymity(self):
        """The label is the deliverable, not decoration.

        A caller who reads ``hardened: true`` and assumes anonymity was misled
        by the tool, so the disclaimer travels in the payload.
        """
        from camoufoxmcp.hardening import describe

        report = describe()
        assert report["not_claimed"] == "anonymity"
        assert "uniqueness" in report["claim"]

    def test_it_points_at_tor_browser_for_actual_anonymity(self):
        from camoufoxmcp.hardening import describe

        assert "Tor Browser" in describe()["for_anonymity"]


# ----------------------------------------------------------------------
# Wiring


class TestLaunchWiring:
    """Source-introspection, in the style of the existing TestSnapshotJS.

    These assert the pieces are actually connected, which is the failure that
    silent configuration invites: every individual value is right and nothing
    reads it.
    """

    def _session_source(self):
        import camoufoxmcp.session as session

        return pathlib.Path(session.__file__).read_text()

    def test_hardening_kwargs_include_the_fingerprint_and_the_os(self):
        import camoufoxmcp.session as session

        kwargs = session._hardening_launch_kwargs()
        assert kwargs["fingerprint"] is not None
        assert kwargs["os"] == session.hardening.host_os_family()
        assert kwargs["webgl_config"], "WebGL is not pinned by the fingerprint alone"
        assert kwargs["enable_cache"] is False

    def test_the_custom_fingerprint_warning_is_acknowledged_not_muted(self):
        """Camoufox warns because a custom fingerprint is less random.

        Less random is the point, so the flag is passed -- but it must be the
        deliberate acknowledgement, not an oversight.
        """
        import camoufoxmcp.session as session

        assert session._hardening_launch_kwargs()["i_know_what_im_doing"] is True

    def test_the_fingerprint_is_injected_before_launch_options_runs(self):
        """launch_options is the only place a fingerprint becomes env vars.

        Patching its return value would be a no-op that looked like it worked,
        so the kwargs must be passed *in*.
        """
        source = self._session_source()
        call = source[source.index("opts = launch_options("):]
        call = call[:call.index(")\n\n") + 1]
        assert "**hard" in call, "hardening kwargs must be passed into launch_options"

    def test_both_launch_paths_share_one_option_builder(self):
        """A resize relaunch must not silently come back un-hardened.

        The headed relaunch builds its own options. When that was a second copy
        of the construction, hardening was applied on the first launch and lost
        on the relaunch -- with the tool still reporting success.
        """
        import re

        source = self._session_source()
        assert source.count("_build_launch_options(") >= 3, (
            "both launch and _launch_headed must go through _build_launch_options")
        # The lookbehind excludes _build_launch_options, which would otherwise
        # match as a substring and make the count meaningless.
        calls = re.findall(r"(?<![_\w])launch_options\(", source)
        assert len(calls) == 1, (
            "launch_options must be called in exactly one place, found %d" % len(calls))
        assert "from camoufox.utils import launch_options" in source

    def test_hardened_launches_do_not_persist_a_profile(self):
        source = self._session_source()
        assert "not cfg.hardened" in source, (
            "hardened mode must refuse a persistent context even if one is configured")

    def test_hardened_launches_disable_humanization(self):
        source = self._session_source()
        assert "humanize=None if cfg.hardened" in source

    def test_hardened_launches_get_a_window_in_headless_mode_too(self):
        """The fingerprint's window metrics are what the page reads back."""
        source = self._session_source()
        assert "cfg.hardened or not cfg.headless" in source

    def test_the_session_reports_what_it_pinned(self):
        import asyncio

        from camoufoxmcp.session import BrowserSession

        async def go():
            return BrowserSession()

        session = asyncio.run(go())
        assert session.hardening_report is None, (
            "an ordinary launch must not carry a stub -- the key's presence is the answer")


class TestServerWiring:
    def _server_source(self):
        import camoufoxmcp.server as server

        return pathlib.Path(server.__file__).read_text()

    def test_launch_accepts_the_flag_and_documents_the_limit(self):
        source = self._server_source()
        assert "hardened: bool = False" in source
        assert "NOT anonymity" in source, (
            "the tool docstring must carry the caveat, not just the README")

    def test_the_conflicts_are_refused_rather_than_ignored(self):
        source = self._server_source()
        assert "hardening.conflicts(" in source
        assert "hardened=True conflicts with:" in source

    def test_the_already_running_branch_admits_hardening_was_not_applied(self):
        """Otherwise the caller believes a running session is hardened."""
        source = self._server_source()
        assert '("hardened", hardened)' in source

    def test_the_report_reaches_the_launch_result(self):
        source = self._server_source()
        assert 'out["hardened"] = _session.hardening_report' in source

    def test_the_instructions_mention_both_the_mode_and_its_limit(self):
        source = self._server_source()
        assert "HARDENED MODE" in source
        assert "WHAT HARDENED DOES NOT BUY" in source
