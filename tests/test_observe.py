"""Offline tests for camoufoxmcp.observe and the snapshot upgrades.

The classifier and the check runner are pure functions over dicts, so they are
tested directly with no browser. That is the point of splitting the blocker
probe into "one evaluate returning evidence" plus "a Python function that
judges it" -- the judgement is the part worth testing, and it needs nothing
running to test.
"""

from unittest.mock import MagicMock


class FakeSession:
    """Just enough session for the freshness and console logic."""

    def __init__(self, nav_epoch=0, console=None, ref_signature=None, ref_map=None):
        self._nav_epoch = nav_epoch if isinstance(nav_epoch, dict) else {"p": nav_epoch}
        self._console = console or {}
        self._ref_signature = ref_signature or {}
        self._ref_map = ref_map or {}


def text_evidence(text="", title="", url="https://example.com/", **kwargs):
    ev = {"text": text, "title": title, "url": url,
          "iframes": [], "forms": [], "overlays": [], "scripts": [],
          "has_password_field": False}
    ev.update(kwargs)
    return ev


class TestBlockerClassification:
    def test_clean_page_is_not_blocked(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            text="Welcome to the dashboard. Your reports are ready.",
            title="Dashboard"))
        assert result["blocked"] is False
        assert result["reason"] is None

    def test_cloudflare_interstitial_by_title(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(title="Just a moment..."))
        assert result["blocked"] is True
        assert result["reason"] == "cloudflare"

    def test_cloudflare_turnstile_by_iframe(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            iframes=[{"src": "https://challenges.cloudflare.com/turnstile/v0/api.js",
                      "id": "", "title": "", "w": 300, "h": 65}]))
        assert result["blocked"] is True
        assert result["reason"] == "cloudflare"
        assert any("Turnstile" in s["label"] for s in result["evidence"]["signals"])

    def test_arkose_is_detected(self):
        # Arkose/FunCaptcha is what displaced reCAPTCHA in practice, so a
        # taxonomy without it would miss the case that actually matters.
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            iframes=[{"src": "https://client-api.arkoselabs.com/v2/1.2.3/enforcement.html",
                      "id": "arkose-iframe", "title": "", "w": 400, "h": 400}]))
        assert result["blocked"] is True
        assert result["reason"] == "arkose"

    def test_recaptcha_is_detected(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            iframes=[{"src": "https://www.google.com/recaptcha/api2/anchor",
                      "id": "", "title": "", "w": 304, "h": 78}]))
        assert result["blocked"] is True
        assert result["reason"] == "recaptcha"

    def test_hcaptcha_is_detected(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            scripts=["https://js.hcaptcha.com/1/api.js"]))
        assert result["blocked"] is True
        assert result["reason"] == "hcaptcha"

    def test_generic_bot_check(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            text="We detected unusual traffic from your network. Please try again later."))
        assert result["blocked"] is True
        assert result["reason"] == "bot_check"

    def test_auth_wall_by_text(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            text="Please sign in to continue.", has_password_field=True))
        assert result["blocked"] is True
        assert result["reason"] == "auth_wall"

    def test_consent_overlay_only_counts_when_it_covers_the_viewport(self):
        # A cookie notice in the corner is noise; a full-screen one swallows
        # clicks, which is the failure worth reporting.
        from camoufoxmcp.observe import classify_blockers

        small = classify_blockers(text_evidence(
            overlays=[{"tag": "div", "id": "cookie", "cls": "", "role": "",
                       "coverage": 0.05, "text": "We use cookies"}]))
        assert small["blocked"] is False

        large = classify_blockers(text_evidence(
            overlays=[{"tag": "div", "id": "consent-banner", "cls": "modal fade",
                       "role": "dialog", "coverage": 0.92,
                       "text": "We use cookies to improve your experience."}]))
        assert large["blocked"] is True
        assert large["reason"] == "consent_overlay"
        assert "consent-banner" in large["hint"] or "consent" in large["detail"]

    def test_consent_overlay_reports_the_occluder(self):
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            overlays=[{"tag": "div", "id": "gdpr", "cls": "", "role": "dialog",
                       "coverage": 0.8, "text": "We use cookies"}]))
        signal = result["evidence"]["signals"][0]
        assert signal["occluder"] == "div#gdpr"

    def test_a_challenge_reports_that_tor_will_not_help(self):
        # The hint has to say this, because "route through Tor" is the
        # intuitive move and it makes a challenge harder, not easier.
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(title="Just a moment..."))
        assert "Tor" in result["hint"]
        assert "harder" in result["hint"]

    def test_more_specific_signal_wins_the_reason(self):
        # A Cloudflare challenge page often also mentions "verify you are
        # human"; the verdict should name the specific cause.
        from camoufoxmcp.observe import classify_blockers
        result = classify_blockers(text_evidence(
            title="Just a moment...",
            text="Verify you are human before continuing."))
        assert result["reason"] == "cloudflare"

    def test_malformed_evidence_does_not_raise(self):
        from camoufoxmcp.observe import classify_blockers
        assert classify_blockers({})["blocked"] is False
        assert classify_blockers({"iframes": None, "overlays": None})["blocked"] is False

    def test_probe_failure_is_not_reported_as_blocked(self):
        # A probe that could not run must not look like a blocker: the caller
        # would act on a challenge that is not there.
        from camoufoxmcp.observe import detect_blockers
        page = MagicMock()
        page.evaluate.side_effect = RuntimeError("execution context destroyed")
        result = detect_blockers(page)
        assert result["blocked"] is False
        assert "probe failed" in result["detail"]


class TestMutationBucketing:
    def test_small_changes_stay_in_the_same_bucket(self):
        from camoufoxmcp.observe import MUTATION_BUCKET, mutation_bucket
        assert mutation_bucket(0) == mutation_bucket(MUTATION_BUCKET - 1)

    def test_a_material_change_crosses_a_bucket(self):
        from camoufoxmcp.observe import MUTATION_BUCKET, mutation_bucket
        assert mutation_bucket(0) != mutation_bucket(MUTATION_BUCKET + 1)

    def test_unknown_stays_unknown(self):
        # -1 means "no observer", which must not read as "no mutations".
        from camoufoxmcp.observe import mutation_bucket
        assert mutation_bucket(-1) == -1
        assert mutation_bucket(None) == -1


class TestFreshness:
    def _page(self, mutations):
        page = MagicMock()
        page.evaluate.return_value = mutations
        page.url = "https://example.com/"
        return page

    def test_no_snapshot_is_unknown_not_fresh(self):
        # A ref that was never snapshotted is unverified, not fine.
        from camoufoxmcp.snapshot import ref_freshness
        session = FakeSession()
        result = ref_freshness(session, self._page(0), "p")
        assert result["verdict"] == "unknown"

    def test_unchanged_page_is_fresh(self):
        from camoufoxmcp.snapshot import ref_freshness
        session = FakeSession(nav_epoch={"p": 3}, ref_signature={"p": {
            "nav_epoch": 3, "mutation_bucket": 1, "mutations": 30}})
        result = ref_freshness(session, self._page(30), "p")
        assert result["verdict"] == "fresh"

    def test_navigation_is_hard_stale(self):
        # This is the verdict that refuses the action: after a navigation every
        # ref points at whatever now occupies that position.
        from camoufoxmcp.snapshot import ref_freshness
        session = FakeSession(nav_epoch={"p": 4}, ref_signature={"p": {
            "nav_epoch": 3, "mutation_bucket": 1, "mutations": 30}})
        result = ref_freshness(session, self._page(30), "p")
        assert result["verdict"] == "hard_stale"
        assert "navigated" in result["detail"]

    def test_dom_churn_is_a_warning_not_a_refusal(self):
        from camoufoxmcp.snapshot import ref_freshness
        session = FakeSession(nav_epoch={"p": 3}, ref_signature={"p": {
            "nav_epoch": 3, "mutation_bucket": 1, "mutations": 30}})
        result = ref_freshness(session, self._page(500), "p")
        assert result["verdict"] == "stale_warning"
        assert result["mutations_delta"] == 470

    def test_below_bucket_churn_stays_fresh(self):
        from camoufoxmcp.observe import MUTATION_BUCKET
        from camoufoxmcp.snapshot import ref_freshness
        session = FakeSession(nav_epoch={"p": 3}, ref_signature={"p": {
            "nav_epoch": 3, "mutation_bucket": 0, "mutations": 0}})
        result = ref_freshness(session, self._page(MUTATION_BUCKET - 1), "p")
        assert result["verdict"] == "fresh"


class TestFingerprintDelta:
    def test_navigation_counts_as_changed(self):
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 0, "title": "A"}
        after = {"url": "https://b.test/", "nav_epoch": 2, "mutations": 10, "title": "B"}
        delta = fingerprint_delta(before, after)
        assert delta["changed"] is True
        assert delta["navigated"] is True

    def test_a_fragment_change_moves_the_url_without_replacing_the_document(self):
        # Scroll-spy and anchor links rewrite the hash constantly. Counting
        # that as a navigation would mark every ref stale on any docs site,
        # which teaches the caller to ignore STALE_REF.
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 0, "title": "A"}
        after = {"url": "https://a.test/#x", "nav_epoch": 1, "mutations": 5, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["navigated"] is False
        assert delta["url_changed"] is True
        # It is still a change worth reporting: clicking an anchor did
        # something, and `changed` is the answer to "did my click work?".
        assert delta["changed"] is True

    def test_mutations_crossing_a_bucket_counts_as_changed(self):
        from camoufoxmcp.observe import MUTATION_BUCKET, fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 0, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1,
                 "mutations": MUTATION_BUCKET * 2, "title": "A"}
        assert fingerprint_delta(before, after)["changed"] is True

    def test_one_inserted_node_is_a_change(self):
        # The bug this pins: a raw delta of 1 was compared against the bucket
        # size (25), so clicking a button that appends a single element
        # reported changed=false while the element was demonstrably in the DOM.
        # `changed` is the answer to "did my click do anything?", and one
        # inserted node is a yes.
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 7, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 8, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["mutations_delta"] == 1
        assert delta["changed"] is True
        # ...but it is not material, which is the judgement the bucket is for.
        assert delta["mutations_material"] is False

    def test_churn_within_a_bucket_is_not_material(self):
        from camoufoxmcp.observe import MUTATION_BUCKET, fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 0, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1,
                 "mutations": MUTATION_BUCKET - 1, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["mutations_material"] is False

    def test_crossing_a_bucket_is_material(self):
        from camoufoxmcp.observe import MUTATION_BUCKET, fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 0, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1,
                 "mutations": MUTATION_BUCKET + 1, "title": "A"}
        assert fingerprint_delta(before, after)["mutations_material"] is True

    def test_a_decrease_in_mutations_is_not_a_change(self):
        # The observer counter is monotonic, so this should not happen; if it
        # ever does, reporting a change would be inventing one.
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 40, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1, "mutations": 5, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["mutations_delta"] == -35
        assert delta["changed"] is False
        assert delta["mutations_material"] is False

    def test_unknown_mutations_do_not_claim_materiality(self):
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": -1, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1, "mutations": -1, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["mutations_observed"] is False
        assert delta["mutations_material"] is False
        assert delta["mutations_delta"] is None

    def test_unknown_mutations_are_reported_as_unobserved(self):
        from camoufoxmcp.observe import fingerprint_delta
        before = {"url": "https://a.test/", "nav_epoch": 1, "mutations": -1, "title": "A"}
        after = {"url": "https://a.test/", "nav_epoch": 1, "mutations": -1, "title": "A"}
        delta = fingerprint_delta(before, after)
        assert delta["mutations_observed"] is False
        assert delta["changed"] is False


class TestRunChecks:
    def _page(self, url="https://example.com/", text="hello world", status=200):
        page = MagicMock()
        page.url = url
        page.title.return_value = "Example"

        def _evaluate(script, *args, **kwargs):
            if "responseStatus" in script:
                return status
            if "innerText" in script:
                return text
            return None

        page.evaluate.side_effect = _evaluate
        return page

    def test_passing_checks_report_passed(self):
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(), FakeSession(), "p", {
            "url_matches": r"example\.com",
            "text_present": "hello",
            "text_absent": "goodbye",
            "http_status": 200,
        })
        assert result["passed"] is True
        assert result["checked"] == 4
        assert result["failed"] == []

    def test_failing_check_names_itself_and_carries_evidence(self):
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(), FakeSession(), "p", {"text_present": "missing"})
        assert result["passed"] is False
        assert result["failed"] == ["text_present"]
        check = result["checks"][0]
        assert "missing" in check["evidence"]["missing"]
        assert check["expected"] == ["missing"]

    def test_text_absent_fails_when_the_text_is_there(self):
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(text="an error occurred"),
                            FakeSession(), "p", {"text_absent": "error"})
        assert result["passed"] is False

    def test_unrecognised_check_name_fails_rather_than_being_ignored(self):
        # A typo'd check that silently does nothing would read as a pass, which
        # is the worst possible outcome for a verification tool.
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(), FakeSession(), "p", {"text_presentt": "x"})
        assert result["passed"] is False
        assert result["unknown"] == ["text_presentt"]

    def test_false_and_none_values_are_skipped_not_failed(self):
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(), FakeSession(), "p", {
            "text_present": "hello",
            "no_blockers": False,
            "url_matches": None,
        })
        assert result["passed"] is True
        assert result["checked"] == 1

    def test_console_errors_are_scoped_to_the_given_index(self):
        from camoufoxmcp.observe import run_checks
        session = FakeSession(console={"p": [
            {"type": "error", "text": "old error from page load"},
            {"type": "error", "text": "new error from my action"},
        ]})
        # Index 1 means "ignore everything logged before this point".
        result = run_checks(self._page(), session, "p",
                            {"no_console_errors": True}, console_since=1)
        assert result["passed"] is False
        assert result["checks"][0]["evidence"]["error_count"] == 1
        assert "my action" in result["checks"][0]["evidence"]["console_errors"][0]

    def test_console_errors_before_the_index_do_not_fail_the_check(self):
        from camoufoxmcp.observe import run_checks
        session = FakeSession(console={"p": [{"type": "error", "text": "page load error"}]})
        result = run_checks(self._page(), session, "p",
                            {"no_console_errors": True}, console_since=1)
        assert result["passed"] is True

    def test_http_status_unavailable_is_unverified_not_a_pass(self):
        # Passing by default when the engine cannot report a status would make
        # the check worthless on exactly the engines that lack it.
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(status=None), FakeSession(), "p", {"http_status": 200})
        assert result["passed"] is False
        assert "unavailable" in result["checks"][0]["evidence"]["reason"]

    def test_url_matches_accepts_a_list_and_passes_on_any(self):
        from camoufoxmcp.observe import run_checks
        result = run_checks(self._page(url="https://app.example.com/home"),
                            FakeSession(), "p",
                            {"url_matches": [r"nope\.test", r"example\.com"]})
        assert result["passed"] is True

    def test_element_absent_fails_when_the_element_exists(self):
        from camoufoxmcp.observe import run_checks
        page = self._page()
        page.locator.return_value.count.return_value = 3
        session = FakeSession(ref_map={"p": {"e1": {"selector": "aria-ref=e1"}}})
        result = run_checks(page, session, "p", {"element_absent": "@e1"})
        assert result["passed"] is False
        assert result["checks"][0]["evidence"]["present_but_should_be_absent"] == ["@e1"]

    def test_no_blockers_check_uses_the_classifier(self):
        from camoufoxmcp.observe import run_checks
        page = self._page()
        page.evaluate.side_effect = lambda script, *a, **k: (
            {"text": "", "title": "Just a moment...", "url": "https://x.test/",
             "iframes": [], "forms": [], "overlays": [], "scripts": [],
             "has_password_field": False}
            if "elementFromPoint" in script else
            "hello" if "innerText" in script else None
        )
        result = run_checks(page, FakeSession(), "p", {"no_blockers": True})
        assert result["passed"] is False
        assert result["checks"][0]["evidence"]["reason"] == "cloudflare"


class TestWaitForChecks:
    def test_polls_until_the_condition_holds(self):
        from camoufoxmcp.observe import wait_for_checks
        page = MagicMock()
        page.url = "https://example.com/"
        calls = {"n": 0}

        def _evaluate(script, *a, **k):
            if "innerText" in script:
                calls["n"] += 1
                return "ready" if calls["n"] >= 3 else "loading"
            return None

        page.evaluate.side_effect = _evaluate
        result = wait_for_checks(page, FakeSession(), "p",
                                 {"text_present": "ready"}, timeout_ms=3000, poll_ms=10)
        assert result["passed"] is True
        assert result["attempts"] >= 3

    def test_reports_a_timeout_rather_than_raising(self):
        from camoufoxmcp.observe import wait_for_checks
        page = MagicMock()
        page.url = "https://example.com/"
        page.evaluate.side_effect = lambda script, *a, **k: "never" if "innerText" in script else None
        result = wait_for_checks(page, FakeSession(), "p",
                                 {"text_present": "ready"}, timeout_ms=60, poll_ms=10)
        assert result["passed"] is False
        assert result["timed_out"] is True


class TestWiring:
    """The JS constants have to actually be wired up, not merely defined."""

    def test_state_probe_js_is_an_occlusion_check(self):
        from camoufoxmcp.snapshot import _STATE_PROBE_JS
        assert "elementFromPoint" in _STATE_PROBE_JS
        assert "occluded" in _STATE_PROBE_JS
        assert "occluder" in _STATE_PROBE_JS

    def test_state_probe_redacts_password_values(self):
        # A snapshot lands in a transcript, so a password value must never
        # travel in one.
        from camoufoxmcp.snapshot import _STATE_PROBE_JS
        assert "password" in _STATE_PROBE_JS
        assert "redacted" in _STATE_PROBE_JS

    def test_mutation_observer_js_installs_a_observer(self):
        from camoufoxmcp.observe import INSTALL_MUTATION_OBSERVER_JS
        assert "MutationObserver" in INSTALL_MUTATION_OBSERVER_JS
        assert "characterData: false" in INSTALL_MUTATION_OBSERVER_JS

    def test_take_snapshot_probes_state_and_stamps_a_signature(self):
        import inspect
        from camoufoxmcp import snapshot as snap_mod
        src = inspect.getsource(snap_mod.take_snapshot)
        assert "_probe_states" in src
        assert "stamp_ref_signature" in src

    def test_session_handler_tracks_main_frame_navigation(self):
        import inspect
        from camoufoxmcp.session import BrowserSession
        src = inspect.getsource(BrowserSession._setup_page_handlers)
        assert "framenavigated" in src
        # Main frame only: bumping on subframe loads would mark every ref
        # permanently stale and train the caller to ignore the warning.
        assert "main_frame" in src

    def test_only_actionable_roles_are_probed(self):
        from camoufoxmcp.snapshot import ACTIONABLE_ROLES
        assert "button" in ACTIONABLE_ROLES
        assert "textbox" in ACTIONABLE_ROLES
        # A paragraph has no actionable state, so it must not cost a round trip.
        assert "paragraph" not in ACTIONABLE_ROLES
        assert "heading" not in ACTIONABLE_ROLES

    def test_state_flags_explain_blockers_only(self):
        from camoufoxmcp.snapshot import state_flags
        assert state_flags({"enabled": False}) == ["disabled"]
        assert state_flags({"occluded": True, "occluder": {"tag": "div", "id": "banner"}}) == [
            "occluded by div#banner"]
        assert state_flags({"visible": True, "in_viewport": False}) == ["off-screen"]
        assert state_flags({"visible": True, "in_viewport": True, "enabled": True}) == []
        # A probe that errored must not produce a misleading flag.
        assert state_flags({"error": "boom", "enabled": False}) == []

    def test_occluder_description_prefers_id_over_class(self):
        from camoufoxmcp.snapshot import _describe_occluder
        assert _describe_occluder({"tag": "div", "id": "x", "cls": "a b"}) == "div#x"
        assert _describe_occluder({"tag": "span", "id": "", "cls": "a b"}) == "span.a"
        assert _describe_occluder(None) == "something"


class TestProxyParsing:
    def test_splits_credentials_out_of_the_url(self):
        from camoufoxmcp.session import _parse_proxy
        server, user, password = _parse_proxy("http://alice:s3cret@proxy.test:8080")
        assert server == "http://proxy.test:8080"
        assert user == "alice"
        assert password == "s3cret"

    def test_handles_a_proxy_without_credentials(self):
        from camoufoxmcp.session import _parse_proxy
        assert _parse_proxy("http://proxy.test:8080") == ("http://proxy.test:8080", None, None)

    def test_preserves_the_socks_scheme(self):
        from camoufoxmcp.session import _parse_proxy
        server, user, password = _parse_proxy("socks5://u:p@127.0.0.1:19050")
        assert server == "socks5://127.0.0.1:19050"
        assert (user, password) == ("u", "p")

    def test_percent_encoded_credentials_are_decoded(self):
        from camoufoxmcp.session import _parse_proxy
        _server, user, password = _parse_proxy("http://a%40b:p%3Aw@proxy.test:8080")
        assert user == "a@b"
        assert password == "p:w"

    def test_empty_proxy_is_empty(self):
        from camoufoxmcp.session import _parse_proxy
        assert _parse_proxy("") == ("", None, None)
        assert _parse_proxy(None) == ("", None, None)

    def test_malformed_proxy_is_passed_through_unchanged(self):
        # Better to hand Playwright what the caller wrote than to silently
        # rewrite it into something else.
        from camoufoxmcp.session import _parse_proxy
        assert _parse_proxy("not a url")[0] == "http://not a url"
        assert _parse_proxy("http://")[0] == "http://"
