"""Tests for CamoufoxMCP v0.6.0 — Playwright MCP quality."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from unittest.mock import MagicMock, patch


class TestBrowserSession:
    """Test BrowserSession lifecycle."""

    def test_session_not_running_initially(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        assert not session.is_running

    def test_session_config_defaults(self):
        from camoufoxmcp.session import SessionConfig
        cfg = SessionConfig()
        assert cfg.headless is True
        assert cfg.humanize is True
        assert cfg.locale is None
        assert cfg.proxy is None

    def test_page_not_found_error(self):
        from camoufoxmcp.session import BrowserSession, PageNotFoundError
        session = BrowserSession()
        with pytest.raises(PageNotFoundError):
            session.get_page("nonexistent")

    def test_list_pages_empty(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        assert session.list_pages() == []

    def test_force_cleanup(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        session._browser = MagicMock()
        session._context = MagicMock()
        session._pages = {"page_abc": MagicMock()}
        session._page_ids = ["page_abc"]
        session._active_page_id = "page_abc"
        session._dialogs = {"page_abc": [{"type": "alert", "message": "test"}]}
        session._console = {"page_abc": [{"type": "log", "text": "hello"}]}
        session._force_cleanup()
        assert session._browser is None
        assert session._context is None
        assert session._pages == {}
        assert session._page_ids == []
        assert session._active_page_id is None
        assert session._dialogs == {}
        assert session._console == {}

    def test_active_page_fallback(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page1 = MagicMock()
        mock_page1.is_closed.return_value = False
        mock_page1.url = "https://example.com"
        session._pages = {"p1": mock_page1}
        session._page_ids = ["p1"]
        assert session.active_page_id == "p1"

    def test_dialog_storage(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page = MagicMock()
        mock_page.is_closed.return_value = False
        session._pages = {"p1": mock_page}
        session._page_ids = ["p1"]
        session._dialogs = {"p1": [{"type": "alert", "message": "hello"}]}
        result = session.get_dialogs("p1")
        assert result["status"] == "ok"
        assert result["count"] == 1
        assert result["dialogs"][0]["message"] == "hello"

    def test_dialog_filter(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page = MagicMock()
        mock_page.is_closed.return_value = False
        session._pages = {"p1": mock_page}
        session._page_ids = ["p1"]
        session._dialogs = {"p1": [
            {"type": "alert", "message": "error 500"},
            {"type": "confirm", "message": "are you sure?"},
        ]}
        result = session.get_dialogs("p1", filter_text="error")
        assert result["count"] == 1
        assert "error 500" in result["dialogs"][0]["message"]

    def test_console_storage(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page = MagicMock()
        mock_page.is_closed.return_value = False
        session._pages = {"p1": mock_page}
        session._page_ids = ["p1"]
        session._console = {"p1": [{"type": "error", "text": "TypeError: x is undefined"}]}
        result = session.get_console("p1")
        assert result["status"] == "ok"
        assert result["count"] == 1

    def test_console_clear(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page = MagicMock()
        mock_page.is_closed.return_value = False
        session._pages = {"p1": mock_page}
        session._page_ids = ["p1"]
        session._console = {"p1": [{"type": "log", "text": "test"}]}
        result = session.get_console("p1", clear=True)
        assert result["count"] == 1
        assert session._console["p1"] == []

    def test_headed_launch_passes_viewport_as_camoufox_window(self):
        """Headed mode must align Camoufox's spoofed window size with Playwright viewport.

        Without this, JS sees the random fingerprint window size (often 2560px wide)
        while the visible headed window is narrower, causing centered login forms to
        render off-screen or look zoomed/clipped on macOS Retina displays.
        """
        from camoufoxmcp.session import BrowserSession, SessionConfig

        session = BrowserSession()
        fake_context = MagicMock()
        fake_manager = MagicMock()
        fake_manager.__enter__.return_value = fake_context

        with patch("camoufox.sync_api.Camoufox", return_value=fake_manager), \
             patch("camoufox.utils.launch_options", return_value={}) as mock_launch_options:
            with ThreadPoolExecutor(max_workers=1) as executor:
                asyncio.run(session.launch(
                    SessionConfig(headless=False, viewport={"width": 1280, "height": 800}),
                    executor,
                ))

        mock_launch_options.assert_called_once()
        assert mock_launch_options.call_args.kwargs["window"] == (1280, 800)

    def test_launch_uses_persistent_context_for_user_data_dir(self, tmp_path):
        """user_data_dir must use Camoufox persistent_context, not BrowserType.launch()."""
        from camoufoxmcp.session import BrowserSession, SessionConfig

        session = BrowserSession()
        fake_context = MagicMock()
        fake_manager = MagicMock()
        fake_manager.__enter__.return_value = fake_context
        profile = tmp_path / "profile"

        with patch("camoufox.sync_api.Camoufox", return_value=fake_manager) as mock_camoufox, \
             patch("camoufox.utils.launch_options", return_value={}) as mock_launch_options:
            with ThreadPoolExecutor(max_workers=1) as executor:
                asyncio.run(session.launch(
                    SessionConfig(
                        headless=False,
                        viewport={"width": 1280, "height": 800},
                        user_data_dir=str(profile),
                    ),
                    executor,
                ))

        assert profile.exists()
        mock_launch_options.assert_called_once()
        mock_camoufox.assert_called_once()
        kwargs = mock_camoufox.call_args.kwargs
        assert kwargs["persistent_context"] is True
        assert kwargs["from_options"]["user_data_dir"] == str(profile)

    def test_macos_properties_workaround_links_resource_file(self, tmp_path):
        """Camoufox macOS Resources/properties.json is exposed at MacOS/properties.json."""
        from camoufoxmcp import session as session_mod

        root = tmp_path / "camoufox"
        resources = root / "Camoufox.app" / "Contents" / "Resources"
        resources.mkdir(parents=True)
        (resources / "properties.json").write_text('{"ok": true}')

        with patch("camoufox.pkgman.camoufox_path", return_value=root):
            session_mod._ensure_macos_properties_json()

        macos_properties = root / "Camoufox.app" / "Contents" / "MacOS" / "properties.json"
        assert macos_properties.exists()
        assert macos_properties.read_text() == '{"ok": true}'


class TestSnapshot:
    """Test snapshot and ref resolution."""

    def test_resolve_ref_from_stored_map(self):
        from camoufoxmcp.snapshot import resolve_ref
        session = MagicMock()
        session._ref_map = {
            "page_abc": {
                "e1": {"selector": "#my-button", "tag": "button", "role": "button", "label": "Click me"},
                "e2": {"selector": "input[name='q']", "tag": "input", "role": "textbox", "label": "Search"},
            }
        }
        clean_ref, selector, frame_idx = resolve_ref(session, "page_abc", "@e1")
        assert clean_ref == "e1"
        assert selector == "#my-button"
        assert frame_idx is None

    def test_resolve_ref_strips_at(self):
        from camoufoxmcp.snapshot import resolve_ref
        session = MagicMock()
        session._ref_map = {}
        clean_ref, _, _ = resolve_ref(session, "page_abc", "@e3")
        assert clean_ref == "e3"

    def test_resolve_ref_fallback(self):
        from camoufoxmcp.snapshot import resolve_ref
        session = MagicMock()
        session._ref_map = {}
        clean_ref, selector, _ = resolve_ref(session, "page_unknown", "e99")
        assert clean_ref == "e99"
        assert "e99" in selector

    def test_resolve_ref_frame_index(self):
        from camoufoxmcp.snapshot import resolve_ref
        session = MagicMock()
        session._ref_map = {}
        clean_ref, selector, frame_idx = resolve_ref(session, "page_abc", "f2")
        assert clean_ref == "f2"
        assert frame_idx == 2
        assert "iframe" in selector

    def test_take_snapshot_passes_full_flag_into_aria(self):
        from camoufoxmcp.snapshot import take_snapshot

        page = MagicMock()
        page.aria_snapshot.return_value = "- textbox \"x\" [ref=e1]\n"
        session = MagicMock()
        session._ref_map = {}

        result = take_snapshot(page, "page_abc", session, full=True, max_length=12000)

        # Must call page.aria_snapshot with mode='ai'
        page.aria_snapshot.assert_called_once_with(mode="ai")
        assert result["status"] == "ok"
        assert result["interactive_elements"] == 1
        assert "e1" in result["refs"]


class TestMarkdownExtraction:
    """Test clean markdown extraction."""

    def test_extract_markdown_basic(self):
        from camoufoxmcp.markdown import extract_markdown
        page = MagicMock()
        page.content.return_value = "<html><body><h1>Hello</h1><p>World</p></body></html>"
        result = extract_markdown(page)
        assert result["status"] == "ok"
        assert "Hello" in result["content"]
        assert "World" in result["content"]

    def test_extract_markdown_strips_scripts(self):
        from camoufoxmcp.markdown import extract_markdown
        page = MagicMock()
        page.content.return_value = (
            "<html><body>"
            "<script>alert('bad')</script>"
            "<h1>Safe</h1>"
            "</body></html>"
        )
        result = extract_markdown(page)
        assert result["status"] == "ok"
        assert "Safe" in result["content"]
        assert "alert" not in result["content"]

    def test_extract_markdown_fallback_when_no_trafilatura(self):
        from camoufoxmcp.markdown import _extract_markdown_fallback
        html = "<html><body><h1>Title</h1><p>Paragraph <strong>bold</strong></p></body></html>"
        text = _extract_markdown_fallback(html)
        assert "Title" in text
        assert "Paragraph" in text
        assert "**bold**" in text

    def test_markdown_links(self):
        from camoufoxmcp.markdown import _extract_markdown_fallback
        html = '<html><body><a href="/api">API Docs</a></body></html>'
        text = _extract_markdown_fallback(html)
        assert "[API Docs](/api)" in text


class TestSnapshotJS:
    """Test the aria_snapshot-based snapshot logic (v0.7+)."""

    def test_snapshot_module_exports(self):
        # New module must expose the parser and a take_snapshot function
        from camoufoxmcp.snapshot import _parse_aria_snapshot, take_snapshot, resolve_ref
        assert callable(take_snapshot)
        assert callable(resolve_ref)
        assert callable(_parse_aria_snapshot)

    def test_snapshot_uses_aria_snapshot(self):
        # Confirm we're calling the browser's native a11y tree, not a JS walker
        from camoufoxmcp import snapshot as snap_mod
        import inspect
        src = inspect.getsource(snap_mod.take_snapshot)
        assert "aria_snapshot" in src
        # We no longer ship a SNAPSHOT_JS constant
        assert not hasattr(snap_mod, "SNAPSHOT_JS"), "stale SNAPSHOT_JS constant should be removed"

    def test_snapshot_returns_useful_refs(self):
        from camoufoxmcp.snapshot import _parse_aria_snapshot
        sample = '''- main:
  - textbox "Email" [ref=e1]
  - textbox "Password" [ref=e2]
  - button "Sign in" [ref=e3] [cursor=pointer]
'''
        refs, _ = _parse_aria_snapshot(sample)
        assert len(refs) == 3
        by_ref = {r["ref"]: r for r in refs}
        assert by_ref["e1"]["role"] == "textbox"
        assert by_ref["e1"]["name"] == "Email"
        assert by_ref["e2"]["role"] == "textbox"
        assert by_ref["e3"]["role"] == "button"
        assert by_ref["e3"]["name"] == "Sign in"  # [cursor=pointer] stripped

    def test_snapshot_handles_modifiers_and_ellipsis(self):
        from camoufoxmcp.snapshot import _parse_aria_snapshot
        # Common modifier combinations from the aria-snapshot spec
        sample = '''- heading "Title" [ref=e1] [level=1]
- link "Help" [ref=e2] [cursor=pointer]:
  - /url: https://x
- button "More" [ref=e3] [cursor=pointer]: ...
- paragraph [ref=e4]: inline child text
- textbox "Phone" [ref=e5] [active]
'''
        refs, _ = _parse_aria_snapshot(sample)
        by_ref = {r["ref"]: r for r in refs}
        assert by_ref["e1"]["name"] == "Title"  # [level=1] stripped
        assert by_ref["e2"]["name"] == "Help"   # [cursor=pointer] + : stripped
        assert by_ref["e3"]["name"] == "More"   # [cursor=pointer]: ... stripped
        assert by_ref["e4"]["role"] == "paragraph"
        assert by_ref["e4"]["name"] is None     # role only, colon-tail dropped
        assert by_ref["e5"]["name"] == "Phone"  # [active] stripped


class TestCloudflareDetection:
    """Test CF challenge detection."""

    def test_is_cf_challenge_true_iuam(self):
        from camoufoxmcp.cloudscraper_bridge import _is_cf_challenge_html
        assert _is_cf_challenge_html("<html><head><title>Just a moment...</title></head><body></body></html>")

    def test_is_cf_challenge_true_chl_opt(self):
        from camoufoxmcp.cloudscraper_bridge import _is_cf_challenge_html
        assert _is_cf_challenge_html(
            '<html><script>window._cf_chl_opt={cType: "managed"}; challenges.cloudflare.com</script></html>'
        )

    def test_is_cf_challenge_false_normal(self):
        from camoufoxmcp.cloudscraper_bridge import _is_cf_challenge_html
        assert not _is_cf_challenge_html("<html><head><title>My Site</title></head><body>Content</body></html>")


class TestServerCreation:
    """Test server can be created."""

    @patch("camoufoxmcp.server._session")
    def test_create_server_returns_fastmcp(self, mock_session):
        from camoufoxmcp.server import create_server
        mcp = create_server()
        assert mcp is not None
        # FastMCP has a name
        assert hasattr(mcp, "name")
        assert mcp.name == "camoufox"

    @patch("camoufoxmcp.server._session")
    def test_resolve_page_no_active(self, mock_session):
        from camoufoxmcp.server import _resolve_page
        from camoufoxmcp.session import BrowserSessionError
        mock_session.active_page_id = None
        with pytest.raises(BrowserSessionError, match="No active page"):
            _resolve_page()

    @patch("camoufoxmcp.server._session")
    def test_resolve_page_explicit(self, mock_session):
        from camoufoxmcp.server import _resolve_page
        mock_page = MagicMock()
        mock_session.get_page.return_value = mock_page
        page, pid = _resolve_page("my_page_id")
        assert pid == "my_page_id"
        mock_session.get_page.assert_called_once_with("my_page_id")


class TestViewport:
    """Test viewport resize and screen detection."""

    def test_detect_screen_size_returns_tuple(self):
        from camoufoxmcp.session import _detect_screen_size
        w, h = _detect_screen_size()
        assert isinstance(w, int)
        assert isinstance(h, int)
        assert w > 0
        assert h > 0

    def test_random_viewport_returns_dict(self):
        from camoufoxmcp.session import _random_viewport
        vp = _random_viewport()
        assert "width" in vp and "height" in vp
        assert vp["width"] > 0 and vp["height"] > 0

    def test_resize_viewport_stores_and_updates(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page1 = MagicMock()
        mock_page1.is_closed.return_value = False
        mock_page2 = MagicMock()
        mock_page2.is_closed.return_value = False
        session._browser = MagicMock()
        session._context = MagicMock()
        session._context.pages = [mock_page1, mock_page2]
        session._executor = MagicMock()
        session._pages = {"p1": mock_page1, "p2": mock_page2}

        result = session.resize_viewport_sync(1280, 720)
        assert result["status"] == "resized"
        assert result["width"] == 1280
        assert result["height"] == 720
        assert result["pages_affected"] == 2
        assert session._current_viewport == {"width": 1280, "height": 720}
        mock_page1.set_viewport_size.assert_called_once_with({"width": 1280, "height": 720})
        mock_page2.set_viewport_size.assert_called_once_with({"width": 1280, "height": 720})

    def test_resize_viewport_auto_detect(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        mock_page = MagicMock()
        mock_page.is_closed.return_value = False
        session._browser = MagicMock()
        session._context = MagicMock()
        session._context.pages = [mock_page]
        session._executor = MagicMock()

        result = session.resize_viewport_sync(0, 0)
        assert result["status"] == "resized"
        assert result["width"] > 0
        assert result["height"] > 0
        assert session._current_viewport is not None


class TestHeaderScopeMatching:
    """host_in_scope — the boundary that decides who sees your header."""

    def test_exact_host_matches(self):
        from camoufoxmcp.session import host_in_scope
        assert host_in_scope("example.com", ["example.com"])

    def test_subdomain_matches(self):
        from camoufoxmcp.session import host_in_scope
        assert host_in_scope("www.example.com", ["example.com"])
        assert host_in_scope("a.b.example.com", ["example.com"])

    def test_leading_dot_is_accepted(self):
        # People copy this form out of cookie banners and DNS zones.
        from camoufoxmcp.session import host_in_scope
        assert host_in_scope("www.example.com", [".example.com"])
        assert host_in_scope("example.com", [".example.com"])

    def test_lookalike_domain_does_not_match(self):
        # The failure this guards: str.endswith("example.com") is True for
        # "notexample.com", so a naive check leaks the header to a domain that
        # merely ends with the same characters.
        from camoufoxmcp.session import host_in_scope
        assert not host_in_scope("notexample.com", ["example.com"])
        assert not host_in_scope("evil-example.com", ["example.com"])

    def test_empty_scope_matches_nothing(self):
        # Empty means "no scoping", which the caller handles; this function must
        # not quietly answer True and turn an unset scope into "send everywhere".
        from camoufoxmcp.session import host_in_scope
        assert not host_in_scope("example.com", [])
        assert not host_in_scope("example.com", None)

    def test_case_insensitive(self):
        from camoufoxmcp.session import host_in_scope
        assert host_in_scope("WWW.Example.COM", ["example.com"])


class TestHeaderMerging:
    """merge_headers — what actually goes on the wire for one request."""

    def test_adds_header_on_in_scope_host(self):
        from camoufoxmcp.session import merge_headers
        out = merge_headers({}, {"HackerOne": "me"}, "example.com", ["example.com"])
        assert out["HackerOne"] == "me"

    def test_withholds_header_from_out_of_scope_host(self):
        from camoufoxmcp.session import merge_headers
        out = merge_headers({}, {"HackerOne": "me"}, "cdn.other.com", ["example.com"])
        assert "HackerOne" not in out

    def test_strips_pre_existing_header_on_out_of_scope_host(self):
        # A header that arrived some other way -- an earlier context-wide
        # setting, a service worker -- must not survive on an excluded host.
        from camoufoxmcp.session import merge_headers
        out = merge_headers({"hackerone": "me"}, {"HackerOne": "me"},
                            "cdn.other.com", ["example.com"])
        assert not any(k.lower() == "hackerone" for k in out)

    def test_removal_is_case_insensitive(self):
        # Playwright reports header names lowercased while callers write them
        # however they like. Without this, the header goes out twice.
        from camoufoxmcp.session import merge_headers
        out = merge_headers({"hackerone": "old"}, {"HackerOne": "new"},
                            "example.com", ["example.com"])
        values = [v for k, v in out.items() if k.lower() == "hackerone"]
        assert values == ["new"]

    def test_unrelated_headers_are_preserved(self):
        from camoufoxmcp.session import merge_headers
        out = merge_headers({"accept": "text/html"}, {"HackerOne": "me"},
                            "example.com", ["example.com"])
        assert out["accept"] == "text/html"
        assert out["HackerOne"] == "me"


class TestSetHttpHeaders:
    """The session-level application, against a mocked context."""

    def test_defaults_are_off(self):
        from camoufoxmcp.session import SessionConfig
        cfg = SessionConfig()
        assert cfg.http_headers is None
        assert cfg.header_scope is None

    def test_unscoped_uses_context_wide_mechanism(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        session._context = MagicMock()
        result = session._apply_http_headers_sync({"X-A": "1"}, None)
        assert result["scoped"] is False
        assert result["headers"] == ["X-A"]
        session._context.set_extra_http_headers.assert_called_with({"X-A": "1"})
        session._context.route.assert_not_called()
        # The disclosure risk is real and easy to reach by omitting an argument,
        # so the unscoped path says so rather than reporting a clean success.
        assert "warning" in result

    def test_scoped_uses_routing_and_not_context_headers(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        session._context = MagicMock()
        result = session._apply_http_headers_sync({"X-A": "1"}, ["example.com"])
        assert result["scoped"] is True
        assert result["scope"] == ["example.com"]
        session._context.route.assert_called_once()
        # Any context-wide value must be cleared, or the header would ride on
        # every host the page touches and the scope would mean nothing.
        session._context.set_extra_http_headers.assert_called_with({})

    def test_clearing_removes_both_mechanisms(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        session._context = MagicMock()
        session._apply_http_headers_sync({"X-A": "1"}, ["example.com"])
        session._context.reset_mock()
        result = session._apply_http_headers_sync(None, None)
        assert result["status"] == "cleared"
        session._context.unroute.assert_called_with("**/*")
        session._context.set_extra_http_headers.assert_called_with({})
        assert session._header_route_installed is False

    def test_get_headers_masks_values_by_default(self):
        from camoufoxmcp.session import BrowserSession
        session = BrowserSession()
        session._context = MagicMock()
        session._apply_http_headers_sync({"Authorization": "Bearer supersecret"},
                                         ["example.com"])
        masked = session.get_http_headers()
        assert "supersecret" not in str(masked)
        assert masked["names"] == ["Authorization"]
        assert "supersecret" in str(session.get_http_headers(reveal=True))


class TestEvaluateHasNoTimeout:
    """camoufox_evaluate must not advertise a timeout it cannot deliver.

    It used to accept `timeout` and pass it to `Page.evaluate`, which rejects
    it -- so every call using a function or async expression raised
    `TypeError: got an unexpected keyword argument 'timeout'`, which is to say
    the parameter broke the exact forms it appeared to support. The measured
    alternative, `page.set_default_timeout`, does not bound `evaluate` either:
    a three-second expression returned despite a 400 ms default.

    So the parameter was removed rather than fixed, and these tests hold that
    line in both directions -- the tool must not take it back, and the
    underlying limitation must still be what it was measured to be.
    """

    def _server_source(self):
        import pathlib
        import camoufoxmcp.server as server
        return pathlib.Path(server.__file__).read_text()

    def test_the_playwright_limitation_still_holds(self):
        """If a future Playwright adds a timeout, this test says so.

        That is the point of asserting against the installed signature rather
        than against a comment: the reason for the missing parameter expires
        with the library, and the failure here is the reminder to revisit it.
        """
        import inspect
        from playwright.sync_api import Page

        parameters = inspect.signature(Page.evaluate).parameters
        assert "timeout" not in parameters, (
            "Playwright's Page.evaluate now accepts a timeout (%r) -- the "
            "parameter can be reinstated and this decision revisited"
            % (list(parameters),))

    def test_the_tool_does_not_take_a_timeout(self):
        import asyncio
        from camoufoxmcp.server import create_server

        tools = {t.name: t for t in asyncio.run(create_server().list_tools())}
        assert "camoufox_evaluate" in tools
        schema = tools["camoufox_evaluate"].inputSchema
        assert "timeout" not in schema.get("properties", {}), (
            "camoufox_evaluate advertises a timeout parameter it cannot honour")

    def test_no_call_site_passes_timeout_to_evaluate(self):
        """Belt and braces: the schema and the call must not drift apart."""
        source = self._server_source()
        tool = source[source.index("async def camoufox_evaluate"):]
        tool = tool[:tool.index("async def ", 10)]
        assert "page.evaluate(expression)" in tool
        assert "timeout=timeout" not in tool

    def test_the_docs_name_the_real_workaround(self):
        """A missing parameter with no alternative is just a missing feature."""
        source = self._server_source()
        assert "Promise.race" in source, (
            "the docstring must give the in-page deadline idiom, since there is "
            "no way to impose one from outside")

    def test_the_instructions_string_no_longer_promises_a_timeout(self):
        source = self._server_source()
        assert "camoufox_evaluate(page_id, expression, timeout)" not in source


class TestReadmeToolCount:
    """The README's tool count is a claim about the code, so measure it.

    This drifted twice: the README said 39 while the server registered 38, and
    adding two tools carried the bad number forward to 41. Both are the same
    failure -- a figure that was true once, edited by hand, and never checked.
    A count in prose cannot be kept honest by being careful.
    """

    def _registered(self):
        import asyncio
        from camoufoxmcp.server import create_server
        return sorted(t.name for t in asyncio.run(create_server().list_tools()))

    def _readme(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        return (root / "README.md").read_text()

    def test_readme_total_matches_registered_tools(self):
        import re
        match = re.search(r"##\s*Tools\s*\((\d+)\s+total\)", self._readme())
        assert match, "README no longer has a '## Tools (N total)' heading"
        claimed = int(match.group(1))
        actual = len(self._registered())
        assert claimed == actual, (
            "README claims %d tools, server registers %d" % (claimed, actual))

    def test_architecture_line_matches_registered_tools(self):
        import re
        match = re.search(r"server\.py\s*#\s*FastMCP server \+ (\d+) tool", self._readme())
        assert match, "README architecture tree no longer states a tool count"
        claimed = int(match.group(1))
        actual = len(self._registered())
        assert claimed == actual, (
            "README architecture line claims %d, server registers %d"
            % (claimed, actual))

    def test_header_tools_are_documented(self):
        """A tool nobody can discover is not shipped."""
        readme = self._readme()
        for name in self._registered():
            if name.startswith("camoufox_set_headers") or \
               name.startswith("camoufox_get_headers"):
                assert name in readme, "%s is registered but absent from README" % name


def _tool_dict(blocks):
    """Pull the returned dict out of call_tool's ContentBlocks."""
    for item in (blocks if isinstance(blocks, (list, tuple)) else [blocks]):
        if isinstance(item, tuple):
            for part in item:
                if isinstance(part, dict):
                    return part
        elif isinstance(item, dict):
            return item
        else:
            meta = getattr(item, "meta", None)
            if isinstance(meta, dict):
                return meta
    return {}


class TestFailureExplainsTheTargetState:
    """click/type/select/hover must say why they failed, not what to go check.

    All four returned the same generic sentence — "If the element is covered by
    an overlay, camoufox_snapshot marks it [occluded by ...]" — and no
    target_state, while camoufox_act probed the element and reported "covered by
    div#overlay". Measured live before this: the generic hint was the only thing
    that came back, so the caller had to make a second call to learn what the
    first one could have told it.
    """

    def _occluded_state(self):
        return {
            "visible": True, "enabled": True, "in_viewport": True, "occluded": True,
            "occluder": {"tag": "div", "id": "overlay", "cls": "", "role": "",
                         "text": "Accept cookies"},
            "tag": "button", "type": "", "name": "", "value": "", "checked": None,
            "readonly": False, "href": "", "aria_expanded": None,
            "rect": {"x": 1, "y": 1, "w": 10, "h": 10}, "error": None,
        }

    def _page(self, state=None, exc=None):
        page = MagicMock()
        err = exc or RuntimeError("Page.click: Timeout 5000ms exceeded")
        for name in ("click", "dblclick", "type", "fill", "hover", "select_option"):
            getattr(page, name).side_effect = err
        page.locator.return_value.first.evaluate.return_value = (
            self._occluded_state() if state is None else state)
        return page

    def _call(self, tool, args, page):
        import camoufoxmcp.server as server_mod
        from camoufoxmcp.server import create_server
        mcp = create_server()
        with patch.object(server_mod._session, "get_page", return_value=page):
            blocks = asyncio.run(mcp.call_tool(tool, args))
        return _tool_dict(blocks)

    @patch("camoufoxmcp.server._session")
    def test_click_names_the_occluder(self, mock_session):
        out = self._call("camoufox_click", {"page_id": "p", "ref": "#covered"}, self._page())
        assert out["status"] == "error"
        assert out["target_state"]["occluded"] is True
        assert "div#overlay" in out["hint"]
        # The generic wording must be gone, not merely joined by the specific one.
        assert not out["hint"].lstrip().startswith("If the element is covered")

    @patch("camoufoxmcp.server._session")
    def test_type_names_the_occluder(self, mock_session):
        out = self._call("camoufox_type",
                         {"page_id": "p", "ref": "#name", "text": "x"}, self._page())
        assert out["status"] == "error"
        assert "div#overlay" in out["hint"]

    @patch("camoufoxmcp.server._session")
    def test_hover_names_the_occluder(self, mock_session):
        out = self._call("camoufox_hover", {"page_id": "p", "ref": "#covered"}, self._page())
        assert out["status"] == "error"
        assert "div#overlay" in out["hint"]

    @patch("camoufoxmcp.server._session")
    def test_select_names_the_occluder(self, mock_session):
        out = self._call("camoufox_select",
                         {"page_id": "p", "ref": "#pick", "value": "a"}, self._page())
        assert out["status"] == "error"
        assert "div#overlay" in out["hint"]

    @patch("camoufoxmcp.server._session")
    def test_the_generic_hint_survives_a_probe_that_cannot_run(self, mock_session):
        # If the probe itself fails there is still something useful to say.
        page = self._page()
        page.locator.return_value.first.evaluate.side_effect = RuntimeError("gone")
        out = self._call("camoufox_click", {"page_id": "p", "ref": "#covered"}, page)
        assert out["status"] == "error"
        assert "target_state" not in out
        assert "camoufox_snapshot" in out["hint"]

    @patch("camoufoxmcp.server._session")
    def test_a_clean_target_does_not_invent_a_reason(self, mock_session):
        clean = self._occluded_state()
        clean.update({"occluded": False, "occluder": None})
        out = self._call("camoufox_click", {"page_id": "p", "ref": "#covered"},
                         self._page(state=clean))
        assert out["status"] == "error"
        assert "target_state" not in out
        assert "camoufox_snapshot" in out["hint"]

    @patch("camoufoxmcp.server._session")
    def test_click_reports_the_retrys_error_not_the_first_attempts(self, mock_session):
        # The retry waits longer, so the two can differ. The name bound by the
        # first `except` used to be what got reported; the retry's was dropped.
        page = MagicMock()
        page.click.side_effect = [
            RuntimeError("first attempt: element not visible"),
            RuntimeError("retry: hard timeout"),
        ]
        page.locator.return_value.first.evaluate.return_value = self._occluded_state()
        out = self._call("camoufox_click", {"page_id": "p", "ref": "#covered"}, page)
        assert "retry: hard timeout" in out["error"]
        assert "first attempt" not in out["error"]


class TestStateExplanation:
    """The sentence itself, independent of any tool."""

    def _state(self, **over):
        base = {"visible": True, "enabled": True, "in_viewport": True,
                "occluded": False, "occluder": None, "readonly": False, "error": None}
        base.update(over)
        return base

    def test_occluder_prefers_id_then_class(self):
        from camoufoxmcp.server import _state_explanation
        with_id = _state_explanation(self._state(
            occluded=True, occluder={"tag": "div", "id": "banner", "cls": "a b"}))
        assert "div#banner" in with_id
        with_cls = _state_explanation(self._state(
            occluded=True, occluder={"tag": "aside", "id": "", "cls": "promo sticky"}))
        assert "aside.promo" in with_cls
        assert "sticky" not in with_cls  # first class only, not the whole list

    def test_nameless_occluder_still_reported(self):
        from camoufoxmcp.server import _state_explanation
        note = _state_explanation(self._state(occluded=True, occluder={"tag": "div"}))
        assert "covered by div" in note

    def test_each_reason_appears(self):
        from camoufoxmcp.server import _state_explanation
        assert "disabled" in _state_explanation(self._state(enabled=False))
        assert "not visible" in _state_explanation(self._state(visible=False))
        assert "off-screen" in _state_explanation(self._state(in_viewport=False))
        assert "read-only" in _state_explanation(self._state(readonly=True))

    def test_reasons_combine(self):
        from camoufoxmcp.server import _state_explanation
        note = _state_explanation(self._state(enabled=False, occluded=True,
                                              occluder={"tag": "div", "id": "x"}))
        assert "div#x" in note and "disabled" in note

    def test_a_clean_state_gets_no_sentence(self):
        from camoufoxmcp.server import _state_explanation
        assert _state_explanation(self._state()) is None

    def test_an_unprobed_target_gets_no_sentence(self):
        # A probe that errored has no opinion; guessing would be a fabrication.
        from camoufoxmcp.server import _state_explanation
        assert _state_explanation({"error": "detached"}) is None
        assert _state_explanation({}) is None
        assert _state_explanation(None) is None
