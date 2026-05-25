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
    """Test the injected snapshot JS logic."""

    def test_snapshot_js_is_valid(self):
        from camoufoxmcp.snapshot import SNAPSHOT_JS
        assert "function isVisible" in SNAPSHOT_JS
        assert "function getSelector" in SNAPSHOT_JS
        assert "function getLabel" in SNAPSHOT_JS
        assert "function describeElement" in SNAPSHOT_JS
        assert "function getValue" in SNAPSHOT_JS
        assert "return {" in SNAPSHOT_JS
        assert "tree:" in SNAPSHOT_JS
        assert "refs," in SNAPSHOT_JS
        assert "ref_count:" in SNAPSHOT_JS

    def test_snapshot_covers_more_interactives(self):
        from camoufoxmcp.snapshot import SNAPSHOT_JS
        # v0.6.0 additions
        assert "[onclick]" in SNAPSHOT_JS or 'onclick' in SNAPSHOT_JS
        assert "[contenteditable" in SNAPSHOT_JS
        assert "data-qa" in SNAPSHOT_JS  # selector coverage
        assert "LANDMARK_SELECTORS" in SNAPSHOT_JS

    def test_snapshot_max_refs_increased(self):
        from camoufoxmcp.snapshot import SNAPSHOT_JS
        # v0.6.0 bumped from 200 to 300
        assert "MAX_REFS = 300" in SNAPSHOT_JS


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
