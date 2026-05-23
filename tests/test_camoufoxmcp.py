"""Tests for CamoufoxMCP."""

import pytest
from unittest.mock import MagicMock


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
        session._force_cleanup()
        assert session._browser is None
        assert session._context is None
        assert session._pages == {}
        assert session._page_ids == []


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
        session._ref_map = {}  # No ref map for this page
        clean_ref, selector, _ = resolve_ref(session, "page_unknown", "e99")
        assert clean_ref == "e99"
        # Falls back to role-based selector
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


class TestSnapshotJS:
    """Test the injected snapshot JS logic."""

    def test_snapshot_js_is_valid(self):
        import re
        # Verify the JS doesn't have obvious syntax errors
        from camoufoxmcp.snapshot import SNAPSHOT_JS
        # Should have function definitions
        assert "function isVisible" in SNAPSHOT_JS
        assert "function getSelector" in SNAPSHOT_JS
        assert "function getLabel" in SNAPSHOT_JS
        assert "function describeElement" in SNAPSHOT_JS
        # Should return an object with expected keys (JS uses single-quote keys in the return stmt)
        assert "return {" in SNAPSHOT_JS
        assert "tree:" in SNAPSHOT_JS
        assert "refs," in SNAPSHOT_JS
        assert "ref_count:" in SNAPSHOT_JS