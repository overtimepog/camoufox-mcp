"""Tests for CamoufoxMCP."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch


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
    """Test accessibility snapshot functionality."""

    def test_resolve_ref_basic(self):
        from camoufoxmcp.snapshot import resolve_ref
        # Mock session and page
        session = MagicMock()
        page_id = "page_abc"
        ref = "e5"
        clean_ref, selector, frame_idx = resolve_ref(session, page_id, ref)
        assert clean_ref == "e5"
        assert "@e5" in ref or clean_ref == "e5"

    def test_resolve_ref_strips_at(self):
        from camoufoxmcp.snapshot import resolve_ref
        session = MagicMock()
        clean_ref, _, _ = resolve_ref(MagicMock(), "page_abc", "@e3")
        assert clean_ref == "e3"


class TestMarkdownExtraction:
    """Test clean markdown extraction."""

    def test_extract_markdown_basic(self):
        from camoufoxmcp.markdown import extract_markdown
        page = MagicMock()
        page.content.return_value = "<html><body><h1>Hello</h1><p>World</p></body></html>"
        result = asyncio.get_event_loop().run_until_complete(extract_markdown(page))
        assert result["status"] == "ok"
        assert "Hello" in result["content"]
        assert "World" in result["content"]


class TestCloudflareDetection:
    """Test Cloudflare challenge detection."""

    def test_is_cloudflare_blocked_true(self):
        from camoufoxmcp.server import _is_cloudflare_blocked
        assert _is_cloudflare_blocked("Just a moment...", "https://example.com/") is True
        assert _is_cloudflare_blocked("Checking your browser", "https://example.com/") is True
        assert _is_cloudflare_blocked("Cloudflare", "https://example.com/") is True

    def test_is_cloudflare_blocked_false(self):
        from camoufoxmcp.server import _is_cloudflare_blocked
        assert _is_cloudflare_blocked("Vx Underground", "https://vx-underground.org/") is False
        assert _is_cloudflare_blocked("Example Domain", "https://example.com/") is False

    def test_is_cloudflare_case_insensitive(self):
        from camoufoxmcp.server import _is_cloudflare_blocked
        assert _is_cloudflare_blocked("JUST A MOMENT...", "https://example.com/") is True
        assert _is_cloudflare_blocked("CloudFlare", "https://example.com/") is True