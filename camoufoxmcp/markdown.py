"""Clean markdown extraction from pages — Playwright MCP quality.

Uses trafilatura (production-grade HTML→text extraction) when available,
with a regex-based fallback for environments where it's not installed.
"""

from __future__ import annotations

import re
from typing import Any


def _extract_markdown_trafilatura(html: str, max_length: int = 50000) -> str:
    """Use trafilatura for high-quality main-content extraction."""
    try:
        import trafilatura
        text = trafilatura.extract(
            html,
            output_format="markdown",
            include_links=True,
            include_images=False,
            include_tables=True,
            favor_precision=True,
        )
        if text and len(text.strip()) > 50:
            if len(text) > max_length:
                text = text[:max_length] + f"\n\n... (truncated, {len(text) - max_length} chars cut)"
            return text
    except Exception:
        pass
    return ""


def _extract_markdown_fallback(html: str, max_length: int = 50000) -> str:
    """Regex-based HTML→markdown fallback (improved over v0.3)."""
    text = html

    # Remove non-content elements first
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<noscript[^>]*>.*?</noscript>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # Strip nav/footer/sidebar noise (common classes/ids)
    for noise in [
        r'<(?:nav|header|footer|aside)[^>]*>.*?</(?:nav|header|footer|aside)>',
    ]:
        text = re.sub(noise, "", text, flags=re.DOTALL | re.IGNORECASE)

    # Headings
    for i in range(6, 0, -1):
        text = re.sub(
            rf"<h{i}[^>]*>(.*?)</h{i}>",
            lambda m: f"\n{'#' * i} {m.group(1).strip()}\n",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )

    # Block elements → newlines
    text = re.sub(r"<(?:p|div|section|article|header|footer|main|aside|nav|blockquote|pre|figure|figcaption)[^>]*>",
                  "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:p|div|section|article|header|footer|main|aside|nav|blockquote|pre|figure|figcaption)>",
                  "", text, flags=re.IGNORECASE)
    text = re.sub(r"<br[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<hr[^>]*>", "\n---\n", text, flags=re.IGNORECASE)

    # Lists
    text = re.sub(r"<li[^>]*>(.*?)</li>",
                  lambda m: f"\n- {m.group(1).strip()}",
                  text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<(?:ul|ol)[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:ul|ol)[^>]*>", "", text, flags=re.IGNORECASE)

    # Tables
    text = re.sub(r"<table[^>]*>", "\n| | | |\n|---|---|---|\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<tr[^>]*>", "| ", text, flags=re.IGNORECASE)
    text = re.sub(r"</tr>", " |\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<t[dh][^>]*>", "| ", text, flags=re.IGNORECASE)
    text = re.sub(r"</t[dh]>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"</table>", "", text, flags=re.IGNORECASE)

    # Inline formatting
    text = re.sub(r"<strong[^>]*>(.*?)</strong>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<b[^>]*>(.*?)</b>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<em[^>]*>(.*?)</em>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<i[^>]*>(.*?)</i>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<u[^>]*>(.*?)</u>", r"<u>\1</u>", text, flags=re.IGNORECASE | re.DOTALL)

    # Code
    text = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<pre[^>]*>(.*?)</pre>", r"\n```\n\1\n```\n", text, flags=re.IGNORECASE | re.DOTALL)

    # Links — capture both href and text
    text = re.sub(
        r"<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)</a>",
        r"[\2](\1)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Images — show alt text
    text = re.sub(
        r"<img[^>]*alt=[\"']([^\"']*)[\"'][^>]*>",
        r"![image: \1]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"<img[^>]*>", "[image]", text, flags=re.IGNORECASE)

    # Strip remaining HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Decode common entities
    import html as _html
    text = _html.unescape(text)
    text = re.sub(r"&[a-z]+;", " ", text)

    # Clean whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + f"\n\n... (truncated, {len(text) - max_length} chars cut)"

    return text


def extract_markdown(page: Any, max_length: int = 50000) -> dict[str, Any]:
    """Extract page content as clean, readable markdown.

    Uses trafilatura (production-grade readability extraction) when available,
    falls back to regex-based extraction. Strips navigation, ads, footers —
    returns just the main content.

    Args:
        page: Playwright Page object.
        max_length: Truncate at this many characters.

    Returns:
        {"status": "ok", "content": "...", "char_count": N, "extractor": "trafilatura"|"regex"}
    """
    html = page.content()

    # Try trafilatura first
    text = _extract_markdown_trafilatura(html, max_length)
    if text:
        return {
            "status": "ok",
            "content": text,
            "char_count": len(text),
            "extractor": "trafilatura",
        }

    # Fall back to regex
    text = _extract_markdown_fallback(html, max_length)
    return {
        "status": "ok",
        "content": text,
        "char_count": len(text),
        "extractor": "regex (trafilatura unavailable or produced insufficient output)",
    }
