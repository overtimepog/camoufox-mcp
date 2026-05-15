"""Clean markdown extraction from pages."""

from __future__ import annotations

import re
from typing import Any


async def extract_markdown(page: Any, max_length: int = 50000) -> dict[str, Any]:
    """Extract page content as clean, readable markdown.

    Strips navigation, ads, footers — returns just the main content.
    """
    html = page.content()
    # Simple strip of script/style tags
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    # Basic markdown conversion
    text = html

    # Remove comments
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # Headings
    for i in range(3, 0, -1):
        text = re.sub(rf"<h{i}[^>]*>(.*?)</h{i}>", lambda m: f"\n{'#' * i} {m.group(1).strip()}\n", text, flags=re.IGNORECASE | re.DOTALL)

    # Paragraphs / divs / sections
    text = re.sub(r"<(?:p|div|section|article)[^>]*>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:p|div|section|article)>", "", text, flags=re.IGNORECASE)

    # Line breaks
    text = re.sub(r"<br[^>]*>", "\n", text, flags=re.IGNORECASE)

    # Lists
    text = re.sub(r"<li[^>]*>(.*?)</li>", lambda m: f"\n- {m.group(1).strip()}", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<(?:ul|ol)[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(?:ul|ol)[^>]*>", "", text, flags=re.IGNORECASE)

    # Bold / italic
    text = re.sub(r"<strong[^>]*>(.*?)</strong>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<b[^>]*>(.*?)</b>", r"**\1**", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<em[^>]*>(.*?)</em>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<i[^>]*>(.*?)</i>", r"*\1*", text, flags=re.IGNORECASE | re.DOTALL)

    # Links
    text = re.sub(r"<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)</a>", r"[\2](\1)", text, flags=re.IGNORECASE | re.DOTALL)

    # Code
    text = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<pre[^>]*>(.*?)</pre>", r"\n```\n\1\n```\n", text, flags=re.IGNORECASE | re.DOTALL)

    # Strip remaining HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Clean whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + f"\n\n... (truncated, {len(text) - max_length} chars cut)"

    return {
        "status": "ok",
        "content": text,
        "char_count": len(text),
    }