"""Screenshots with optional element annotation overlay — Playwright MCP quality."""

from __future__ import annotations

import base64
import uuid
from pathlib import Path
from typing import Any


ANNOTATE_JS = r"""
(elementRefs) => {
  const colors = [
    '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
    '#1abc9c', '#e67e22', '#2980b9', '#27ae60', '#8e44ad',
  ];

  let idx = 0;
  for (const [refId, info] of Object.entries(elementRefs)) {
    idx++;
    const color = colors[(idx - 1) % colors.length];
    try {
      const el = document.querySelector(info.selector);
      if (!el) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;

      // Skip elements far off-screen
      if (rect.bottom < -100 || rect.top > window.innerHeight + 100) continue;

      const badge = document.createElement('div');
      badge.textContent = (idx).toString();
      badge.style.cssText = `
        position: fixed; z-index: 2147483647;
        left: ${Math.max(0, rect.left - 2)}px;
        top: ${Math.max(0, rect.top - 2)}px;
        background: ${color};
        color: white; font-size: 10px; font-weight: bold;
        padding: 1px 4px; border-radius: 2px;
        pointer-events: none; line-height: 1.3;
        font-family: -apple-system, sans-serif;
      `;
      document.body.appendChild(badge);

      // Highlight border
      const highlight = document.createElement('div');
      highlight.style.cssText = `
        position: fixed; z-index: 2147483646;
        left: ${Math.max(0, rect.left - 1)}px;
        top: ${Math.max(0, rect.top - 1)}px;
        width: ${rect.width + 2}px; height: ${rect.height + 2}px;
        border: 2px solid ${color};
        border-radius: 2px; pointer-events: none;
      `;
      document.body.appendChild(highlight);
    } catch(e) {}
  }
  return idx;
}
"""


def take_screenshot(
    page: Any,
    full_page: bool = False,
    annotate: bool = False,
    session: Any = None,
    page_id: str | None = None,
) -> dict[str, Any]:
    """Take a screenshot of the page, optionally with element index annotations.

    When annotate=True, overlays numbered badges on interactive elements
    matching the [@eN] ref IDs from camoufox_snapshot(), so the AI can
    visually identify which ref corresponds to which element.

    Args:
        page: Playwright Page object.
        full_page: Capture entire scrollable page.
        annotate: Overlay numbered element indices.
        session: BrowserSession (needed for ref map access when annotating).
        page_id: Page ID (needed for ref map access).

    Returns:
        {
            "status": "ok",
            "path": "/tmp/camoufox_screenshot_abc123.png",
            "annotated": bool,
            "element_count": N (if annotated),
        }
    """
    path = f"/tmp/camoufox_screenshot_{uuid.uuid4().hex[:6]}.png"

    ref_map = {}
    if annotate and session and page_id:
        ref_map = getattr(session, "_ref_map", {}).get(page_id, {})
        if ref_map:
            try:
                count = page.evaluate(ANNOTATE_JS, ref_map)
                # Brief pause to let DOM settle
                page.wait_for_timeout(100)
            except Exception:
                count = 0
                annotate = False
        else:
            annotate = False

    if full_page:
        page.screenshot(path=path, full_page=True)
    else:
        page.screenshot(path=path)

    result: dict[str, Any] = {
        "status": "ok",
        "path": path,
    }

    if annotate:
        result["annotated"] = True
        result["element_count"] = len(ref_map) if ref_map else 0
        result["note"] = ("Numbered badges [1] [2] ... overlay interactive elements. "
                          "Match badge numbers to [@eN] refs from camoufox_snapshot().")

    return result
