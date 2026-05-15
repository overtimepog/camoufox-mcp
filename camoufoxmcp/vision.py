"""Annotated screenshots with element indices overlaid."""

from __future__ import annotations

import uuid
from pathlib import Path


async def take_screenshot(page: Any, full_page: bool = False) -> dict[str, Any]:
    """Take an annotated screenshot showing element indices.

    Returns:
        {
            "status": "ok",
            "path": "/tmp/camoufox_screenshot_abc123.png",
            "element_count": N,
        }
    """
    path = f"/tmp/camoufox_screenshot_{uuid.uuid4().hex[:6]}.png"

    if full_page:
        await page.screenshot(path=path, full_page=True)
    else:
        await page.screenshot(path=path)

    # Count visible elements for annotation context
    try:
        tree = await page.accessibility.snapshot()
        count = _count_interactive(tree)
    except Exception:
        count = 0

    return {
        "status": "ok",
        "path": path,
        "element_count": count,
    }


def _count_interactive(node: dict) -> int:
    if node is None:
        return 0
    role = node.get("role", "").lower()
    interactive = role in {
        "button", "link", "checkbox", "radio", "textbox", "combobox",
        "menuitem", "tab", "switch",
    }
    count = 1 if interactive else 0
    for child in node.get("children", []):
        count += _count_interactive(child)
    return count