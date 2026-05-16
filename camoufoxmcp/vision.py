"""Annotated screenshots."""

from __future__ import annotations

import uuid
from typing import Any


def take_screenshot(page: Any, full_page: bool = False) -> dict[str, Any]:
    """Take a screenshot of the page.

    Returns:
        {
            "status": "ok",
            "path": "/tmp/camoufox_screenshot_abc123.png",
            "element_count": N,
        }
    """
    path = f"/tmp/camoufox_screenshot_{uuid.uuid4().hex[:6]}.png"

    if full_page:
        page.screenshot(path=path, full_page=True)
    else:
        page.screenshot(path=path)

    return {
        "status": "ok",
        "path": path,
    }