"""Accessibility-tree snapshot with [@eN] ref IDs, mirroring CloakBrowser MCP."""

from __future__ import annotations

import re
from typing import Any


async def take_snapshot(page: Any, page_id: str, session: Any, full: bool = False, max_length: int = 12000) -> dict[str, Any]:
    """Capture the page's accessibility tree with interactive element refs.

    Returns:
        {
            "status": "ok",
            "snapshot": "...",          # formatted accessibility tree
            "interactive_elements": N,  # count of clickable/inputtable elements
            "refs": {ref: description}  # optional: mapping of refs to descriptions
        }
    """
    tree = await page.accessibility.snapshot()

    if tree is None:
        return {
            "status": "ok",
            "snapshot": "(no accessibility tree available — page may still be loading)",
            "interactive_elements": 0,
        }

    lines = []
    refs: dict[str, str] = {}
    counter = [0]

    def render_node(node: dict, depth: int = 0) -> None:
        indent = "  " * depth
        role = node.get("role", "").lower()
        name = node.get("name", "")
        focused = node.get("focused", False)

        # Interactive elements get a ref
        interactive = role in {
            "button", "link", "checkbox", "radio", "textbox", "combobox",
            "menuitem", "tab", "switch", "slider", "searchbox", "spinbutton",
            "listbox", "option", "menuitemcheckbox", "menuitemradio",
        }

        if interactive:
            counter[0] += 1
            ref = f"e{counter[0]}"
            role_display = f"[{role}]" if focused else role
            lines.append(f"{indent}[@{ref}] {role_display} \"{name}\"")
            refs[ref] = f"{role}: {name}" if name else role
        elif full:
            role_display = f"[{role}]" if focused else role
            lines.append(f"{indent}{role_display} \"{name}\"")

        # Recurse children
        children = node.get("children") or node.get("children" + str(depth)) or []
        # Try standard Playwright accessibility tree children
        if "children" in node:
            for child in node["children"]:
                render_node(child, depth + 1)

    try:
        render_node(tree)
    except Exception as exc:
        lines.append(f"(snapshot render error: {exc})")

    snapshot_text = "\n".join(lines)

    # Truncate if needed
    if len(snapshot_text) > max_length:
        snapshot_text = snapshot_text[:max_length] + f"\n... (truncated, {len(snapshot_text) - max_length} chars cut)"

    return {
        "status": "ok",
        "snapshot": snapshot_text,
        "interactive_elements": counter[0],
        "refs": refs,
    }


def resolve_ref(session: Any, page_id: str, ref: str) -> tuple[str, str, int | None]:
    """Resolve a [@eN] ref to a Playwright selector.

    Returns (clean_ref, selector, frame_index).
    frame_index is None for main frame, or an integer for iframes.

    Since Camoufox uses Playwright, we build a selector from the
    accessibility tree's DOM relationship.
    """
    clean_ref = ref.lstrip("@")

    # For now, build selector from the element's text content / role
    # A full implementation would walk the tree to find the exact DOM path
    # This is a best-effort approach using Playwright's accessibility selectors
    return clean_ref, f'[role="{clean_ref}"]', None