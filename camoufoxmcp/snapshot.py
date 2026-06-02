"""Accessibility-tree snapshot with [@eN] ref IDs and CSS selector mapping.

Uses Playwright's native accessibility tree (page.aria_snapshot with mode='ai'),
which is the same approach as the official Microsoft Playwright MCP server. This
is dramatically more reliable than walking the raw DOM because:

  - The a11y tree abstracts away pure-presentational <div> wrappers
  - It surfaces elements by role/name, not by deep DOM position
  - On sites like Microsoft Entra ID SSO, the form is nested 18+ levels deep
    in the DOM but the a11y tree flattens it to a top-level textbox
  - It also handles shadow DOM, ARIA roles, and dynamic content uniformly

How it works:
  1. page.aria_snapshot(mode='ai') returns a YAML-ish tree with [ref=eN] annotations
  2. Each ref is a real Playwright selector: page.locator('aria-ref=eN')
  3. We also extract role + accessible name for display + fallback selector
  4. resolve_ref() returns 'aria-ref=eN' as the selector — Playwright handles
     the rest. CSS selectors still work as a fallback for raw selectors.

Why the previous approach was broken:
  - It walked the visible DOM up to MAX_DEPTH=12
  - Microsoft Entra ID's login form nests 18+ levels deep (provide-min-height
    pattern collapses the form's height to 1px until JS measures it)
  - Result: snapshot returned only 3 footer refs, missing the entire login form
  - This was the exact bug the user hit on the PSU Canvas SSO page
"""

from __future__ import annotations

import re
from typing import Any


# Maps an aria role to the most common Playwright get_by_role invocation.
# When an aria-ref fails to resolve (a11y tree hasn't been populated, or the
# element was destroyed by a navigation), we fall back to get_by_role.
ROLE_RE = re.compile(r"^\s*[-*]\s*(\w+)")


def _parse_aria_snapshot(snap_text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse the YAML output of page.aria_snapshot(mode='ai') into refs + tree lines.

    Returns (refs, tree_lines). refs is a list of dicts with:
      - ref: e.g. "e29"
      - role: e.g. "textbox"
      - name: accessible name (or None)
      - raw: original line (trimmed)
      - line_text: formatted tree line to show in the snapshot
    tree_lines preserves the YAML structure (including generic / non-ref nodes
    that provide useful structural context).
    """
    refs: list[dict[str, Any]] = []
    tree_lines: list[str] = []

    for raw_line in snap_text.splitlines():
        # Compute indent from leading whitespace
        stripped = raw_line.lstrip()
        indent_depth = (len(raw_line) - len(stripped)) // 2
        # Bullet check
        if not stripped.startswith("- "):
            tree_lines.append(raw_line)
            continue
        body_full = stripped[2:]

        # Find the ref token (if any)
        ref_m = re.search(r"\[ref=(e\d+)\]", body_full)
        ref_id = ref_m.group(1) if ref_m else None

        # Strip the ref token
        body = re.sub(r"\[ref=e\d+\]", "", body_full)
        # Strip trailing modifier + colon + "..." combination.
        # Real-world examples this must handle:
        #   'link "X" [ref=eN] [cursor=pointer]:'            -> 'link "X"'
        #   'button "Y" [ref=eN] [cursor=pointer]: ...'      -> 'button "Y"'
        #   'paragraph "Z" [ref=eN]: Some inline text'        -> 'paragraph "Z"'
        #   'heading "W" [ref=eN] [level=1]'                  -> 'heading "W"'
        # The colon + optional ellipsis can appear with or without intervening modifiers.
        body = re.sub(r"\s*\[(?:[^\]]+)\]\s*:?\s*\.{0,3}\s*$", "", body).strip()
        # Second pass for chains of modifiers
        body = re.sub(r"\s*(?:\[[^\]]+\]\s*)+:?\s*\.{0,3}\s*$", "", body).strip()
        # Final fallback: any trailing colon (YAML child introducer)
        body = re.sub(r"\s*:\s*\.{0,3}\s*$", "", body).strip()
        # If the line still has a ": <text>" tail (e.g. inline child text after role+name),
        # drop the tail — it's a child element, not the accessible name
        if ":" in body:
            m_role_name = re.match(r"(\w+)\s+[\"\'](.+?)[\"\']\s*:", body)
            if m_role_name:
                body = f'{m_role_name.group(1)} "{m_role_name.group(2)}"'
            else:
                # No name in quotes — strip everything after the role
                m_role_only = re.match(r"(\w+)\s*:", body)
                if m_role_only:
                    body = m_role_only.group(1)
        # Strip "..." truncation one more time (safety)
        body = re.sub(r"\s*\.{3}\s*$", "", body).strip()

        # Parse "role \"name\"" or "role" alone
        m2 = re.match(r"(\w+)\s+[\"'](.+?)[\"']\s*$", body)
        if m2:
            role, name = m2.group(1), m2.group(2)
        else:
            m3 = re.match(r"(\w+)\s*$", body)
            if m3:
                role, name = m3.group(1), None
            else:
                role, name = body, None

        # Build a friendly tree line
        prefix = "  " * indent_depth + "- "
        if name:
            ref_tag = f" [@{ref_id}]" if ref_id else ""
            line = f"{prefix}{role} \"{name}\"{ref_tag}"
        else:
            ref_tag = f" [@{ref_id}]" if ref_id else ""
            line = f"{prefix}{role}{ref_tag}"
        tree_lines.append(line)

        if ref_id:
            refs.append({
                "ref": ref_id,
                "role": role,
                "name": name,
                "raw": body,
                "line_text": line.strip(),
            })

    return refs, tree_lines


def take_snapshot(page: Any, page_id: str, session: Any, full: bool = False, max_length: int = 12000) -> dict[str, Any]:
    """Capture accessibility tree using Playwright's native aria snapshot.

    The aria snapshot (mode='ai') is what the official Playwright MCP server uses.
    It returns refs that are valid Playwright selectors: page.locator('aria-ref=eN').

    IMPORTANT: Calling aria_snapshot() ALSO populates the a11y tree in the page,
    which is required for aria-ref selectors to resolve. This is why refs work
    after a snapshot but fail if you try them cold.

    Args:
        page: Playwright page object
        page_id: For storing the ref map on the session
        session: BrowserSession (holds _ref_map)
        full: Include surrounding structural nodes (default: False, refs only)
        max_length: Max characters in returned snapshot

    Returns:
        {
            "status": "ok",
            "snapshot": "tree text",
            "interactive_elements": N,
            "refs": {ref_id: {"selector": "aria-ref=eN", "tag": "button", "role": "button", "label": "Next"}},
        }
    """
    try:
        snap_text = page.aria_snapshot(mode="ai")
    except Exception as exc:
        return {
            "status": "error",
            "snapshot": f"(aria_snapshot failed: {exc})",
            "interactive_elements": 0,
            "refs": {},
        }

    if not snap_text:
        return {
            "status": "ok",
            "snapshot": "(empty page — no accessibility nodes)",
            "interactive_elements": 0,
            "refs": {},
        }

    refs, tree_lines = _parse_aria_snapshot(snap_text)

    # When full=False, trim to a more compact view that still shows all refs
    # (the YAML structure with [ref=eN] is already compact; we just need to
    # make sure non-ref generic wrappers don't bloat the output)
    if not full:
        # Keep only lines that contain a ref OR are a structural landmark
        # (main, contentinfo, navigation, banner, alert, dialog)
        structural_roles = ("main", "navigation", "contentinfo", "banner",
                            "alert", "dialog", "alertdialog", "complementary",
                            "search", "form", "region", "log", "status")
        compact = []
        for line in tree_lines:
            stripped = line.strip()
            if "[@e" in stripped or stripped.startswith("- "):
                # Check if it's a structural landmark
                m_role = re.match(r"-\s*(\w+)", stripped)
                if m_role and m_role.group(1) in structural_roles:
                    compact.append(line)
                elif "[@e" in stripped:
                    compact.append(line)
                # Skip - generic and other pure-container roles
        tree_lines = compact if compact else tree_lines

    tree_text = "\n".join(tree_lines)

    # Truncate intelligently if too long
    if len(tree_text) > max_length:
        truncated = tree_text[:max_length]
        last_newline = truncated.rfind("\n")
        if last_newline > max_length * 0.5:
            truncated = truncated[:last_newline]
        tree_text = truncated + f"\n... (truncated, {len(tree_text) - max_length} chars cut)"

    # Build the refs dict for the session. Each ref maps to its aria-ref selector
    # AND its normalized form (for the LLM to use as a stable CSS-style hint).
    refs_data: dict[str, dict[str, Any]] = {}
    for r in refs:
        refs_data[r["ref"]] = {
            "selector": f"aria-ref={r['ref']}",  # Playwright native selector
            "tag": r["role"],
            "role": r["role"],
            "label": r["name"] or "",
            "value": "",
        }

    # Store refs on the session for lookup by resolve_ref
    if hasattr(session, "_ref_map"):
        session._ref_map[page_id] = refs_data
    else:
        session._ref_map = {page_id: refs_data}

    return {
        "status": "ok",
        "snapshot": tree_text,
        "interactive_elements": len(refs),
        "refs": refs_data,
    }


def resolve_ref(session: Any, page_id: str, ref: str) -> tuple[str, str, int | None]:
    """Resolve a ref to a Playwright selector.

    Accepts three forms:
      - [@eN] snapshot ref (e.g. '@e5', 'e12') — looked up from the last snapshot
      - Frame index ref (e.g. 'f0', 'f1') — targets iframe by index
      - Raw CSS selector — used directly when the ref doesn't match known patterns

    Returns (clean_ref, css_selector, frame_index).

    For aria refs, the selector is "aria-ref=eN" which Playwright resolves
    natively. We also try to produce a normalized fallback selector that the
    LLM can read for debugging.
    """
    clean_ref = ref.lstrip("@")

    # 1. Known snapshot ref: look up the stored selector
    ref_map = getattr(session, "_ref_map", {}).get(page_id, {})
    if clean_ref in ref_map:
        ref_info = ref_map[clean_ref]
        selector = ref_info.get("selector", f"aria-ref={clean_ref}")
        return clean_ref, selector, None

    # 2. Frame index ref
    if clean_ref.startswith("f"):
        try:
            frame_idx = int(clean_ref[1:])
            return clean_ref, f"iframe:nth-of-type({frame_idx + 1})", frame_idx
        except ValueError:
            pass

    # 3. Raw CSS selector fallback — treat the ref string as a CSS selector directly.
    #    Handles cases where the target element isn't in the snapshot
    #    (e.g. content inside React popovers, popovers, shadow DOM).
    #    Must look like a CSS selector (contains #. [] or starts with a tag).
    raw = ref.lstrip("@")
    if any(c in raw for c in "#.[]") or raw[0].isalpha() or raw.startswith("*"):
        return raw, raw, None

    # Last resort: return as-is so Playwright can surface the error
    return clean_ref, f"aria-ref={clean_ref}", None
