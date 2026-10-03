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

import logging
import re
import time
from typing import Any

logger = logging.getLogger("camoufoxmcp")


# Maps an aria role to the most common Playwright get_by_role invocation.
# When an aria-ref fails to resolve (a11y tree hasn't been populated, or the
# element was destroyed by a navigation), we fall back to get_by_role.
ROLE_RE = re.compile(r"^\s*[-*]\s*(\w+)")

# Roles worth spending a round trip on. Probing state is N round trips, not
# one -- Playwright exposes no batch state API for aria-refs, and the refs are
# a Playwright selector engine rather than a DOM attribute, so they cannot be
# resolved from page JS. Restricting to actionable roles is the mitigation
# that keeps the cost proportional to what the caller can actually act on.
ACTIONABLE_ROLES = frozenset({
    "button", "link", "textbox", "searchbox", "checkbox", "radio",
    "combobox", "listbox", "menuitem", "menuitemcheckbox", "menuitemradio",
    "option", "tab", "switch", "slider", "spinbutton",
})

# Hard cap on probes per snapshot. A page with 300 links would otherwise cost
# 300 round trips, which is slower than the model call it exists to inform.
STATE_PROBE_LIMIT = 60

# Returns everything needed to judge whether an element is actionable right
# now: is it visible, is it enabled, is it on screen, and -- the one that
# actually matters -- is something else sitting on top of it. `occluder`
# names the thing in the way, because "occluded" without "by what" leaves the
# caller with no next move.
_STATE_PROBE_JS = r"""
(el) => {
  const out = {
    visible: false, enabled: true, in_viewport: false,
    occluded: false, occluder: null,
    tag: "", type: "", name: "", value: null, checked: null,
    readonly: false, href: "", aria_expanded: null,
    rect: null, error: null,
  };
  try {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    const vw = window.innerWidth || 1, vh = window.innerHeight || 1;

    out.tag = el.tagName.toLowerCase();
    out.type = (el.getAttribute("type") || "").toLowerCase();
    out.name = el.getAttribute("name") || "";
    out.readonly = !!(el.readOnly || el.getAttribute("aria-readonly") === "true");
    out.href = el.getAttribute("href") || "";
    out.aria_expanded = el.getAttribute("aria-expanded");
    out.rect = { x: Math.round(r.left), y: Math.round(r.top),
                 w: Math.round(r.width), h: Math.round(r.height) };

    out.visible = !!(r.width || r.height)
      && cs.visibility !== "hidden"
      && cs.display !== "none"
      && parseFloat(cs.opacity || "1") > 0;

    out.in_viewport = r.bottom > 0 && r.right > 0 && r.top < vh && r.left < vw;

    out.enabled = !el.disabled && el.getAttribute("aria-disabled") !== "true";

    // Never surface a password value. A snapshot ends up in a transcript.
    if (out.type !== "password") {
      if (el.value !== undefined && el.value !== null) out.value = String(el.value).slice(0, 200);
    } else {
      out.value = "[redacted]";
    }
    if (el.checked !== undefined) out.checked = !!el.checked;

    // Occlusion: probe the element's own centre point. If hit-testing there
    // returns a different element that neither contains nor is contained by
    // this one, a click would land on that instead.
    if (out.visible && out.in_viewport) {
      const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      if (cx >= 0 && cy >= 0 && cx <= vw && cy <= vh) {
        const top = document.elementFromPoint(cx, cy);
        if (top && top !== el && !el.contains(top) && !top.contains(el)) {
          out.occluded = true;
          const cls = typeof top.className === "string" ? top.className : "";
          out.occluder = {
            tag: top.tagName.toLowerCase(),
            id: top.id || "",
            cls: cls.slice(0, 100),
            role: top.getAttribute("role") || "",
            text: (top.innerText || "").slice(0, 80),
          };
        }
      }
    }
  } catch (e) {
    out.error = String(e).slice(0, 200);
  }
  return out;
}
"""


def _describe_occluder(occluder: dict[str, Any] | None) -> str:
    """Short human-readable name for whatever is covering an element."""
    if not occluder:
        return "something"
    tag = occluder.get("tag") or "element"
    el_id = occluder.get("id") or ""
    cls = (occluder.get("cls") or "").split()
    desc = tag
    if el_id:
        desc += f"#{el_id}"
    elif cls:
        desc += f".{cls[0]}"
    return desc


def state_flags(state: dict[str, Any]) -> list[str]:
    """The state facts worth showing inline in the snapshot text.

    Only the blocking ones. `visible`, `in_viewport` and the rest stay in the
    structured `refs` payload where they are cheap to read programmatically;
    putting them inline would triple the size of the tree for no benefit.
    """
    flags: list[str] = []
    if state.get("error"):
        return flags
    if state.get("occluded"):
        flags.append(f"occluded by {_describe_occluder(state.get('occluder'))}")
    if state.get("visible") and not state.get("in_viewport"):
        flags.append("off-screen")
    if state.get("visible") is False:
        flags.append("hidden")
    if state.get("enabled") is False:
        flags.append("disabled")
    if state.get("readonly"):
        flags.append("readonly")
    if state.get("checked") is True:
        flags.append("checked")
    return flags


def _probe_states(page: Any, refs: list[dict[str, Any]],
                  session: Any, page_id: str,
                  limit: int = STATE_PROBE_LIMIT) -> tuple[dict[str, Any], int, int]:
    """Probe live state for actionable refs.

    Returns ``(states, probed_count, skipped_count)``. Failures are recorded
    per-ref and never abort the snapshot: a snapshot with partial state is
    still far more useful than no snapshot, and the caller can see exactly
    which refs are missing it.
    """
    states: dict[str, Any] = {}
    probed = 0
    skipped = 0

    for ref_info in refs:
        role = (ref_info.get("role") or "").lower()
        if role not in ACTIONABLE_ROLES:
            skipped += 1
            continue
        if probed >= limit:
            skipped += 1
            continue

        ref_id = ref_info["ref"]
        try:
            _clean, selector, _frame = resolve_ref(session, page_id, ref_id)
            state = page.locator(selector).first.evaluate(_STATE_PROBE_JS)
            if isinstance(state, dict):
                states[ref_id] = state
            probed += 1
        except Exception as exc:
            states[ref_id] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
            probed += 1

    return states, probed, skipped


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


def take_snapshot(page: Any, page_id: str, session: Any, full: bool = False,
                  max_length: int = 12000, state: bool = True,
                  state_limit: int = STATE_PROBE_LIMIT) -> dict[str, Any]:
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
        state: Probe live state (visible/enabled/occluded) for actionable refs.
            Costs one round trip per actionable ref, capped at state_limit.
            Disable on very large pages where the cost outweighs the benefit.
        state_limit: Max refs to probe.

    Returns:
        {
            "status": "ok",
            "snapshot": "tree text, with [disabled] / [occluded by X] inline",
            "interactive_elements": N,
            "refs": {ref_id: {"selector": "aria-ref=eN", "tag": "button",
                              "role": "button", "label": "Next",
                              "state": {...}}},
            "state_probed": N,
            "blockers": {...},
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

    # Live state for actionable refs, and the freshness baseline. Both live
    # after the tree is built so the annotations can be folded into the text
    # the caller reads -- a snapshot that says a button is disabled inline
    # saves the caller a round trip it would otherwise have to spend finding
    # out why the click did nothing.
    result: dict[str, Any] = {
        "status": "ok",
        "snapshot": tree_text,
        "interactive_elements": len(refs),
        "refs": refs_data,
    }

    if state and refs_data:
        states, probed, skipped = _probe_states(
            page, refs, session, page_id, limit=state_limit)
        for ref_id, st in states.items():
            if ref_id in refs_data:
                refs_data[ref_id]["state"] = st
        for ref_id, st in states.items():
            flags = state_flags(st)
            if flags and ref_id in refs_data:
                refs_data[ref_id]["flags"] = flags
                tree_text = tree_text.replace(
                    f"[@{ref_id}]", f"[@{ref_id}] " + " ".join(flags), 1)
        result["snapshot"] = tree_text
        result["state_probed"] = probed
        result["state_skipped"] = skipped
        if skipped and probed >= state_limit:
            result["state_note"] = (
                f"State probed for the first {probed} actionable refs "
                f"(state_limit); {skipped} more were not probed."
            )

    stamp_ref_signature(session, page, page_id)

    # Blockers ride along with the snapshot because the answer to "why did
    # nothing happen?" is so often "you are looking at an interstitial". One
    # extra evaluate() is cheap next to a follow-up tool call.
    try:
        from .observe import detect_blockers
        blockers = detect_blockers(page)
        if blockers.get("blocked"):
            result["blocked"] = True
            result["blocker"] = blockers
    except Exception as exc:
        logger.debug("blocker check during snapshot failed: %s", exc)

    return result


def stamp_ref_signature(session: Any, page: Any, page_id: str) -> dict[str, Any]:
    """Record the page state that the current refs are valid against."""
    from .observe import install_mutation_observer, mutation_bucket, nav_epoch

    mutations = install_mutation_observer(page)
    signature = {
        "nav_epoch": nav_epoch(session, page_id),
        "mutation_bucket": mutation_bucket(mutations),
        "mutations": mutations,
        "url": None,
        "taken_at": time.time(),
    }
    try:
        signature["url"] = page.url
    except Exception:
        pass
    if not hasattr(session, "_ref_signature"):
        session._ref_signature = {}
    session._ref_signature[page_id] = signature
    return signature


def ref_freshness(session: Any, page: Any, page_id: str) -> dict[str, Any]:
    """Decide whether the stored refs still refer to what they referred to.

    Three verdicts, and the middle one is the reason this exists:

      * ``fresh`` — nothing material changed since the snapshot.
      * ``stale_warning`` — the DOM moved but no navigation occurred. Actions
        proceed and report it, because most mutations are unrelated and
        refusing outright would make the tool unusable on any live page.
      * ``hard_stale`` — a navigation happened. Every ref from before it is
        meaningless, and resolving one silently acts on whatever now occupies
        that position. The caller must re-snapshot.

    Also ``unknown`` when no snapshot has been taken, which is reported rather
    than treated as fresh: a ref that was never snapshotted is not "fine", it
    is unverified.
    """
    from .observe import mutation_bucket, nav_epoch, read_mutation_count

    signature = getattr(session, "_ref_signature", {}).get(page_id)
    if not signature:
        return {
            "verdict": "unknown",
            "detail": "No snapshot has been taken for this page",
            "hint": "Run camoufox_snapshot before using [@eN] refs",
        }

    current_epoch = nav_epoch(session, page_id)
    current_mutations = read_mutation_count(page)
    current_bucket = mutation_bucket(current_mutations)

    if current_epoch != signature.get("nav_epoch"):
        return {
            "verdict": "hard_stale",
            "detail": (f"Page navigated since the snapshot "
                       f"(epoch {signature.get('nav_epoch')} -> {current_epoch})"),
            "hint": "Re-run camoufox_snapshot; every [@eN] ref from before the "
                    "navigation now points at whatever occupies that position",
            "from_url": signature.get("url"),
        }

    if current_bucket >= 0 and signature.get("mutation_bucket", -1) >= 0 \
            and current_bucket != signature.get("mutation_bucket"):
        return {
            "verdict": "stale_warning",
            "detail": (f"DOM changed since the snapshot "
                       f"({signature.get('mutations')} -> {current_mutations} mutations)"),
            "hint": "Refs may be unchanged; verify with camoufox_verify if the "
                    "action matters",
            "mutations_delta": current_mutations - signature.get("mutations", 0),
        }

    return {
        "verdict": "fresh",
        "detail": "No navigation and no material DOM change since the snapshot",
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
