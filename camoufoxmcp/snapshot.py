"""Accessibility-tree snapshot with [@eN] ref IDs and CSS selector mapping.

Uses a two-pass approach:
  1. JS injection: collect interactive DOM elements with their CSS selectors + a11y info
  2. Build a human-readable tree with @eN refs that map to real selectors

Playwright MCP quality improvements:
  - Wider interactive element coverage (onclick, [contenteditable], form elements, etc.)
  - Landmark/region detection for page structure
  - Smarter text extraction for non-interactive containers
  - Cross-origin iframe handling with graceful fallback
"""

from __future__ import annotations

import re
from typing import Any


SNAPSHOT_JS = r"""
(() => {
  const MAX_DEPTH = 12;
  const TEXT_LIMIT = 50;
  const MAX_REFS = 300;

  // Interactive element selectors — comprehensive coverage matching Playwright a11y + DOM
  const INTERACTIVE_SELECTORS = [
    // Native interactive elements
    'a[href]', 'a:not([href])',  // links (even empty href — they might be JS-driven)
    'button', 'input', 'select', 'textarea', 'datalist', 'optgroup', 'option',
    'fieldset', 'legend', 'label',
    // ARIA roles
    '[role="button"]', '[role="link"]', '[role="checkbox"]', '[role="radio"]',
    '[role="tab"]', '[role="menuitem"]', '[role="switch"]', '[role="combobox"]',
    '[role="slider"]', '[role="spinbutton"]', '[role="textbox"]', '[role="searchbox"]',
    '[role="listbox"]', '[role="option"]', '[role="menuitemcheckbox"]', '[role="menuitemradio"]',
    '[role="treeitem"]', '[role="tree"]', '[role="grid"]', '[role="row"]',
    '[role="gridcell"]', '[role="columnheader"]', '[role="rowheader"]',
    '[role="separator"]', '[role="scrollbar"]',
    // Focusable
    '[tabindex]:not([tabindex="-1"])',
    // Editable
    '[contenteditable="true"]', '[contenteditable=""]',
    // Expandable
    'summary', 'details',
    // Event-driven (onclick and friends — heuristic for JS-driven interactivity)
    '[onclick]', '[ondblclick]', '[onmousedown]', '[onmouseup]',
    '[onsubmit]', '[onreset]', '[onchange]', '[oninput]',
    '[onkeydown]', '[onkeyup]', '[onkeypress]',
    // Form-associated
    'datalist', 'output', 'meter', 'progress',
  ];

  // Landmark/region roles — structural elements worth reporting even if non-interactive
  const LANDMARK_SELECTORS = [
    '[role="navigation"]', '[role="banner"]', '[role="contentinfo"]',
    '[role="main"]', '[role="complementary"]', '[role="form"]',
    '[role="search"]', '[role="region"]', '[role="application"]',
    '[role="dialog"]', '[role="alertdialog"]', '[role="alert"]',
    '[role="log"]', '[role="status"]', '[role="timer"]',
    '[role="tooltip"]', '[role="menu"]', '[role="menubar"]',
    'nav', 'header', 'footer', 'main', 'aside', 'section', 'article',
  ];

  // Visibility check
  function isVisible(el) {
    if (!el || el.nodeType !== 1) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    if (el.hasAttribute('hidden') && !el.matches('dialog[open]')) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    return true;
  }

  // Generate a robust CSS selector for an element
  function getSelector(el) {
    if (!el || el === document.body || el === document.documentElement) return 'body';

    // 1. data-testid / data-test-id takes priority
    for (const attr of ['data-testid', 'data-test-id', 'data-cy', 'data-e2e', 'data-qa']) {
      if (el.hasAttribute(attr)) {
        return el.tagName.toLowerCase() + '[' + attr + '="' +
          el.getAttribute(attr).replace(/"/g, '\\"') + '"]';
      }
    }

    // 2. name attribute (for inputs/forms)
    if (['input', 'select', 'textarea', 'button', 'form', 'fieldset'].includes(el.tagName.toLowerCase()) && el.name) {
      const nameSel = el.tagName.toLowerCase() + '[name="' + el.name.replace(/"/g, '\\"') + '"]';
      // Check uniqueness — radio/checkbox groups share a name, so disambiguate with value
      if (document.querySelectorAll(nameSel).length === 1) return nameSel;
      // For radio/checkbox inputs, combine name + value for a unique selector
      if (el.hasAttribute('value')) {
        const valSel = el.tagName.toLowerCase() +
          '[name="' + el.name.replace(/"/g, '\\"') + '"]' +
          '[value="' + el.getAttribute('value').replace(/"/g, '\\"') + '"]';
        if (document.querySelectorAll(valSel).length === 1) return valSel;
      }
      // Still ambiguous — annotate with label text as a hint and fall through
    }

    // 3. id is unique
    if (el.id) {
      const sel = '#' + CSS.escape(el.id);
      if (document.querySelectorAll(sel).length === 1) return sel;
    }

    // 4. aria-label unique enough?
    if (el.getAttribute('aria-label')) {
      const escaped = el.getAttribute('aria-label').replace(/"/g, '\\"');
      const sel = el.tagName.toLowerCase() + '[aria-label="' + escaped + '"]';
      if (document.querySelectorAll(sel).length <= 3) return sel;
    }

    // 5. Build path with classes and nth-of-type
    const parts = [];
    let cur = el;
    for (let i = 0; i < 5 && cur && cur !== document.body && cur !== document.documentElement; i++) {
      let seg = cur.tagName.toLowerCase();
      if (cur.id) {
        seg = '#' + CSS.escape(cur.id);
        parts.unshift(seg);
        break;
      }
      const cls = Array.from(cur.classList)
        .slice(0, 2)
        .map(c => '.' + CSS.escape(c))
        .join('');
      if (cls) seg += cls;
      const parent = cur.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children)
          .filter(c => c.tagName === cur.tagName && isVisible(c));
        if (siblings.length > 1) {
          const idx = siblings.indexOf(cur) + 1;
          seg += ':nth-of-type(' + idx + ')';
        }
      }
      parts.unshift(seg);
      cur = parent;
    }
    return parts.join(' > ') || ('body > ' + el.tagName.toLowerCase());
  }

  // Get label/description for an element
  function getLabel(el) {
    if (el.getAttribute('aria-label')) return el.getAttribute('aria-label').trim();
    if (el.getAttribute('aria-labelledby')) {
      const ids = el.getAttribute('aria-labelledby').trim().split(/\s+/);
      const texts = ids.map(id => {
        const ref = document.getElementById(id);
        return ref ? ref.textContent.trim() : '';
      }).filter(Boolean);
      if (texts.length) return texts.join(' ');
    }
    if (el.id) {
      const label = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
      if (label) return label.textContent.trim();
    }
    const parentLabel = el.closest('label');
    if (parentLabel) {
      const clone = parentLabel.cloneNode(true);
      clone.querySelectorAll('input,select,textarea,button').forEach(i => i.remove());
      const text = clone.textContent.trim();
      if (text) return text;
    }
    // For links/buttons: use their own visible text as label if short
    if (['a', 'button'].includes(el.tagName.toLowerCase())) {
      const ownText = (el.textContent || '').replace(/\s+/g, ' ').trim();
      if (ownText.length <= 80) return ownText;
    }
    if (el.getAttribute('title')) return el.getAttribute('title').trim();
    if (el.getAttribute('placeholder')) return el.getAttribute('placeholder').trim();
    return '';
  }

  // Get input value preview
  function getValue(el) {
    const tag = el.tagName.toLowerCase();
    if (tag === 'input') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      if (['checkbox', 'radio'].includes(type)) return el.checked ? '✓ checked' : '☐ unchecked';
      if (type === 'file') return el.files && el.files.length ? el.files.length + ' file(s)' : '';
      if (['hidden', 'image', 'button', 'submit', 'reset'].includes(type)) return '';
      return el.value || '(empty)';
    }
    if (tag === 'select') {
      const opts = el.selectedOptions;
      if (opts && opts.length) return Array.from(opts).map(o => o.text).join(', ');
      return '(none selected)';
    }
    if (tag === 'textarea') return el.value ? '"' + el.value.trim().slice(0, 40) + '"' : '(empty)';
    return '';
  }

  // Collect all interactive elements with their refs and selectors
  const refs = {};
  let refCounter = 0;

  function addRef(el) {
    if (refCounter >= MAX_REFS) return null;
    refCounter++;
    const key = 'e' + refCounter;
    refs[key] = {
      selector: getSelector(el),
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute('role') || '',
      label: getLabel(el),
      value: getValue(el),
    };
    return key;
  }

  // Build tree lines
  const lines = [];

  function describeElement(el, depth, frameIndex) {
    if (depth > MAX_DEPTH) return;
    if (!el || el.nodeType !== 1) return;
    if (!isVisible(el)) return;

    const tag = el.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'template', 'svg', 'path',
         'link', 'meta', 'head', 'br', 'hr'].includes(tag)) return;

    const role = el.getAttribute('role') || '';
    const disabled = el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true';
    const label = getLabel(el);
    const text = (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, TEXT_LIMIT);

    let ref = '';
    const isInteractive = INTERACTIVE_SELECTORS.some(sel => {
      try { return el.matches(sel); } catch(e) { return false; }
    });

    const isLandmark = !isInteractive && LANDMARK_SELECTORS.some(sel => {
      try { return el.matches(sel); } catch(e) { return false; }
    });

    if (isInteractive && !disabled) {
      const key = addRef(el);
      if (key) ref = '[@' + key + ']';
    }

    const indent = '  '.repeat(Math.min(depth, MAX_DEPTH));
    const prefix = frameIndex !== null ? '[f' + frameIndex + '] ' : '';

    if (ref) {
      const roleTag = role || tag;
      const labelStr = label ? '"' + label.slice(0, 60) + '"' : '';
      const valStr = getValue(el);
      const valDisplay = valStr ? ' = ' + valStr : '';
      const typeAttr = tag === 'input' ? (el.getAttribute('type') || 'text') : '';
      const typeStr = typeAttr ? ' [type=' + typeAttr + ']' : '';
      const disabledStr = disabled ? ' (disabled)' : '';
      lines.push(indent + prefix + ref + ' ' + roleTag + typeStr + ' ' +
                 (labelStr || (text ? '"' + text + '"' : '')) + valDisplay + disabledStr);
    } else if (isLandmark && depth < 5) {
      // Report landmarks even if not interactive (structural context)
      const roleLabel = role || tag;
      const labelStr = label ? '"' + label.slice(0, 60) + '"' : '';
      lines.push(indent + prefix + '[' + roleLabel + '] ' + labelStr);
    }

    // Process children (limit to reduce noise)
    const children = Array.from(el.children).filter(c => isVisible(c)).slice(0, 40);
    for (const child of children) {
      describeElement(child, depth + 1, frameIndex);
    }
  }

  // Main frame
  describeElement(document.body, 0, null);

  // Portal / popover detection: scan direct body children with high z-index
  // or fixed/absolute positioning that are likely React popovers, modals, or
  // dropdown menus rendered outside the normal document flow.
  try {
    const popoverChildren = Array.from(document.body.children).filter(el => {
      if (!isVisible(el)) return false;
      const style = getComputedStyle(el);
      const zIndex = parseInt(style.zIndex) || 0;
      const pos = style.position;
      // Heuristic: fixed/absolute with z-index >= 100, or any element with z-index >= 1000
      return (zIndex >= 100 && (pos === 'fixed' || pos === 'absolute')) || zIndex >= 1000;
    });
    if (popoverChildren.length > 0) {
      lines.push('');
      lines.push('  --- popover ---');
      for (const popover of popoverChildren) {
        if (refCounter < MAX_REFS) {
          describeElement(popover, 1, null);
        }
      }
    }
  } catch(e) { /* popover detection best-effort */ }

  // Shadow DOM roots
  try {
    const shadowHosts = document.querySelectorAll('*');
    for (const host of shadowHosts) {
      if (host.shadowRoot && host.shadowRoot.children.length) {
        describeElement(host.shadowRoot, 1, null);
      }
    }
  } catch(e) { /* cross-origin shadow roots throw */ }

  // Iframes
  const iframes = Array.from(document.querySelectorAll('iframe'));
  for (let fi = 0; fi < iframes.length; fi++) {
    const iframe = iframes[fi];
    try {
      if (!isVisible(iframe)) continue;
      const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
      if (!iframeDoc || !iframeDoc.body) continue;
      describeElement(iframeDoc.body, 1, fi);
    } catch(e) {
      // Cross-origin iframe — note but skip
      lines.push('  [iframe src="' + (iframe.getAttribute('src') || '').slice(0, 60) + '" — cross-origin, skipped]');
    }
  }

  return { tree: lines.join('\n'), refs, ref_count: refCounter };
})()
"""


def take_snapshot(page: Any, page_id: str, session: Any, full: bool = False, max_length: int = 12000) -> dict[str, Any]:
    """Capture accessibility tree with real CSS selectors per ref.

    Returns:
        {
            "status": "ok",
            "snapshot": "...",
            "interactive_elements": N,
            "refs": {ref_id: {"selector": "...", "tag": "...", "role": "...", "label": "..."}},
        }
    """
    try:
        result = page.evaluate(SNAPSHOT_JS)
    except Exception as exc:
        return {
            "status": "error",
            "snapshot": f"(snapshot JS failed: {exc})",
            "interactive_elements": 0,
            "refs": {},
        }

    if not result:
        return {
            "status": "ok",
            "snapshot": "(no snapshot result — page may still be loading)",
            "interactive_elements": 0,
            "refs": {},
        }

    tree_text = result.get("tree", "")
    refs_data = result.get("refs", {})
    ref_count = result.get("ref_count", 0)

    if len(tree_text) > max_length:
        # Smart truncation: cut at a line boundary
        truncated = tree_text[:max_length]
        last_newline = truncated.rfind("\n")
        if last_newline > max_length * 0.5:
            truncated = truncated[:last_newline]
        tree_text = truncated + f"\n... (truncated, {len(tree_text) - max_length} chars cut)"

    # Store refs on the session for lookup by resolve_ref
    if hasattr(session, "_ref_map"):
        session._ref_map[page_id] = refs_data
    else:
        session._ref_map = {page_id: refs_data}

    return {
        "status": "ok",
        "snapshot": tree_text,
        "interactive_elements": ref_count,
        "refs": refs_data,
    }


def resolve_ref(session: Any, page_id: str, ref: str) -> tuple[str, str, int | None]:
    """Resolve a ref to a Playwright CSS selector.

    Accepts three forms:
      - [@eN] snapshot ref (e.g. '@e5', 'e12') — looked up from the last snapshot
      - Frame index ref (e.g. 'f0', 'f1') — targets iframe by index
      - Raw CSS selector — used directly when the ref doesn't match known patterns

    Returns (clean_ref, css_selector, frame_index).
    """
    clean_ref = ref.lstrip("@")

    # 1. Known snapshot ref: look up the stored selector
    ref_map = getattr(session, "_ref_map", {}).get(page_id, {})
    if clean_ref in ref_map:
        ref_info = ref_map[clean_ref]
        selector = ref_info.get("selector", f"[role=e{clean_ref}]")
        return clean_ref, selector, None

    # 2. Frame index ref
    if clean_ref.startswith("f"):
        try:
            frame_idx = int(clean_ref[1:])
            return clean_ref, f"iframe:nth-of-type({frame_idx + 1})", frame_idx
        except ValueError:
            pass

    # 3. Raw CSS selector fallback — treat the ref string as a CSS selector directly.
    #    This handles cases where the target element isn't in the snapshot
    #    (e.g. content inside React popovers, popovers, shadow DOM).
    #    Must look like a CSS selector (contains #. [] or starts with a tag).
    raw = ref.lstrip("@")
    if any(c in raw for c in "#.[]") or raw[0].isalpha() or raw.startswith("*"):
        return raw, raw, None

    return clean_ref, f"[role=e{clean_ref}]", None
