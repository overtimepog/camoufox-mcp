"""Accessibility-tree snapshot with [@eN] ref IDs and CSS selector mapping.

Uses a two-pass approach:
  1. JS injection: collect interactive DOM elements with their CSS selectors + a11y info
  2. Build a human-readable tree with @eN refs that map to real selectors
"""

from __future__ import annotations

import re
import uuid
from typing import Any


SNAPSHOT_JS = r"""
(() => {
  const MAX_DEPTH = 12;
  const TEXT_LIMIT = 50;
  const MAX_REFS = 200;

  // Interactive element selectors (matches Playwright a11y roles)
  const INTERACTIVE_SELECTORS = [
    'a[href]', 'button', 'input', 'select', 'textarea',
    '[role="button"]', '[role="link"]', '[role="checkbox"]', '[role="radio"]',
    '[role="tab"]', '[role="menuitem"]', '[role="switch"]', '[role="combobox"]',
    '[role="slider"]', '[role="spinbutton"]', '[role="textbox"]', '[role="searchbox"]',
    '[role="listbox"]', '[role="option"]', '[role="menuitemcheckbox"]', '[role="menuitemradio"]',
    '[role="treeitem"]', '[role="tree"]', '[role="grid"]', '[role="row"]',
    '[tabindex]:not([tabindex="-1"])', '[contenteditable="true"]',
    'summary', 'details > summary'
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
    for (const attr of ['data-testid', 'data-test-id', 'data-cy', 'data-e2e']) {
      if (el.hasAttribute(attr)) {
        return el.tagName.toLowerCase() + '[' + attr + '="' +
          el.getAttribute(attr).replace(/"/g, '\\"') + '"]';
      }
    }

    // 2. id is unique
    if (el.id) {
      const safeId = el.id.replace(/"/g, '\\"');
      const sel = '#' + CSS.escape(el.id);
      if (document.querySelectorAll(sel).length === 1) return sel;
    }

    // 3. Build path with classes and nth-of-type
    const parts = [];
    let cur = el;
    for (let i = 0; i < 4 && cur && cur !== document.body; i++) {
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
    return parts.join(' > ') || 'body';
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
      clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
      const text = clone.textContent.trim();
      if (text) return text;
    }
    if (el.getAttribute('title')) return el.getAttribute('title').trim();
    if (el.getAttribute('placeholder')) return el.getAttribute('placeholder').trim();
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
    };
    return key;
  }

  // Build tree lines
  const lines = [];
  let inIframe = false;

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

    if (isInteractive && !disabled) {
      const key = addRef(el);
      if (key) ref = '[@' + key + ']';
    }

    const indent = '  '.repeat(Math.min(depth, MAX_DEPTH));
    const prefix = frameIndex !== null ? '[f' + frameIndex + '] ' : '';

    if (ref) {
      lines.push(indent + prefix + ref + ' [' + (role || tag) + '] ' +
                 (label ? '"' + label.slice(0, 60) + '"' : (text ? '"' + text + '"' : '')));
    } else if (role && ['dialog', 'alertdialog', 'tooltip', 'menu', 'list', 'tree',
                         'grid', 'table', 'navigation', 'banner', 'contentinfo',
                         'main', 'article', 'section'].includes(role)) {
      lines.push(indent + prefix + '[' + role + '] ' + (label ? '"' + label.slice(0, 60) + '"' : ''));
    }

    // Process children (limit to reduce noise)
    const children = Array.from(el.children).filter(c => isVisible(c)).slice(0, 30);
    for (const child of children) {
      describeElement(child, depth + 1, frameIndex);
    }
  }

  // Main frame
  describeElement(document.body, 0, null);

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
      // Cross-origin iframe — skip
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
        tree_text = tree_text[:max_length] + f"\n... (truncated, {len(tree_text) - max_length} chars cut)"

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
    """Resolve a [@eN] ref to a Playwright CSS selector.

    Returns (clean_ref, css_selector, frame_index).

    The CSS selector is a real selector that can be used with page.click(selector),
    page.fill(selector), etc. via Playwright's locator API.
    """
    clean_ref = ref.lstrip("@")

    ref_map = getattr(session, "_ref_map", {}).get(page_id, {})

    if clean_ref in ref_map:
        ref_info = ref_map[clean_ref]
        selector = ref_info.get("selector", f"[role=e{clean_ref}]")
        return clean_ref, selector, None

    # Fallback: try to build something reasonable
    # Check if it's a frame index
    if clean_ref.startswith("f"):
        try:
            frame_idx = int(clean_ref[1:])
            return clean_ref, f"iframe:nth-of-type({frame_idx + 1})", frame_idx
        except ValueError:
            pass

    return clean_ref, f"[role=e{clean_ref}]", None