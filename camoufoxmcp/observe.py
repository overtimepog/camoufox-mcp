"""Deterministic observation: blockers, page fingerprints, and checks.

Everything here is a hard check executed in code. Nothing in this module asks
a model to judge anything, which is the point: a checkpoint that can be
answered by reading the DOM should never be answered by inference, because
inference costs a round trip, is not reproducible, and is wrong often enough
to matter on exactly the pages where it matters most.

Three facilities:

  * `detect_blockers` — is this page actually the page we asked for, or an
    interstitial standing in front of it? Covers Cloudflare, Turnstile,
    reCAPTCHA, hCaptcha, **Arkose/FunCaptcha** (which is what has largely
    replaced reCAPTCHA in practice), generic bot checks, auth walls, and
    consent overlays that swallow clicks.
  * `page_fingerprint` — a cheap identity for "the page as it is right now",
    used to decide whether an [@eN] ref is still pointing at what it was
    pointing at when the snapshot was taken.
  * `run_checks` / `wait_for_checks` — assert against the live page and report
    the **evidence** each verdict was reached on, not just a boolean. A check
    that reports `passed: false` with no evidence is a check nobody can debug.

The blocker probe is a single `evaluate()` returning raw evidence, classified
afterwards by a pure Python function. Splitting it that way is deliberate: the
classification logic — the part with actual judgement in it — is then testable
offline, with no browser and no network.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

logger = logging.getLogger("camoufoxmcp")


# ---------------------------------------------------------------------------
# Blocker detection
# ---------------------------------------------------------------------------

# One round trip. Returns raw evidence only — no verdicts — so the classifying
# logic lives in Python where it can be unit tested.
_BLOCKER_PROBE_JS = r"""
() => {
  const ev = {
    title: (document.title || "").slice(0, 300),
    url: location.href,
    text: "",
    iframes: [],
    forms: [],
    overlays: [],
    scripts: [],
    has_password_field: false,
  };
  try {
    ev.text = (document.body ? (document.body.innerText || "") : "").slice(0, 30000);
  } catch (e) { ev.text = ""; }

  try {
    ev.iframes = Array.from(document.querySelectorAll("iframe"))
      .slice(0, 60)
      .map(f => ({ src: (f.src || f.getAttribute("src") || "").slice(0, 400),
                   id: f.id || "", title: f.title || "",
                   w: Math.round(f.getBoundingClientRect().width),
                   h: Math.round(f.getBoundingClientRect().height) }));
  } catch (e) {}

  try {
    ev.forms = Array.from(document.querySelectorAll("form"))
      .slice(0, 20)
      .map(f => ({ action: (f.getAttribute("action") || "").slice(0, 200),
                   id: f.id || "" }));
    ev.has_password_field = !!document.querySelector('input[type="password"]');
  } catch (e) {}

  try {
    ev.scripts = Array.from(document.querySelectorAll("script[src]"))
      .slice(0, 80)
      .map(s => (s.src || "").slice(0, 300));
  } catch (e) {}

  // Overlay detection: what is actually on top at the centre of the viewport,
  // and at four probe points, so a banner swallowing clicks is visible.
  try {
    const vw = window.innerWidth || 1, vh = window.innerHeight || 1;
    const points = [[vw/2, vh/2], [vw/2, vh*0.25], [vw/2, vh*0.75], [vw*0.5, vh*0.9]];
    const seen = new Set();
    for (const [x, y] of points) {
      const el = document.elementFromPoint(x, y);
      if (!el) continue;
      const tag = el.tagName.toLowerCase();
      if (tag === "html" || tag === "body") continue;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const key = tag + "#" + (el.id || "") + "." + (typeof el.className === "string" ? el.className : "");
      if (seen.has(key)) continue;
      seen.add(key);
      ev.overlays.push({
        tag: tag,
        id: el.id || "",
        cls: (typeof el.className === "string" ? el.className : "").slice(0, 150),
        role: el.getAttribute("role") || "",
        position: cs.position,
        zIndex: parseInt(cs.zIndex || "0", 10) || 0,
        coverage: (r.width * r.height) / (vw * vh),
        text: (el.innerText || "").slice(0, 160),
      });
    }
  } catch (e) {}

  return ev;
}
"""

# Signature fragments. Each entry is (name, where, regex, label).
# "where" is one of: title, url, text, iframe, script, overlay, form.
_BLOCKER_SIGNATURES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    # -- Cloudflare ------------------------------------------------------
    ("cloudflare", "title", re.compile(r"just a moment|attention required|checking your browser|cf-browser", re.I),
     "Cloudflare interstitial"),
    ("cloudflare", "text", re.compile(r"checking your browser before accessing|enable javascript and cookies to continue|ray id:|cloudflare", re.I),
     "Cloudflare interstitial"),
    ("cloudflare", "iframe", re.compile(r"challenges\.cloudflare\.com", re.I),
     "Cloudflare Turnstile"),
    ("cloudflare", "script", re.compile(r"/cdn-cgi/challenge-platform/", re.I),
     "Cloudflare challenge script"),
    ("cloudflare", "text", re.compile(r"verify you are human|verifying you are human", re.I),
     "Cloudflare human verification"),
    # -- Other CAPTCHAs --------------------------------------------------
    # Arkose/FunCaptcha is named explicitly because it is what displaced
    # reCAPTCHA on the sites that matter, and because it fingerprints the
    # device rather than grading an answer, so "solve the puzzle" is the
    # wrong mental model for it.
    ("arkose", "iframe", re.compile(r"arkoselabs\.com|funcaptcha", re.I),
     "Arkose Labs / FunCaptcha"),
    ("arkose", "script", re.compile(r"arkoselabs\.com|funcaptcha", re.I),
     "Arkose Labs / FunCaptcha"),
    ("arkose", "text", re.compile(r"arkose|funcaptcha", re.I),
     "Arkose Labs / FunCaptcha"),
    ("recaptcha", "iframe", re.compile(r"google\.com/recaptcha|recaptcha/api", re.I),
     "reCAPTCHA"),
    ("recaptcha", "script", re.compile(r"google\.com/recaptcha|gstatic\.com/recaptcha", re.I),
     "reCAPTCHA"),
    ("recaptcha", "overlay", re.compile(r"g-recaptcha|recaptcha", re.I),
     "reCAPTCHA"),
    ("hcaptcha", "iframe", re.compile(r"hcaptcha\.com", re.I), "hCaptcha"),
    ("hcaptcha", "script", re.compile(r"hcaptcha\.com", re.I), "hCaptcha"),
    ("hcaptcha", "overlay", re.compile(r"h-captcha|hcaptcha", re.I), "hCaptcha"),
    # -- Generic bot walls ----------------------------------------------
    ("bot_check", "text", re.compile(r"are you a robot|unusual traffic|automated queries|not a robot|bot detection|access denied.{0,40}automation", re.I),
     "generic bot check"),
    ("bot_check", "title", re.compile(r"are you a robot|access denied|blocked", re.I),
     "generic bot check"),
    ("bot_check", "text", re.compile(r"please verify you are a human|confirm you are human|human verification", re.I),
     "generic human verification"),
    # -- Auth walls ------------------------------------------------------
    ("auth_wall", "text", re.compile(r"sign in to continue|log in to continue|you must be logged in|session (?:has )?expired|please sign in", re.I),
     "authentication required"),
    ("auth_wall", "url", re.compile(r"/(?:login|signin|sign-in|auth|sso)(?:[/?#]|$)", re.I),
     "redirected to a login route"),
)

# Text on an overlay that identifies a consent/notice banner rather than a
# challenge. These swallow clicks without looking like a block, which is the
# failure this taxonomy needs to catch most: the click silently lands on the
# banner instead of the button.
_CONSENT_RE = re.compile(
    r"accept (?:all )?cookies|we use cookies|manage (?:your )?preferences|"
    r"privacy preferences|before you continue|by clicking .{0,30}you agree|"
    r"subscribe to (?:our|the) newsletter|enable notifications",
    re.I,
)

# Minimum viewport share before an overlay is treated as click-blocking.
_OVERLAY_COVERAGE_THRESHOLD = 0.35


def classify_blockers(evidence: dict[str, Any]) -> dict[str, Any]:
    """Turn raw page evidence into a blocker verdict.

    Pure function over the dict produced by `_BLOCKER_PROBE_JS`, so it is
    testable without a browser.
    """
    title = str(evidence.get("title") or "")
    url = str(evidence.get("url") or "")
    text = str(evidence.get("text") or "")
    iframes = evidence.get("iframes") or []
    scripts = evidence.get("scripts") or []
    overlays = evidence.get("overlays") or []
    forms = evidence.get("forms") or []

    haystacks: dict[str, list[str]] = {
        "title": [title],
        "url": [url],
        "text": [text],
        "iframe": [str(f.get("src", "")) + " " + str(f.get("id", "")) + " " + str(f.get("title", ""))
                   for f in iframes],
        "script": [str(s) for s in scripts],
        "overlay": [str(o.get("id", "")) + " " + str(o.get("cls", "")) + " " + str(o.get("role", ""))
                    for o in overlays],
        "form": [str(f.get("action", "")) + " " + str(f.get("id", "")) for f in forms],
    }

    matches: list[dict[str, Any]] = []
    for name, where, pattern, label in _BLOCKER_SIGNATURES:
        for value in haystacks.get(where, []):
            m = pattern.search(value)
            if m:
                matches.append({
                    "kind": name,
                    "label": label,
                    "matched_on": where,
                    "matched_text": m.group(0)[:120],
                })
                break

    # Consent overlay: only counts when it is actually large enough to be
    # intercepting clicks. A cookie notice in a corner is noise.
    consent = None
    for overlay in overlays:
        if overlay.get("coverage", 0) >= _OVERLAY_COVERAGE_THRESHOLD and _CONSENT_RE.search(str(overlay.get("text", ""))):
            consent = {
                "kind": "consent_overlay",
                "label": "consent / notice overlay",
                "matched_on": "overlay",
                "matched_text": str(overlay.get("text", ""))[:120],
                "coverage": round(float(overlay.get("coverage", 0)), 3),
                "occluder": _describe_element(overlay),
            }
            break

    # A challenge iframe is a stronger signal than a text mention, so order
    # the verdict by the most specific thing found rather than by the order
    # the signatures happen to be declared in.
    priority = ["cloudflare", "arkose", "recaptcha", "hcaptcha", "bot_check",
                "consent_overlay", "auth_wall"]

    reason = None
    if matches:
        reason = sorted({m["kind"] for m in matches},
                        key=lambda k: priority.index(k) if k in priority else 99)[0]
    elif consent:
        reason = "consent_overlay"

    if reason is None:
        return {
            "blocked": False,
            "reason": None,
            "detail": "",
            "evidence": {
                "title": title[:200],
                "url": url,
                "signals": [],
                "overlay_count": len(overlays),
            },
        }

    if consent and consent["kind"] == reason:
        detail = consent["label"]
    else:
        detail = "; ".join(sorted({m["label"] for m in matches if m["kind"] == reason}))

    signals = matches + ([consent] if consent else [])

    # A CAPTCHA is present but not necessarily blocking the specific action
    # the caller wanted. Saying so beats a bare "blocked: true", which reads
    # as "nothing can be done here".
    challenge_kinds = {"cloudflare", "arkose", "recaptcha", "hcaptcha", "bot_check"}
    hint = None
    if reason in challenge_kinds:
        hint = ("A challenge is present. Routing through Tor will generally make "
                "this harder, not easier — Tor exit addresses are heavily "
                "blocklisted. A residential proxy is the effective lever here.")
    elif reason == "consent_overlay":
        hint = ("A consent overlay covers most of the viewport and will "
                "intercept clicks. Dismiss it before interacting, or target "
                "elements with camoufox_act and check the reported occluder.")
    elif reason == "auth_wall":
        hint = "The session is not authenticated for this page."

    return {
        "blocked": True,
        "reason": reason,
        "detail": detail,
        "hint": hint,
        "evidence": {
            "title": title[:200],
            "url": url,
            "signals": signals,
            "overlay_count": len(overlays),
            "has_password_field": bool(evidence.get("has_password_field")),
        },
    }


def _describe_element(info: dict[str, Any]) -> str:
    """Human-readable identifier for an element, for reporting an occluder."""
    tag = info.get("tag") or "element"
    el_id = info.get("id") or ""
    cls = (info.get("cls") or "").split()
    desc = tag
    if el_id:
        desc += f"#{el_id}"
    elif cls:
        desc += f".{cls[0]}"
    return desc


def detect_blockers(page: Any) -> dict[str, Any]:
    """Probe a live page for blockers. Never raises."""
    try:
        evidence = page.evaluate(_BLOCKER_PROBE_JS)
    except Exception as exc:
        return {
            "blocked": False,
            "reason": None,
            "detail": f"blocker probe failed: {type(exc).__name__}: {exc}",
            "evidence": {"probe_failed": True},
        }
    if not isinstance(evidence, dict):
        return {"blocked": False, "reason": None, "detail": "probe returned no evidence",
                "evidence": {}}
    return classify_blockers(evidence)


# ---------------------------------------------------------------------------
# Mutation counting + page fingerprint
# ---------------------------------------------------------------------------

# Idempotent: installs the observer on first call and returns the running
# count thereafter. Returns -1 if MutationObserver is unavailable, which the
# freshness logic reads as "unknown" rather than as "no mutations".
#
# characterData is deliberately off: on a page with a clock or a spinner it
# would tick continuously and mark every ref permanently stale, which trains
# the caller to ignore the warning. Attribute changes are on because an
# `disabled` or `aria-expanded` flip is exactly what we want to notice.
INSTALL_MUTATION_OBSERVER_JS = r"""
() => {
  if (window.__cfxMut === undefined) {
    window.__cfxMut = 0;
    try {
      const obs = new MutationObserver((records) => { window.__cfxMut += records.length; });
      obs.observe(document.documentElement || document, {
        childList: true, subtree: true, attributes: true, characterData: false,
      });
      window.__cfxMutObs = obs;
    } catch (e) {
      window.__cfxMut = -1;
    }
  }
  return window.__cfxMut;
}
"""

READ_MUTATION_COUNT_JS = r"""
() => (window.__cfxMut === undefined ? -1 : window.__cfxMut)
"""

# Mutation counts are bucketed before comparison so that ordinary churn
# (a carousel, a lazy-loaded image) does not read as a *material* change. The
# bucket governs `mutations_material` only — never whether a change happened,
# which the raw count answers exactly. See fingerprint_delta.
MUTATION_BUCKET = 25


def mutation_bucket(count: int) -> int:
    """Bucket a raw mutation count. -1 (unknown) stays -1."""
    if count is None or count < 0:
        return -1
    return count // MUTATION_BUCKET


def install_mutation_observer(page: Any) -> int:
    """Ensure the observer is running; return the current count (-1 if unknown)."""
    try:
        count = page.evaluate(INSTALL_MUTATION_OBSERVER_JS)
        return int(count) if isinstance(count, (int, float)) else -1
    except Exception:
        return -1


def read_mutation_count(page: Any) -> int:
    """Current mutation count without installing. -1 if unknown."""
    try:
        count = page.evaluate(READ_MUTATION_COUNT_JS)
        return int(count) if isinstance(count, (int, float)) else -1
    except Exception:
        return -1


def nav_epoch(session: Any, page_id: str) -> int:
    """Navigation counter for a page, incremented on each frame navigation.

    Read defensively: a session that predates the nav-epoch tracking simply
    reports 0 for everything, which degrades to "cannot tell a navigation
    happened" rather than to a crash.
    """
    epochs = getattr(session, "_nav_epoch", None)
    if not isinstance(epochs, dict):
        return 0
    return int(epochs.get(page_id, 0))


def page_fingerprint(page: Any, session: Any, page_id: str) -> dict[str, Any]:
    """A cheap identity for the page's current state.

    Used for two things: deciding ref freshness, and computing the
    before/after delta that tells the caller whether an action did anything.

    Never raises — a fingerprint that fails is reported as `degraded`, because
    failing the action itself over a bookkeeping problem would be worse.
    """
    fp: dict[str, Any] = {
        "url": None,
        "title": None,
        "nav_epoch": nav_epoch(session, page_id),
        "mutations": -1,
        "ref_count": len(getattr(session, "_ref_map", {}).get(page_id, {}) or {}),
        "degraded": False,
    }
    try:
        fp["url"] = page.url
    except Exception:
        fp["degraded"] = True
    try:
        fp["title"] = page.title()
    except Exception:
        fp["degraded"] = True
    fp["mutations"] = read_mutation_count(page)
    return fp


def fingerprint_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """What changed between two fingerprints.

    `changed` is the answer to "did my click do anything?", which is the
    question the caller actually has. It is computed here rather than left to
    the agent because comparing two dicts is exact arithmetic, and exact
    arithmetic belongs in code.
    """
    # `navigated` means the document was replaced, which is the thing that
    # invalidates refs and is what the navigation epoch tracks. `url_changed`
    # is the weaker fact that the URL string differs — a fragment-only change
    # moves the URL without replacing the document, so collapsing the two
    # would either overstate a hash change or hide a real navigation.
    navigated = before.get("nav_epoch") != after.get("nav_epoch")
    url_changed = before.get("url") != after.get("url")
    before_mut, after_mut = before.get("mutations", -1), after.get("mutations", -1)
    mutations_delta = None
    mutations_changed = False
    mutations_material = False
    if before_mut >= 0 and after_mut >= 0:
        mutations_delta = after_mut - before_mut
        # Any increase at all is an observed change, and one inserted node is
        # an increase of one. An earlier version compared the *raw* delta
        # against MUTATION_BUCKET -- the bucket size -- so a click had to cause
        # 26 mutations before it counted, and every small real change was
        # reported as a no-op. Measured: clicking a button that appends a <p>
        # returned changed=false while the element was demonstrably in the DOM.
        #
        # The bucket is for judging whether a change was *material* (a carousel
        # or a lazy image moving vs. the page actually reacting), not for
        # deciding whether anything happened — that is a question the raw count
        # already answers, and conflating the two silently discards the answer.
        mutations_changed = mutations_delta > 0
        mutations_material = mutation_bucket(after_mut) > mutation_bucket(before_mut)
    title_changed = before.get("title") != after.get("title")

    unknown = before_mut < 0 or after_mut < 0

    return {
        "changed": navigated or url_changed or mutations_changed or title_changed,
        "navigated": navigated,
        "url_changed": url_changed,
        "title_changed": title_changed,
        "mutations_delta": mutations_delta,
        # False for ordinary churn that did not cross a bucket, so a caller can
        # tell "something moved" from "the page reacted". `changed` deliberately
        # does not consult this: we cannot attribute causation either way.
        "mutations_material": mutations_material,
        "mutations_observed": not unknown,
        "from_url": before.get("url"),
        "to_url": after.get("url"),
    }


# ---------------------------------------------------------------------------
# Deterministic checks
# ---------------------------------------------------------------------------

# The recognised check names, in the order results are reported. Listed
# explicitly so an unrecognised key can be reported as such rather than
# silently ignored — a check that does not run must never look like a check
# that passed.
CHECK_NAMES = (
    "url_matches",
    "url_not_matches",
    "text_present",
    "text_absent",
    "element_present",
    "element_absent",
    "no_console_errors",
    "no_blockers",
    "http_status",
)


def _as_list(value: Any) -> list[str]:
    if value is None or value is False:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _console_errors(session: Any, page_id: str, since: int = 0) -> list[dict[str, Any]]:
    entries = getattr(session, "_console", {}).get(page_id, []) or []
    scoped = entries[since:] if since > 0 else entries
    return [e for e in scoped if e.get("type") == "error"]


def console_index(session: Any, page_id: str) -> int:
    """Current console length, to be passed back as `console_since`.

    Checks scoped to "since I acted" are what make `no_console_errors`
    meaningful: errors from page load are usually unrelated to the action
    under test, and including them makes the check useless.
    """
    return len(getattr(session, "_console", {}).get(page_id, []) or [])


def run_checks(page: Any, session: Any, page_id: str, specs: dict[str, Any],
               console_since: int = 0) -> dict[str, Any]:
    """Evaluate deterministic checks against a live page.

    Returns `{passed, checks: [...], failed: [...], skipped: [...]}` where
    every check carries the evidence it was judged on. A check with no
    evidence is a check nobody can debug, so `evidence` is populated for
    passes as well as failures.

    Unknown check names are reported under `unknown` and make the overall
    result fail — a typo'd check name must not read as success.
    """
    results: list[dict[str, Any]] = []
    unknown: list[str] = []

    for key, value in specs.items():
        if value is None or value is False:
            continue
        if key not in CHECK_NAMES:
            unknown.append(key)
            continue

        result: dict[str, Any] = {"check": key, "passed": False, "evidence": {}}

        try:
            if key == "url_matches":
                patterns = _as_list(value)
                current = page.url
                matched = [p for p in patterns if re.search(p, current, re.I)]
                result["passed"] = bool(matched)
                result["evidence"] = {"url": current, "patterns": patterns,
                                      "matched": matched}
                result["expected"] = patterns

            elif key == "url_not_matches":
                patterns = _as_list(value)
                current = page.url
                matched = [p for p in patterns if re.search(p, current, re.I)]
                result["passed"] = not matched
                result["evidence"] = {"url": current, "patterns": patterns,
                                      "matched": matched}
                result["expected"] = f"not {patterns}"

            elif key in ("text_present", "text_absent"):
                needles = _as_list(value)
                try:
                    body = page.evaluate(
                        "() => document.body ? (document.body.innerText || '') : ''"
                    ) or ""
                except Exception as exc:
                    result["evidence"] = {"error": f"{type(exc).__name__}: {exc}"}
                    results.append(result)
                    continue
                lowered = body.lower()
                found = [n for n in needles if n.lower() in lowered]
                missing = [n for n in needles if n.lower() not in lowered]
                if key == "text_present":
                    result["passed"] = not missing
                    result["evidence"] = {"missing": missing, "found": found,
                                          "body_length": len(body)}
                    result["expected"] = needles
                else:
                    result["passed"] = not found
                    result["evidence"] = {"present_but_should_absent": found,
                                          "body_length": len(body)}
                    result["expected"] = f"absent: {needles}"

            elif key in ("element_present", "element_absent"):
                # Imported here rather than at module scope to avoid a
                # snapshot <-> observe import cycle.
                from .snapshot import resolve_ref

                refs = _as_list(value)
                found_refs: list[str] = []
                missing_refs: list[str] = []
                selectors: dict[str, str] = {}
                for ref in refs:
                    try:
                        _clean, selector, _frame = resolve_ref(session, page_id, ref)
                    except Exception:
                        selector = ref
                    selectors[ref] = selector
                    try:
                        count = page.locator(selector).count()
                    except Exception:
                        count = 0
                    (found_refs if count > 0 else missing_refs).append(ref)
                if key == "element_present":
                    result["passed"] = not missing_refs
                    result["evidence"] = {"selectors": selectors,
                                          "missing": missing_refs,
                                          "found": found_refs}
                    result["expected"] = refs
                else:
                    result["passed"] = not found_refs
                    result["evidence"] = {"selectors": selectors,
                                          "present_but_should_be_absent": found_refs}
                    result["expected"] = f"absent: {refs}"

            elif key == "no_console_errors":
                errors = _console_errors(session, page_id, console_since)
                result["passed"] = not errors
                result["evidence"] = {
                    "console_errors": [e.get("text", "")[:200] for e in errors[:10]],
                    "error_count": len(errors),
                    "scoped_from_index": console_since,
                }
                result["expected"] = "no console errors"

            elif key == "no_blockers":
                blockers = detect_blockers(page)
                result["passed"] = not blockers.get("blocked")
                result["evidence"] = {
                    "reason": blockers.get("reason"),
                    "detail": blockers.get("detail"),
                    "signals": (blockers.get("evidence") or {}).get("signals", []),
                }
                result["expected"] = "no blocker"

            elif key == "http_status":
                # PerformanceNavigationTiming.responseStatus is the only way to
                # see the main-document status from page JS. Absent on older
                # engines, in which case the check reports unverified rather
                # than passing by default.
                try:
                    status = page.evaluate(
                        "() => { const n = performance.getEntriesByType('navigation')[0];"
                        " return n && typeof n.responseStatus === 'number' ? n.responseStatus : null; }"
                    )
                except Exception:
                    status = None
                want = value
                wants = want if isinstance(want, list) else [want]
                if status is None:
                    result["passed"] = False
                    result["evidence"] = {"http_status": None,
                                          "reason": "responseStatus unavailable in this engine"}
                else:
                    result["passed"] = int(status) in [int(w) for w in wants]
                    result["evidence"] = {"http_status": int(status), "wanted": wants}
                result["expected"] = wants

        except Exception as exc:
            result["passed"] = False
            result["evidence"] = {"error": f"{type(exc).__name__}: {exc}"}

        results.append(result)

    failed = [r for r in results if not r["passed"]]
    passed = not failed and not unknown

    out: dict[str, Any] = {
        "passed": passed,
        "checks": results,
        "failed": [r["check"] for r in failed],
        "checked": len(results),
    }
    if unknown:
        out["unknown"] = unknown
        out["hint"] = f"Unrecognised checks: {unknown}. Valid: {list(CHECK_NAMES)}"
    if failed:
        out["hint"] = out.get("hint") or (
            "Failed: " + ", ".join(
                f"{r['check']} (expected {r.get('expected')!r}, saw {r['evidence']})"
                for r in failed[:3]
            )
        )
    return out


def wait_for_checks(page: Any, session: Any, page_id: str, specs: dict[str, Any],
                    timeout_ms: int = 5000, poll_ms: int = 250,
                    console_since: int = 0) -> dict[str, Any]:
    """Poll `run_checks` until every check passes or the budget runs out.

    Reports `waited_ms` and `attempts` so a caller can tell "passed
    immediately" from "passed on the last attempt", which is the difference
    between a settled page and a race that happened to land.
    """
    t0 = time.time()
    deadline = t0 + (timeout_ms / 1000.0)
    attempts = 0
    last: dict[str, Any] = {}

    while True:
        attempts += 1
        last = run_checks(page, session, page_id, specs, console_since=console_since)
        if last["passed"]:
            break
        if time.time() >= deadline:
            break
        time.sleep(min(poll_ms / 1000.0, max(0.0, deadline - time.time())))

    last["attempts"] = attempts
    last["waited_ms"] = int((time.time() - t0) * 1000)
    last["timed_out"] = not last["passed"] and last["waited_ms"] >= timeout_ms
    return last
