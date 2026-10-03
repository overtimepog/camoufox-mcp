"""Hardened launch mode — a *stable, normalised* Camoufox, and what that is not.

Camoufox randomises its fingerprint on every launch and its own docs recommend
that. This module does the opposite on purpose: it makes every hardened launch
present the *same* browser surface, and it aligns that surface with the values
Firefox's own ``privacy.resistFingerprinting`` (RFP) produces rather than
fighting them.

Why alignment rather than more spoofing: RFP is not defeatable from the
fingerprint, and the two do not compose. RFP rewrites ``navigator.userAgent``
to the UA of the **real** OS family and refuses to be overridden, while
Camoufox's injected fingerprint wins for ``navigator.platform``/``oscpu``.

The mismatch is not something a custom fingerprint has to introduce — turning RFP
on over a *stock* Camoufox already produces one. Measured on a macOS host, three
configurations, same host, `hc` included because it is the third value in
dispute:

    A  hardened (pinned fingerprint for the host family + RFP)
       platform MacIntel  oscpu Intel Mac OS X 10.15      hc 12
       ua       ...Macintosh; Intel Mac OS X 10.15...     <- agrees
    B  RFP on, no custom fingerprint
       platform Win32     oscpu Windows NT 10.0; Win64; x64   hc 8
       ua       ...Macintosh; Intel Mac OS X 10.15...     <- contradicts
    C  RFP off, no custom fingerprint (Camoufox's default)
       platform Win32     oscpu Windows NT 10.0; Win64; x64   hc 12
       ua       ...Windows NT 10.0; Win64; x64...         <- agrees
       timezone America/New_York                          <- the real one

B is the important row. Camoufox's default is to pick a fingerprint's OS
independently of the host, so on a macOS host it picks Windows; RFP then forces
the UA to macOS and the two halves of the browser disagree. Neither plain
Camoufox nor plain RFP presents that combination, so it is a *rarer* browser
than either — the opposite of what a hardened mode is for. Generating the
fingerprint for the **host** family is what removes it: platform and oscpu then
agree with the UA that RFP insists on, which is row A.

Row C is what hardened mode would be without RFP: internally consistent, and
reporting the real timezone.

What this is NOT
----------------
**This is not anonymity, and it is not a defence against a determined
adversary.** It reduces uniqueness; it does not hide you. Nothing here changes
your IP address, and the reduced-but-nonzero uniqueness of a scripted browser
is still uniqueness. Uniqueness reduction and anonymity are different
properties and only one of them is on offer here. For anonymity the tool is Tor
Browser, run as itself — a browser built so that every user looks identical,
which is the property this module trades away to be stable.

Measured behaviour (macOS host, repeated launches)
--------------------------------------------------
Stable under hardened mode::

    platform MacIntel        oscpu Intel Mac OS X 10.15
    ua       RFP's own       hardwareConcurrency 12 (the fingerprint's value)
    languages en-US,en       timezone Atlantic/Reykjavik (offset 0)
    screen   1920x1080       devicePixelRatio 2
    WebGL    vendor + renderer

The timezone reads ``Atlantic/Reykjavik`` rather than ``UTC``: that is RFP's
UTC, an alias with no DST, and it is the same string Tor Browser reports.

``hardwareConcurrency`` is the pinned fingerprint's value and it **wins over
RFP** — rows A and C above agree at 12 while RFP alone (row B) reports its own
bucketed 8. So this one is stable but not RFP-normalised; if the persisted file
is replaced the number changes with it. Stable across launches and across
processes, which is what matters for linking — but 12 is not on its own a common
value, and nothing here makes it one.

Deliberately NOT stable, and this is worth knowing before relying on any of it:

* **Canvas readback differs per call, not merely per launch** — two identical
  ``toDataURL()`` calls inside one launch return different data. That is RFP's
  canvas noise doing its job, the same as in Tor Browser, and it means canvas
  output is not a linking signal in either direction. The instability is the
  feature.
* **``innerWidth``/``innerHeight`` vary between launches** because RFP
  letterboxing buckets the content area. Also by design.
* **``window.history.length`` is randomised per launch** by Camoufox itself
  (``randrange(1, 6)``), and no config key controls it.

RFP is load-bearing for the timezone specifically. Same fingerprint, same
launch options, only that pref changed::

    RFP off   tzOffset 240   tz America/New_York   <- the real timezone
    RFP on    tzOffset 0     tz Atlantic/Reykjavik

That is the leak a browser-automation session is most likely to hand over, and
it is the reason this mode exists rather than merely being a fingerprint cache.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sys
import typing
from pathlib import Path
from typing import Any

logger = logging.getLogger("camoufoxmcp")

HARDENING_DIR = Path(os.environ.get("CAMOUFOX_HARDENING_DIR", "~/.camoufoxmcp")).expanduser()
FINGERPRINT_PATH = HARDENING_DIR / "fingerprint.json"

# RFP's canonical screen, and the size every hardened launch reports. Pinning
# it through browserforge's own constraint object (min == max) is what keeps the
# generated fingerprint's screen off the "unusual resolution" list.
CANONICAL_WIDTH = 1920
CANONICAL_HEIGHT = 1080

# Applied over Camoufox's defaults. Every name here is a real Firefox pref, not
# a Tor Browser one -- `privacy.spoof_english` is the only entry that looks like
# a Tor-ism and it is genuinely in Firefox (RFPHelper.sys.mjs reads it to decide
# whether to force the en-US locale). Names were checked against RFPHelper and
# against the strings in the shipped binary rather than assumed; an invalid pref
# is silently ignored by Firefox, so a typo here would be invisible.
HARDENED_PREFS: dict[str, Any] = {
    # The load-bearing entry. Without it the real timezone is reported.
    "privacy.resistFingerprinting": True,
    # Round the content area to a standard size so the window is not a
    # one-off. This is the source of the innerWidth variation noted above.
    "privacy.resistFingerprinting.letterboxing": True,
    # Keep RFP active in private contexts too, so the surface does not change
    # depending on how a context was opened.
    "privacy.resistFingerprinting.pbmode": True,
    # 2 = force the en-US locale and English UI. A non-English locale is a
    # strong signal on its own when almost everyone else reports en-US.
    "privacy.spoof_english": 2,
    # Remote DNS: hostname lookups must not reach the local resolver.
    "network.proxy.socks_remote_dns": True,
    # Prefetch would resolve and contact hosts the page never uses.
    "network.dns.disablePrefetch": True,
    # WebRTC can expose the real address independently of any proxy.
    "media.peerconnection.enabled": False,
    # No on-disk or in-memory cache: nothing survives either the launch or the
    # process, so there is no cross-run state to recover.
    "browser.cache.disk.enable": False,
    "browser.cache.memory.enable": False,
    # Geolocation and Safe Browsing-style lookups are network callbacks that
    # betray what is being visited. Neither is needed by a scripted session.
    "geo.enabled": False,
    "privacy.trackingprotection.enabled": True,
}

# Camoufox config, not prefs. Both canvas knobs it exposes are set here; note
# this does *not* make canvas output deterministic (see the module docstring) --
# it removes Camoufox's own antialiasing offset so the remaining variation is
# RFP's, and only RFP's.
HARDENED_CONFIG: dict[str, Any] = {
    "canvas:aaOffset": 0,
    "canvas:aaCapOffset": False,
}

# `launch_options(os=...)` and `sample_webgl(os=...)` use different vocabularies
# for the same three families, so the mapping is explicit rather than inferred.
_HOST_TO_CAMOUFOX = {"darwin": "macos", "win32": "windows", "linux": "linux"}
_HOST_TO_WEBGL = {"darwin": "mac", "win32": "win", "linux": "lin"}
_CAMOUFOX_TO_WEBGL = {"macos": "mac", "windows": "win", "linux": "lin"}


def host_os_family() -> str:
    """The host's OS family, in ``launch_options``'s vocabulary."""
    return _HOST_TO_CAMOUFOX.get(sys.platform, "linux")


def _webgl_os(family: str | None = None) -> str:
    """An OS family in ``sample_webgl``'s vocabulary (``win``/``mac``/``lin``).

    Defaults to the host's, but takes an override so a fingerprint can be built
    for any family -- which is what lets the platform/RFP agreement be tested
    for all three rather than only for the machine the tests run on.
    """
    if family is None:
        return _HOST_TO_WEBGL.get(sys.platform, "lin")
    return _CAMOUFOX_TO_WEBGL.get(family, "lin")


def _nested_dataclass(hint: Any) -> type | None:
    """The dataclass inside a type annotation, if there is one.

    ``Optional[VideoCard]`` is ``Union[VideoCard, None]`` and is *not* a type,
    so a naive ``isinstance(hint, type)`` check skips it. That is not a
    cosmetic gap: ``videoCard`` is Optional, so skipping it left the WebGL pair
    as a plain dict on the way back in and ``webgl_config()`` returned None for
    every launch after the first — the pinned renderer silently reverting to
    Camoufox's per-launch random sample. Caught by the round-trip test.
    """
    if isinstance(hint, type) and dataclasses.is_dataclass(hint):
        return hint
    for arg in typing.get_args(hint):
        if isinstance(arg, type) and dataclasses.is_dataclass(arg):
            return arg
    return None


def _coerce(cls: type, data: dict[str, Any]) -> Any:
    """Rebuild a nested dataclass tree from plain JSON.

    ``Fingerprint`` is a dataclass whose fields include further dataclasses
    (``screen``, ``navigator``, ``videoCard``) and there is no ``from_dict`` —
    ``dataclasses.asdict`` is one-way. The field annotations are the only
    available schema, so they are what the rebuild is driven from. Unknown keys
    are dropped rather than passed through, so a fingerprint file written by a
    different browserforge version degrades instead of raising.
    """
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(cls):
        if field.name not in data:
            continue
        value = data[field.name]
        nested = _nested_dataclass(hints.get(field.name))
        if isinstance(value, dict) and nested is not None:
            value = _coerce(nested, value)
        kwargs[field.name] = value
    return cls(**kwargs)


def _pick_webgl_pair(family: str | None = None) -> tuple[str, str]:
    """Draw one valid WebGL vendor/renderer pair for an OS family.

    ``sample_webgl`` is Camoufox's own sampler and it draws a *random* pair on
    every call — which is exactly why WebGL is not stable between launches
    without ``webgl_config``. It is used here once, at fingerprint creation, and
    the result is persisted, so the randomness happens once and never again.

    Going through the sampler rather than hardcoding a pair is deliberate: it
    validates against the database Camoufox will later look the pair up in, so
    a pair that is valid here cannot be rejected at launch.
    """
    from camoufox.webgl.sample import sample_webgl

    sampled = sample_webgl(_webgl_os(family))
    return sampled["webGl:vendor"], sampled["webGl:renderer"]


def _fingerprint_for(family: str) -> Any:
    """Generate one fingerprint for an OS family, screen and WebGL pinned.

    Split out from persistence so each family can be built and inspected
    without touching a file -- which is what makes "the injected platform
    agrees with RFP for every family, not just this host's" a testable claim
    rather than a claim about the one machine it was measured on.

    The family is a parameter rather than always the host's because
    ``browserforge``'s own default is to choose randomly among all three, which
    is the behaviour that produced the UA/platform contradiction.

    WebGL is set here rather than left to ``launch_options``: that function
    calls ``sample_webgl`` and draws a *fresh random* pair on every launch, so
    without a pair on the fingerprint the renderer changes between launches
    while everything else stays pinned (measured: NVIDIA in one, AMD in the
    next). Draws through Camoufox's own sampler so the pair is guaranteed valid
    for the OS it will later be looked up under.
    """
    from browserforge.fingerprints import FingerprintGenerator, Screen

    fingerprint = FingerprintGenerator(browser="firefox").generate(
        os=family,
        screen=Screen(
            min_width=CANONICAL_WIDTH,
            max_width=CANONICAL_WIDTH,
            min_height=CANONICAL_HEIGHT,
            max_height=CANONICAL_HEIGHT,
        ),
    )

    vendor, renderer = _pick_webgl_pair(family)
    if fingerprint.videoCard is not None:
        fingerprint = dataclasses.replace(
            fingerprint,
            videoCard=dataclasses.replace(fingerprint.videoCard, vendor=vendor, renderer=renderer),
        )
    return fingerprint


def create_fingerprint(path: Path | None = None) -> Any:
    """Generate a fingerprint for the host OS family and persist it.

    Generated for the *host's* family on purpose. That is what makes the
    injected ``platform``/``oscpu`` agree with the ``userAgent`` RFP insists on
    reporting, and agreement is the whole value of the exercise.
    """
    family = host_os_family()
    fingerprint = _fingerprint_for(family)

    target = path or FINGERPRINT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w") as handle:
        json.dump(dataclasses.asdict(fingerprint), handle, indent=1, sort_keys=True)
    logger.info("generated a hardened fingerprint for %s at %s", family, target)
    return fingerprint


def load_or_create_fingerprint(path: Path | None = None) -> Any:
    """Return the persisted hardened fingerprint, creating it on first use.

    Every hardened launch gets the *same* object back, which is the point: a
    fingerprint that is regenerated per launch is not pinned, it is just a
    random fingerprint with extra steps.
    """
    from browserforge.fingerprints import Fingerprint

    target = path or FINGERPRINT_PATH
    try:
        with open(target) as handle:
            return _coerce(Fingerprint, json.load(handle))
    except FileNotFoundError:
        return create_fingerprint(target)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        # A corrupt or stale-format file must not brick launching. Regenerating
        # silently would change the identity without saying so, so it is logged
        # and reported through the launch result instead of hidden.
        logger.warning("hardened fingerprint at %s is unusable (%s); regenerating", target, exc)
        return create_fingerprint(target)


def webgl_config(fingerprint: Any) -> tuple[str, str] | None:
    """The ``webgl_config`` pair matching a persisted fingerprint."""
    card = getattr(fingerprint, "videoCard", None)
    if card is None or not getattr(card, "vendor", None) or not getattr(card, "renderer", None):
        return None
    return card.vendor, card.renderer


def fingerprint_summary(fingerprint: Any) -> dict[str, Any]:
    """The part of the fingerprint worth reporting back on a launch.

    Enough to answer "is this the identity I pinned?" without dumping a
    hundred fields into the tool result.
    """
    nav = fingerprint.navigator
    screen = fingerprint.screen
    card = getattr(fingerprint, "videoCard", None)
    return {
        "platform": getattr(nav, "platform", None),
        "oscpu": getattr(nav, "oscpu", None),
        "hardware_concurrency": getattr(nav, "hardwareConcurrency", None),
        "screen": [getattr(screen, "width", None), getattr(screen, "height", None)],
        "webgl_vendor": getattr(card, "vendor", None),
        "webgl_renderer": getattr(card, "renderer", None),
        "source": str(FINGERPRINT_PATH),
    }


def conflicts(
    timezone: str | None = None,
    locale: str | None = None,
    user_agent: str | None = None,
    user_data_dir: str | None = None,
) -> dict[str, str]:
    """Launch arguments that cannot be honoured under hardened mode.

    Returns ``{argument_name: why}`` for the ones that were actually passed, so
    the caller can refuse the launch and say which and why.

    These are refused rather than overridden because in every case the caller
    asked for something specific and getting the opposite back silently is
    worse than an error: the launch result would claim ``hardened: true`` while
    the session behaved as asked, and the two would disagree only in the values
    a target actually observes — the one place the disagreement is invisible
    from the inside.

    Two of them *contradict* the mode and two *defeat* it:

    * ``timezone`` and ``locale`` contradict RFP, which forces both to UTC and
      en-US. A context-level override sits in front of RFP, so the session would
      report one value to JavaScript and another to the network.
    * ``user_agent`` contradicts RFP's UA, which is derived from the real OS
      family and refuses to be overridden. The result is a header claiming one
      OS and ``navigator.platform`` claiming another — a rarer combination than
      either value alone, i.e. the opposite of the intent.
    * ``user_data_dir`` is cross-run state, which is precisely what the mode
      removes.
    """
    passed = {
        "timezone": (
            timezone,
            "RFP forces the timezone to UTC, and a context timezone_id would "
            "override that — the session would report one timezone to JavaScript "
            "and another to the network.",
        ),
        "locale": (
            locale,
            "RFP forces an en-US locale via privacy.spoof_english; a context "
            "locale would sit in front of it and reintroduce the signal the pref "
            "exists to remove.",
        ),
        "user_agent": (
            user_agent,
            "RFP reports the UA of the real OS family and refuses to be "
            "overridden, so a custom UA produces a header that contradicts "
            "navigator.platform — a rarer, more identifiable combination than "
            "either value alone.",
        ),
        "user_data_dir": (
            user_data_dir,
            "A profile directory is cross-run state, which is what the mode "
            "removes. Use an ordinary launch when persistence is the requirement.",
        ),
    }
    return {name: why for name, (value, why) in passed.items() if value}


def describe() -> dict[str, Any]:
    """What hardened mode does and does not claim.

    Returned in the launch result rather than kept in the docs alone, because
    the label is the part that matters: a caller who reads ``hardened: true``
    and assumes anonymity has been misled by the tool, not by their own
    carelessness.
    """
    return {
        "claim": "reduces uniqueness — a stable, normalised browser surface",
        "not_claimed": "anonymity",
        "prefs": sorted(HARDENED_PREFS),
        "for_anonymity": (
            "Use Tor Browser, run as itself. Its model depends on every user "
            "looking identical; this mode deliberately trades that away to be "
            "stable, so it is the wrong tool for the job."
        ),
    }
