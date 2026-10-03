# Camoufox MCP

> Stealth browser automation MCP server powered by [Camoufox](https://github.com/askjoe/camoufox) — a humanized Playwright Firefox fork. **Playwright MCP quality** with two-tier Cloudflare bypass, headed-mode viewport/window alignment, CSS selector + snapshot ref targeting, batch form filling, drag & drop, async JS evaluation, keyboard input, console capture, tab management, cookies, file upload, and annotated screenshots.

## Features

- **Stealth by default** — randomized viewports, real human mouse/keyboard patterns, spoofed fingerprints
- **Headed mode that matches what you see** — launch-time Camoufox fingerprint window is aligned with the Playwright viewport so Retina/macOS pages do not render off-screen or look zoomed/clipped
- **Two-tier Cloudflare bypass** — cloudscraper (fast HTTP) → FlareSolverr (guaranteed, with browser recovery)
- **Full browser session recovery** — `flaresolverr_solve` sets up Playwright route interception so the entire browser session works through FlareSolverr: navigate, snapshot, click, type — all transparent
- **Ref-based interaction** — snapshot-first: `[@eN]` refs from accessibility tree with real CSS selectors; click by ref, type by ref. **Also accepts raw CSS selectors** for elements not in the snapshot (React portals, popovers, etc.).
- **Snapshots know what's clickable** — each actionable ref is annotated with its live state: `disabled`, `off-screen`, or `occluded by div#banner` naming the element actually covering it. An overlay that swallows clicks is reported as such instead of failing opaquely.
- **Stale refs are refused, not silently mis-clicked** — a ref from before a navigation returns `STALE_REF` instead of clicking whatever now occupies that position. Fragment-only changes are correctly *not* treated as navigations.
- **Act and verify in one call** — `camoufox_act` reports what actually changed (navigation, DOM mutations, console errors), and `camoufox_verify` answers with deterministic checks that return the evidence they were judged on. No model judgement for things code can answer exactly.
- **Failures name the reason** — `camoufox_click` / `type` / `select` / `hover` probe the target on failure and say `covered by div#overlay` rather than describing what to go and check. `camoufox_act` reports `changed` (something happened) separately from `mutations_material` (the page reacted).
- **Tor routing, with a managed instance** — `camoufox_launch(tor=True)` routes through a tor instance the MCP owns on its own ports, with per-launch circuit isolation, country-specific exit nodes, and exit-IP verification. [Read the caveat](#tor) — this is IP isolation, **not** anonymity.
- **Hardened mode — a stable identity, not an anonymous one** — `camoufox_launch(hardened=True)` pins one persisted fingerprint, turns on Firefox's `resistFingerprinting`, and closes the real-timezone leak. This **reduces uniqueness; it is not anonymity** — see [the caveat](#hardened-mode).
- **Batch form filling** — `camoufox_fill_form` fills multiple fields at once (textbox, checkbox, radio, combobox, slider).
- **Drag & drop** — `camoufox_drag` moves elements between targets.
- **Async JavaScript** — `camoufox_evaluate` supports both sync and async expressions. Deliberately has no `timeout` parameter: Playwright's `evaluate` accepts none, and `set_default_timeout` was measured not to bound it, so the deadline goes inside the expression as a `Promise.race`.
- **Tab management** — open multiple pages, switch between them, close individually
- **Console capture** — real-time JS errors, warnings, and logs from the page
- **Auto-managed FlareSolverr** — Tier 2 automatically starts/stops Docker container on demand
- **Persistent sessions** — cookies survive restarts via `user_data_dir`
- **Proxy support** — residential proxies for harder targets
- **trafilatura integration** — production-grade readability extraction when available

## Quick Start

```bash
pip install camoufox-mcp
# With better markdown extraction:
pip install camoufox-mcp[extract]
camoufox-mcp
```

Or add to your MCP client config (`claude_desktop_config.json`, etc.):

```json
"camoufox-mcp": {
  "command": "camoufox-mcp"
}
```

### Tier 2: FlareSolverr (for hardest Cloudflare)

Tier 2 uses FlareSolverr (Docker-based headless Chromium) to bypass Turnstile, JS VM v3, and CAPTCHA challenges. The MCP server manages it automatically — it starts on first use, stops when you're done. Just have Docker installed.

```bash
# Only need Docker installed. The MCP server handles everything else.
# First Tier 2 call auto-pulls the image and starts the container.
```

## Tools (60 total)

### Browser Lifecycle

| Tool | Description |
|------|-------------|
| `camoufox_launch` | Start stealth browser (Firefox-based Playwright). Accepts `headers`/`header_scope`, `tor=True` (+ `tor_isolation`, `tor_exit_nodes`), `hardened=True`, and `account="name"` (start already logged in), `passkeys=True` (allow the software passkey authenticator) — see [Tor](#tor) and [Hardened Mode](#hardened-mode) for what each does and does not buy. |
| `camoufox_set_headers` | Set, replace, or clear custom request headers on a live session |
| `camoufox_get_headers` | Report the header policy in force (values masked unless `reveal=True`) |
| `camoufox_resize_viewport` | Resize viewport; in headed mode, relaunches Camoufox with matching fingerprint window and restores cookies/URLs |
| `camoufox_close` | Close browser and release all resources |

### Page / Tab Management

| Tool | Description |
|------|-------------|
| `camoufox_new_page` | Open a new tab (becomes active) |
| `camoufox_close_page` | Close a specific tab |
| `camoufox_list_pages` | List all open pages with URLs and active status |

### Navigation

| Tool | Description |
|------|-------------|
| `camoufox_navigate` | Navigate to URL — flags `cloudflare_blocked` if CF detected |
| `camoufox_back` | Navigate back in browser history |

### Page Interaction

| Tool | Description |
|------|-------------|
| `camoufox_snapshot` | Get interactive elements as `[@eN]` refs with real CSS selectors. Detects React portals / popovers. Annotates each ref with live state (`disabled`, `off-screen`, `occluded by div#banner`, …). |
| `camoufox_act` | **Act and verify in one call.** Fingerprints the page, performs the action, waits for it to settle, then reports what changed (`navigated`, `mutations_delta`, `mutations_material`, console errors) and optionally runs `verify` checks. This is the "did my click work?" answer with no follow-up call. |
| `camoufox_verify` | **Deterministic checks, no model involved.** `url_matches`, `text_present`, `text_absent`, `element_present`, `element_absent`, `no_console_errors`, `no_blockers`, `http_status` — each returns the evidence it was judged on. Set `timeout_ms` to poll until the condition holds. |
| `camoufox_click` | Click by ref or raw CSS selector (supports double-click) |
| `camoufox_type` | Type text into input by ref or raw CSS selector |
| `camoufox_fill_form` | Batch fill multiple fields at once (textbox, checkbox, radio, combobox, slider) |
| `camoufox_drag` | Drag one element onto another by ref or CSS selector |
| `camoufox_press` | Press keyboard key (Enter, Tab, Escape, ArrowDown, etc.) |
| `camoufox_select` | Select dropdown option by value/label/index. Accepts ref or CSS selector. |
| `camoufox_hover` | Hover over element by ref or CSS selector |
| `camoufox_scroll` | Scroll up/down by pixel amount |
| `camoufox_evaluate` | Execute JavaScript in page context (sync or async; no timeout parameter — Playwright's `evaluate` takes none, use a `Promise.race` inside the expression) |
| `camoufox_file_upload` | Upload files to a file input by ref or CSS selector |
| `camoufox_wait` | Wait for page to settle (network idle) |

### Content Extraction

| Tool | Description |
|------|-------------|
| `camoufox_read_page` | Extract page as clean markdown (trafilatura when available) |
| `camoufox_screenshot` | Take screenshot (optional annotated element overlays) |
| `camoufox_get_dialogs` | Get captured JS dialogs (alert/confirm/prompt) — auto-dismissed |
| `camoufox_console` | Get browser console messages (JS errors, warnings, logs) |

### Cookie Management

| Tool | Description |
|------|-------------|
| `camoufox_get_cookies` | Get all browser cookies (optional URL filter) |
| `camoufox_set_cookies` | Set cookies from JSON array |
| `camoufox_clear_cookies` | Clear all cookies |

### Saved Accounts (re-usable logins)

Log in once, save the session under a name, and restore it later without touching the login form again. What is saved is the browser's **session** (cookies + localStorage), not a password — no password is ever stored or requested.

| Tool | Description |
|------|-------------|
| `camoufox_save_account` | Save the live login as `name` (+ optional `site`, `username` label, `notes`). Re-saving refreshes the session and keeps old metadata |
| `camoufox_list_accounts` | List saved accounts: site, cookie domains, expiry. Never shows cookie/storage values. Optional `site` filter |
| `camoufox_load_account` | Apply a saved account to the *running* browser (cookies now, localStorage on next page load — navigate after) |
| `camoufox_delete_account` | Remove a saved account from the vault (and its keychain password) |
| `camoufox_save_credentials` | Store username + password in the **OS keychain** for autofill. `from_page=True` (default) reads them from the login form you filled in, so the password never passes through the conversation |
| `camoufox_autofill` | Fill the login form on the current page from saved credentials (`submit=True` presses Enter). Handles two-step logins. Refuses on any page that isn't the account's site |
| `camoufox_allow_login_frame` | Trust one third-party iframe host for an account's autofill (login widgets embedded from another domain). Refused by default |
| `camoufox_passkey_enable` | Turn the software passkey authenticator on for an account (`name=None` turns it off). Needs `camoufox_launch(passkeys=True)` |
| `camoufox_passkey_list` | An account's passkeys (never the keys) + recent grant/refusal decisions |
| `camoufox_passkey_delete` | Delete one passkey, or all of an account's |
| `camoufox_forget_credentials` | Remove the saved password **and TOTP secret**; keeps the session |
| `camoufox_save_totp` | Store an authenticator secret (base32 key or `otpauth://` URI) in the keychain for 2FA |
| `camoufox_autofill_totp` | Enter the current 2FA code into the page's verification field (single box or one-digit-per-box). Waits out a window about to roll over. Origin-locked; code never returned |

`camoufox_launch(account="name")` restores the session at context creation. An account-bound session is **re-saved on `camoufox_close`**, so tokens the site refreshed while you worked persist. If the live session is empty at close (the site logged you out), the previous good login is kept rather than overwritten.

```
camoufox_launch(display_mode="headed")      # log in by hand or with fill_form
camoufox_save_account("github-alice", username="alice")
camoufox_close()
...later...
camoufox_launch(account="github-alice")     # already logged in
```

#### Autofill

Sessions expire. For hands-off re-login, save the credentials once:

```
camoufox_launch(display_mode="headed")
camoufox_navigate(page, "https://example.com/login")
# type your username and password into the form yourself
camoufox_save_credentials("example-alice")       # reads them from the form; stored in the OS keychain
...later, session expired...
camoufox_navigate(page, "https://example.com/login")
camoufox_autofill("example-alice", submit=True)  # fills + presses Enter
camoufox_save_account("example-alice")           # refresh the saved session
```

- **Passwords live only in the OS keychain** (macOS Keychain, Windows Credential Locker, Secret Service/KWallet) via `keyring`. Never in the vault JSON, never in a tool result. With no secure keychain, saving is **refused** — there is no plaintext fallback.
- **Keep the password out of the chat.** Use `from_page=True`: the values are read from the form fields in the browser. Passing `password=` explicitly works but puts it in the conversation history.
- **Origin-bound.** Autofill only runs when the page host is the account's `site` (or a subdomain). `evilexample.com` does not match `example.com`. Without this, a lookalike page could talk an agent into handing over the real password.
- **Scope.** Fills visible username/password fields on the top page **and in iframes** (see below), including two-step flows (run it on each step). SMS and push approval are not handled; passkeys are covered by the [passkey authenticator](#passkeys).

#### Logins inside iframes

Embedded logins (an SSO widget, an identity provider's frame) are found automatically. Playwright can run code in any frame, so the finding is easy; the hard part is trust, because handing a password to whatever frame is on the page would let any page harvest it by embedding a hostile one. So:

- The **top-level page must still be the account's site**, always.
- Frames from the account's own site (including subdomains) are searched automatically.
- A frame from **any other domain is refused**, and the result names it: `Refused third-party iframe(s): auth.sso-vendor.com … trust it with camoufox_allow_login_frame(name, host)`. If that really is the account's login, allow exactly that host. `camoufox_allow_login_frame(name, host, remove=True)` withdraws it. Passing `frame_hosts=[...]` to `camoufox_save_credentials` does the same at save time.
- Hidden / zero-size frames are ignored, and `about:blank` / `srcdoc` frames carry no site identity so they are never searched.
- The result says where it filled (`"in": "login.example.com"`), and the same rules apply to `camoufox_autofill_totp`.

#### Passkeys

```
camoufox_launch(passkeys=True, display_mode="headed")   # must be chosen at launch
...log in normally...
camoufox_save_account("example-alice")                   # gives the account a site to lock to
camoufox_passkey_enable("example-alice")
camoufox_navigate(page, "https://example.com/security")  # (re)load, then use the site's own
                                                          # "Add a passkey" button
...later, any session...
camoufox_launch(passkeys=True, account="example-alice")
camoufox_passkey_enable("example-alice")
# click the site's "Sign in with a passkey" button
```

A **software authenticator**: while enabled, a site's `navigator.credentials.create/get` (publicKey) is answered by this server instead of the browser. It generates ES256 keys, signs assertions, and keeps the private keys **only in the OS keychain**. Disabled (`camoufox_passkey_enable()` with no name), the browser's native behaviour returns.

- **Origin-locked.** It answers only for the account's own site (or hosts trusted with `camoufox_allow_login_frame`) and declines everything else as if the user cancelled. The origin is taken from the browser-reported frame URL, never from anything the page sends. `rpId` must be the origin's host or a parent domain (the WebAuthn rule); IP addresses and bare TLDs are refused; plain `http` is refused except `localhost`.
- **Auditable.** `camoufox_passkey_list` shows every grant *and refusal* with the reason, so "why didn't it work?" has an answer.
- **No plaintext, ever.** With no secure keychain, creating a passkey is refused. Keys are persisted *before* the site is answered, so a failure can't leave a registered-but-lost passkey.
- **Honest about what it is.** Attestation is `none`; it does not claim to be a hardware key. A site that *requires* a hardware security key (some enterprise policies) will refuse it — that is not a bug to route around. Counter is always 0, which sites accept. Our copy is separate from the site's: delete a passkey in the site's security settings too.
- **Why `passkeys=True` at launch.** Camoufox runs Playwright init scripts in an isolated world the page can't see, so the shim has to be injected into the page's own world, which needs Camoufox's `main_world_eval`. That is off by default so the baseline browser stays exactly stock Camoufox. (Verified against Camoufox 152, including pages with a strict `Content-Security-Policy`; script-element injection and `eval`-based injection do *not* work there.)
- **Timing.** Passkey requests are answered while the browser is processing a tool call, so after clicking a site's passkey button, follow it with any snapshot/wait call.
- **Not covered.** Hardware-key-only sites, cross-device (QR/hybrid) flows, and resident-key management UIs.

#### 2FA (authenticator codes)

```
camoufox_save_totp("example-alice", "JBSW Y3DP EHPK 3PXP")   # the setup key shown beside the site's QR code
...at login...
camoufox_autofill("example-alice", submit=True)              # username + password
camoufox_autofill_totp("example-alice", submit=True)         # on the 2FA prompt
```

Codes are generated locally (RFC 6238, standard library only; SHA1/256/512, 6–8 digits, any period) from a secret held in the OS keychain. Same origin lock as password autofill. If the current window has under 4 seconds left, it waits for the next one so the code isn't stale when the site checks it. **Caveat:** unlike a password, the setup key can't be read off a form, so `camoufox_save_totp` passes it through the conversation once — treat it as exposed to that history. Storing the password *and* the TOTP secret together means this tool alone can satisfy both factors; that is the usual trade-off of any password manager that holds both, so only do it for accounts where that is acceptable.

**Security.** A saved session is a credential: anyone who can read the file can act as that account. Files live in `~/.camoufoxmcp/accounts/` (override with `CAMOUFOX_MCP_ACCOUNTS_DIR`), directory `0700`, files `0600`, written atomically. Account names are restricted to `[A-Za-z0-9._-]` so a name can never address a file outside the vault. Sites can still expire a session server-side; when that happens, log in again and re-save. `account` cannot be combined with `user_data_dir` (a whole browser profile) — pick one.

### Custom Request Headers

Some bug-bounty programs require an attribution header on **all** traffic —
`HackerOne: yourhandle` is the common form. Attach it at launch:

```python
camoufox_launch(
    display_mode="headed",
    headers={"HackerOne": "myhandle"},
    header_scope=["example.com"],     # <- pass this
)
```

Or change it on a session that is already running:

```python
camoufox_set_headers({"HackerOne": "myhandle"}, ["example.com"])
camoufox_set_headers(None)            # clear
camoufox_get_headers()                # what is actually in force
```

**Always pass `header_scope` when the header identifies you.** Without it the
header is applied context-wide, which means it also rides on every third-party
request the page makes — CDNs, analytics, fonts. That discloses your engagement
to hosts that are not part of the program and cannot be being tested. With a
scope, the header is attached only to matching hosts (an entry covers the host
and its subdomains) and is actively **stripped** from everything else, including
third-party requests and any value that was previously set context-wide. The
unscoped path returns a `warning` saying so, because it is easy to reach by
simply omitting an argument.

**A custom header forces a CORS preflight, and that can break a site.** The
header is not CORS-safelisted, so the browser must send an `OPTIONS` preflight
before any cross-origin request carrying it. If a page calls its API on a
different origin and that API does not answer `OPTIONS`, every response is
discarded and the app renders an empty shell — 0 form fields, no visible error
in the DOM, and a console full of `CORS header 'Access-Control-Allow-Origin'
missing` with status `405`. A `GET` to the same endpoint from `httpx` or `curl`
will still return 200, which is what makes it confusing: the header is not
breaking the API, it is breaking the browser's ability to *read* it. If a site
fails to load right after you add a header, this is why — and scoping the header
to the single origin that needs it is often the fix.

### Bug Bounty / API Tools

| Tool | Description |
|------|-------------|
| `camoufox_extract_tokens` | Grab JWT, CSRF, cookies from session (generic, any web app) |
| `camoufox_api_call` | Make authenticated API call using browser session (auto-detect CSRF) |
| `camoufox_js_extract` | Find endpoints/secrets in loaded JavaScript bundles |
| `camoufox_network_capture` | Capture XHR/fetch traffic for API endpoint discovery |

### Cloudflare Bypass — Two Tiers

| Tier | Tool | Speed | What it does |
|------|------|-------|---------------|
| 1 | `camoufox_cloudscraper_fetch` | ~100-500ms | HTTP-level JS solver: IUAM, JS v1, JS v2 |
|   | `camoufox_cloudscraper_solve` | ~1-2s | Cookie injection into browser |
| 2 | `camoufox_flaresolverr_fetch` | ~1-15s | Turnstile, JS VM v3, CAPTCHA — returns content + links |
|   | `camoufox_flaresolverr_solve` | ~1-15s | **Full browser recovery via route interception** — browser works normally after |

| Tool | Description |
|------|-------------|
| `camoufox_flaresolverr_start` | Start FlareSolverr Docker container |
| `camoufox_flaresolverr_stop` | Stop FlareSolverr container |
| `camoufox_flaresolverr_health` | Check if FlareSolverr is running |

### Ref Freshness — Why a Click Can Be Refused

A `[@eN]` ref is a *remembered position* in the accessibility tree, not a live
handle. After a navigation, `e5` is not "the button" any more — it is whatever
now occupies that slot, and clicking it silently acts on the wrong element.
That failure looks like success, which is the worst kind.

So a ref from before a navigation is refused:

```json
{"status": "error",
 "error": "STALE_REF @e5: Page navigated since the snapshot (epoch 3 -> 4)",
 "hint": "Re-run camoufox_snapshot; every [@eN] ref from before the navigation now points at whatever occupies that position"}
```

Three verdicts, reported as `ref_freshness` on the action itself:

| Verdict | When | What happens |
|---------|------|--------------|
| `fresh` | nothing material changed | action proceeds |
| `stale_warning` | the DOM moved, no navigation | action **proceeds** and reports it — most mutations are unrelated to the element in hand, so refusing would make the tool unusable on a live page |
| `hard_stale` | the page navigated | action is **refused** |

Two details worth knowing, because both were measured rather than assumed:

- **A fragment change is not a navigation.** Playwright reports `location.hash = 'x'` as a navigation, but the document is unchanged and the refs are still
  valid. Counting it would hard-stale every ref on any scroll-spy or anchor-link
  page — most documentation sites — so the guard ignores fragment-only changes.
- **A reload *is* a navigation**, and it reuses the same URL, so it cannot be
  detected by comparing URLs. It is caught from the `load` event instead.

### When an action fails, it says why

`camoufox_click`, `camoufox_type`, `camoufox_select` and `camoufox_hover` probe
the target's state on failure and name the reason, rather than returning a
sentence about what to go and check:

```
"hint": "The target was already covered by div#overlay before the action,
         which is the likely reason it had no effect."
```

The generic wording ("*If* the element is covered by an overlay,
`camoufox_snapshot` marks it `[occluded by ...]`") is still what you get when
the probe itself cannot run — if the element is gone, there is no state to
report and guessing would be a fabrication.

Note that `camoufox_click` still fails on a covered element *by timeout*:
Playwright's actionability check waits for the element to become clickable and
gives up after 5 s. The guard does not pre-empt it. What the tool adds is the
explanation, so the 5 s is not spent wondering.

### `changed` vs `mutations_material`

`camoufox_act` reports both, and they answer different questions:

| Field | Question | Notes |
|-------|----------|-------|
| `changed` | did anything happen at all? | true for **any** DOM mutation, a URL change, or a title change |
| `mutations_material` | did the page *react*? | true only when the mutation count crossed a bucket (25), so ordinary churn does not read as a response |

`changed` is computed from the raw mutation count, deliberately. An earlier
version compared that raw count against the bucket size, so an action had to
cause 26 mutations before it counted as a change — and clicking a button that
appends one `<p>` reported `changed: false` while the element was demonstrably
in the document. Whether a change was *material* is a judgement; whether one
happened is not, and the two must not share a threshold.

Raw CSS selectors are never refused: they are re-resolved against the live DOM on
every use, so they never point at a remembered position.

## Tor

Camoufox can route through Tor, with a **managed tor instance owned by the MCP**
on dedicated ports (`19050`/`19051`) so it never touches a Tor Browser or system
daemon you already have running.

> ### ⚠️ Read this before using Tor
>
> **Camoufox-over-Tor gives reachability and IP isolation — not anonymity.**
> Camoufox randomises fingerprints, and Tor's anonymity model depends on every
> user looking *identical*. A randomised fingerprint makes your session *more*
> unique, not less. Do not treat this as an anonymity tool.
>
> **Tor will make bot challenges harder, not easier.** Exit IPs are heavily
> blocklisted, so Cloudflare and Arkose are more likely to challenge you, not
> less. Tor here is for geo-specific egress and per-session IP isolation. It is
> not a bypass tier.

| Tool | Description |
|------|-------------|
| `camoufox_tor_status` | Local only, no network. Managed instance plus every discovered endpoint (managed → Tor Browser → system daemon), each flagged with `in_use_by` so you can see when a port belongs to something of yours. |
| `camoufox_tor_start` | Start the managed instance if needed. Reports bootstrap progress (~60s on first run) and the exit IP. |
| `camoufox_tor_stop` | Idempotent teardown. Safe to call when nothing is running. |
| `camoufox_tor_new_circuit` | Optionally apply `exit_nodes`, send `SIGNAL NEWNYM`, then **measure the new exit IP and report before/after** — rotation and confirmation in one call. |
| `camoufox_tor_exit_info` | Network round trip (~2-5s): exit IP, `IsTor`, geo, and the headers a target sees. Slow, which is why it is separate from `status`. |

```python
camoufox_launch(tor=True)                                  # random circuit
camoufox_launch(tor=True, tor_isolation="job-a")           # stable, distinct circuit
camoufox_launch(tor=True, tor_exit_nodes="{us}")           # country-specific egress
```

**Isolation is one SocksPort per label.** The managed torrc declares a fixed pool
of listeners — the base `19050` plus eight isolation slots at `19060`-`19067`
(`CAMOUFOX_TOR_ISOLATION_SLOTS` to change it). A `tor_isolation` label is
assigned a slot the first time it is seen and keeps it in
`~/.camoufoxmcp/tor/isolations.json`, so the same label always returns to the
same circuit and two different labels never share one. This rests on tor's own
default rather than on a credential: *streams received on different SocksPorts
are always isolated from one another*, even with no authentication configured.

Two consequences worth knowing before you rely on it:

- **Omit the label and you get the base circuit**, shared with every other
  unlabelled session. There is deliberately no automatic per-launch label —
  each one permanently claims a slot from a pool fixed at tor's startup, so
  auto-generated labels would fill the pool with names nothing will reuse.
  Ask for a label (or `tor_new_circuit`) when you want a circuit of your own.
- **`NEWNYM` is global.** It marks every circuit dirty, so it rotates the base
  circuit *and* every label's at once. A label separates two sessions from each
  other; it does not shelter one from a rotation. There is no per-label
  rotation in the control protocol.

**Isolation is per launch, not per page.** Playwright's proxy is set per browser
context and Camoufox runs a single context, so `tor_isolation` yields a distinct
circuit per *browser launch*. Parallel work needing distinct circuits means
multiple launches.

`camoufox_launch(tor=True)` also sets `network.proxy.socks_remote_dns=true`
(otherwise DNS leaks straight past Tor) and `media.peerconnection.enabled=false`
(WebRTC can expose the real IP). Passing both `tor=True` and an explicit `proxy`
is an error rather than a silent precedence rule.

Nothing is proxied through the user's own Tor Browser or system tor daemon, and
`SIGNAL NEWNYM` is only ever sent to the managed instance.

## Hardened Mode

`camoufox_launch(hardened=True)` trades Camoufox's per-launch randomness for a
**stable, normalised identity**: one fingerprint generated once and persisted,
Firefox's `privacy.resistFingerprinting` (RFP) turned on, humanisation off, no
profile reuse, no cache.

> ### ⚠️ This is not anonymity either
>
> The distinction from the Tor caveat above is not pedantry, it is the whole
> claim. Hardened mode **reduces uniqueness** — the same surface every launch,
> and the real timezone no longer leaks — but **your IP address is untouched**,
> and a stable identity is a small haystack, not a crowd. An identity shared by
> one browser is still an identity.
>
> **For anonymity the tool is Tor Browser, run as itself.** Its model depends on
> every user looking identical; hardened mode deliberately trades that away to
> be stable, so it is the wrong tool for that job. `hardened=True` combines with
> `tor=True` and is strictly better than `tor` alone — it is still not anonymity.
>
> It is also **not a defence against a determined adversary.** It removes the
> obvious signals a scripted browser leaks. It does not make the browser
> indistinguishable from a human one.

### What it pins, measured

Two hardened launches, separate processes, macOS host:

| Value | Hardened | Notes |
|---|---|---|
| `navigator.platform` | `MacIntel` | the fingerprint's, agreeing with RFP's UA |
| `navigator.oscpu` | `Intel Mac OS X 10.15` | as above |
| `navigator.userAgent` | RFP's own | RFP derives it from the real OS family and refuses an override |
| `hardwareConcurrency` | `12` | **the fingerprint's value wins over RFP** — see below |
| `navigator.languages` | `en-US,en` | `privacy.spoof_english=2` |
| timezone | `UTC` (offset `0`) | **the leak this mode exists to close** |
| screen | `1920x1080` | pinned through the generator, not left to chance |
| `devicePixelRatio` | `2` | |
| WebGL vendor/renderer | pinned pair | the fingerprint alone does *not* pin this |

Deliberately **not** stable, and worth knowing before relying on any of it:

- **Canvas readback differs per call, not per launch** — two identical
  `toDataURL()` calls inside one launch return different data. That is RFP's
  canvas noise working, the same as in Tor Browser, and it means canvas output is
  not a linking signal in either direction. The instability is the feature.
- **`innerWidth`/`innerHeight` vary between launches** — RFP letterboxing buckets
  the content area. Also by design.
- **`window.history.length` is randomised per launch** by Camoufox itself, and no
  config key controls it.

Three findings shaped the implementation, each of which changed it:

1. **The fingerprint must be generated for the host's OS family.** RFP rewrites
   the UA to the real OS family and refuses to be overridden, while the injected
   fingerprint owns `navigator.platform`. Three configurations, same macOS host:

   | | platform | oscpu | UA | `hc` |
   |---|---|---|---|---|
   | hardened (fingerprint for host + RFP) | `MacIntel` | `Intel Mac OS X 10.15` | macOS | 12 |
   | RFP on, no custom fingerprint | `Win32` | `Windows NT 10.0; Win64; x64` | macOS | 8 |
   | neither (Camoufox default) | `Win32` | same | Windows | 12 |

   The middle row is the point: **stock Camoufox with RFP is already
   self-contradictory**, because Camoufox picks a fingerprint OS independently of
   the host. That combination is rarer than either plain Camoufox or plain RFP —
   the opposite of the intent. Generating for the host family is what removes it.
2. **The fingerprint alone does not pin WebGL.** `launch_options` re-samples a
   random vendor/renderer on every launch, so the renderer changed between
   launches while everything else held (NVIDIA in one, AMD in the next).
   `webgl_config` is required.
3. **RFP is load-bearing for the timezone.** Same fingerprint, same options, only
   that pref changed: with RFP off, `tzOffset 240` / `America/New_York`; with it
   on, `tzOffset 0` / `Atlantic/Reykjavik` (RFP's UTC alias — the same string Tor
   Browser reports). That is the leak a scripted browser is most likely to hand
   over, and the reason this is a mode rather than a fingerprint cache.
4. **`hardwareConcurrency` is the fingerprint's, not RFP's.** Rows 1 and 3 agree
   at 12 while RFP alone reports its bucketed 8, so this value is stable but not
   RFP-normalised — and 12 is not on its own a common value. Replacing the
   persisted file changes it.

### Refused rather than silently overridden

`hardened=True` rejects `timezone`, `locale`, `user_agent`, and `user_data_dir`,
each with the reason. All four are cases where the caller asked for something
specific, and returning the opposite while reporting `hardened: true` would
disagree only in the values a target actually observes — the one place the
disagreement is invisible from the inside.

The identity lives in `~/.camoufoxmcp/fingerprint.json` (override with
`CAMOUFOX_HARDENING_DIR`). Delete it to get a new identity. Every launch reports
what it pinned under `hardened` in the result, alongside `humanize: false`.

`hardened=True` and `tor=True` are orthogonal and compose.

## Headed Mode Viewport Alignment

Camoufox spoofs browser fingerprint values such as `window.innerWidth` and `window.outerWidth`. In headed mode, Camoufox MCP now keeps that spoofed fingerprint window aligned with Playwright's viewport so visually centered pages, OAuth/login screens, and responsive layouts render where the user actually sees them.

```python
# Launch a comfortable headed browser for manual login / visual QA
camoufox_launch(
    display_mode="headed",
    viewport_width=1280,
    viewport_height=800,
)

# Auto-fit to the detected screen on macOS, or pass explicit dimensions
camoufox_resize_viewport(width=0, height=0)
camoufox_resize_viewport(width=1440, height=900)
```

In headed mode, `camoufox_resize_viewport` relaunches Camoufox with a matching fingerprint window and restores cookies, storage state, open page URLs, and the active page id. In headless mode, it performs a normal Playwright viewport resize.

## Cloudflare Bypass Workflow

When `camoufox_navigate` returns `cloudflare_blocked: true`:

### Fetch content only (fast, no browser needed)

```
flaresolverr_fetch(url) → content + links array
  Returns a 'links' array for directory discovery (supports <a href> and phx-click).
```

### Full browser session recovery (the browser works normally after)

```
navigate → cf_blocked
  → flaresolverr_solve(page_id) → routes_active: true
  → navigate (same URL) → page loads!  ← CF bypassed transparently
  → snapshot / click / type / read_page — all work normally

How it works:
  flaresolverr_solve sets up Playwright route interception — ALL document/xhr/fetch requests
  to the CF-protected domain are proxied through FlareSolverr's headless
  Chromium (which has CF clearance). Subresources load directly for speed.
  The browser renders normally — no tools behave differently.
```

### Example

```python
# Navigate to a hard target
result = camoufox_navigate("page_abc", "https://vx-underground.org/")

if result.get("cloudflare_blocked"):
    # Recover full browser session — routes ALL requests through FlareSolverr
    camoufox_flaresolverr_solve(page_id="page_abc")

    # Now navigate normally — FlareSolverr handles CF transparently
    camoufox_navigate("page_abc", "https://vx-underground.org/")
    # → cloudflare_blocked: false, title: "Vx Underground"

    # All normal tools work:
    camoufox_snapshot("page_abc")     # Interactive elements with [@eN] refs
    camoufox_read_page("page_abc")    # Full content as markdown
    camoufox_click("page_abc", "@e8") # Click file entries
    camoufox_scroll("page_abc")       # Scroll normally
```

## Architecture

```
camoufox-mcp/
├── camoufoxmcp/
│   ├── __init__.py              # v0.9.0
│   ├── __main__.py              # Entry point
│   ├── server.py                # FastMCP server + 60 tool definitions
│   ├── session.py               # BrowserSession: lifecycle, dialogs, console, cookies, tabs
│   ├── snapshot.py              # Accessibility-tree snapshot + CSS selector ref resolution
│   ├── markdown.py              # trafilatura + regex fallback markdown extraction
│   ├── vision.py                # Screenshots with optional element annotation overlays
│   ├── tor.py                   # Tor control protocol, managed instance, exit verification
│   ├── observe.py               # Blocker taxonomy, page fingerprint, deterministic checks
│   ├── accounts.py              # Account vault: named, re-usable saved logins (0600 files)
│   ├── frames.py                # Find login/2FA fields across top page + trusted iframes
│   ├── passkeys.py              # Software WebAuthn authenticator (keys in keychain, origin-locked)
│   ├── credentials.py           # Keychain-backed username/password storage + login-field detection for autofill
│   ├── hardening.py             # Hardened mode: pinned fingerprint + RFP (not anonymity)
│   ├── cloudscraper_bridge.py   # Tier 1: HTTP JS solver + cookie injection
│   └── flaresolverr_bridge.py   # Tier 2: solve, fetch (raw + text), links, Docker mgmt
├── pyproject.toml
└── tests/
```

## Development

```bash
git clone https://github.com/overtimepog/camoufox-mcp.git
cd camoufox-mcp
pip install -e ".[dev,extract]"
pytest tests/
```

## Why Camoufox over CloakBrowser?

| | CloakBrowser | Camoufox |
|---|---|---|
| Engine | Source-patched Chromium | Humanized Playwright (Firefox/Chromium) |
| Cloudflare | Passes Turnstile/reCAPTCHA | Two-tier bypass: cloudscraper → FlareSolverr |
| CF auto-management | Manual cookie import | Auto-start/stop Docker FlareSolverr |
| Browser recovery | N/A | Route interception: `flaresolverr_solve` recovers the entire browsing session |
| Console capture | — | Real-time JS error/warning/log capture |
| Tab management | — | Multi-page with active tracking |
| Cookie management | — | Get/set/clear cookies programmatically |
| Markdown quality | — | trafilatura (production readability) + fallback |
| Maintenance | You maintain the fork | Active upstreams (askjoe, cloudscraper, FlareSolverr) |
| Platforms | Linux/Windows/macOS | Linux/Windows/macOS |

## License

Apache-2.0
