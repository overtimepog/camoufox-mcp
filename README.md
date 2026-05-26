# Camoufox MCP

> Stealth browser automation MCP server powered by [Camoufox](https://github.com/askjoe/camoufox) — a humanized Playwright Firefox fork. **Playwright MCP quality** with two-tier Cloudflare bypass, headed-mode viewport/window alignment, CSS selector + snapshot ref targeting, batch form filling, drag & drop, async JS evaluation, keyboard input, console capture, tab management, cookies, file upload, and annotated screenshots.

## Features

- **Stealth by default** — randomized viewports, real human mouse/keyboard patterns, spoofed fingerprints
- **Headed mode that matches what you see** — launch-time Camoufox fingerprint window is aligned with the Playwright viewport so Retina/macOS pages do not render off-screen or look zoomed/clipped
- **Two-tier Cloudflare bypass** — cloudscraper (fast HTTP) → FlareSolverr (guaranteed, with browser recovery)
- **Full browser session recovery** — `flaresolverr_solve` sets up Playwright route interception so the entire browser session works through FlareSolverr: navigate, snapshot, click, type — all transparent
- **Ref-based interaction** — snapshot-first: `[@eN]` refs from accessibility tree with real CSS selectors; click by ref, type by ref. **Also accepts raw CSS selectors** for elements not in the snapshot (React portals, popovers, etc.).
- **Batch form filling** — `camoufox_fill_form` fills multiple fields at once (textbox, checkbox, radio, combobox, slider).
- **Drag & drop** — `camoufox_drag` moves elements between targets.
- **Async JavaScript** — `camoufox_evaluate` supports both sync and async expressions with configurable timeout.
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

## Tools (39 total)

### Browser Lifecycle

| Tool | Description |
|------|-------------|
| `camoufox_launch` | Start stealth browser (Firefox-based Playwright) |
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
| `camoufox_snapshot` | Get interactive elements as `[@eN]` refs with real CSS selectors. Detects React portals / popovers. |
| `camoufox_click` | Click by ref or raw CSS selector (supports double-click) |
| `camoufox_type` | Type text into input by ref or raw CSS selector |
| `camoufox_fill_form` | Batch fill multiple fields at once (textbox, checkbox, radio, combobox, slider) |
| `camoufox_drag` | Drag one element onto another by ref or CSS selector |
| `camoufox_press` | Press keyboard key (Enter, Tab, Escape, ArrowDown, etc.) |
| `camoufox_select` | Select dropdown option by value/label/index. Accepts ref or CSS selector. |
| `camoufox_hover` | Hover over element by ref or CSS selector |
| `camoufox_scroll` | Scroll up/down by pixel amount |
| `camoufox_evaluate` | Execute JavaScript in page context (sync or async, configurable timeout) |
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
│   ├── __init__.py              # v0.7.0
│   ├── __main__.py              # Entry point
│   ├── server.py                # FastMCP server + 39 tool definitions
│   ├── session.py               # BrowserSession: lifecycle, dialogs, console, cookies, tabs
│   ├── snapshot.py              # Accessibility-tree snapshot + CSS selector ref resolution
│   ├── markdown.py              # trafilatura + regex fallback markdown extraction
│   ├── vision.py                # Screenshots with optional element annotation overlays
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
