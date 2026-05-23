# Camoufox MCP

> Stealth browser automation MCP server powered by [Camoufox](https://github.com/askjoe/camoufox) — a humanized Playwright Firefox fork with **two-tier Cloudflare bypass** including full browser session recovery through route interception.

## Features

- **Stealth by default** — randomized viewports, real human mouse/keyboard patterns, spoofed fingerprints
- **Two-tier Cloudflare bypass** — cloudscraper (fast HTTP) → FlareSolverr (guaranteed, with browser recovery)
- **Full browser session recovery** — `flaresolverr_solve` sets up Playwright route interception so the entire browser session works through FlareSolverr: navigate, snapshot, click, type — all transparent
- **Ref-based interaction** — snapshot-first: `[@eN]` refs from accessibility tree, no CSS selectors
- **Auto-managed FlareSolverr** — Tier 2 automatically starts/stops Docker container on demand
- **Persistent sessions** — cookies survive restarts via `user_data_dir`
- **Proxy support** — residential proxies for harder targets

## Quick Start

```bash
pip install camoufox-mcp
camoufox-mcp
```

Or add to your MCP client config (`claude_desktop_config.json`, `claude_code_settings.json`, etc.):

```json
"camoufox-mcp": {
  "command": "pip",
  "args": ["install", "--quiet", "camoufox-mcp", "&&", "camoufox-mcp"]
}
```

### Tier 2: FlareSolverr (for hardest Cloudflare)

Tier 2 uses FlareSolverr (Docker-based headless Chromium) to bypass Turnstile, JS VM v3, and CAPTCHA challenges. The MCP server manages it automatically — it starts on first use, stops when you're done. Just have Docker installed.

```bash
# Only need Docker installed. The MCP server handles everything else.
# First Tier 2 call auto-pulls the image and starts the container.
```

## Tools (22 total)

### Browser Lifecycle
| Tool | Description |
|------|-------------|
| `camoufox_launch` | Start stealth browser (Firefox-based Playwright) |
| `camoufox_navigate` | Navigate to URL — flags `cloudflare_blocked` if CF detected |
| `camoufox_close` | Close browser |

### Page Interaction
| Tool | Description |
|------|-------------|
| `camoufox_snapshot` | Get interactive elements as `[@eN]` refs |
| `camoufox_click` | Click by ref |
| `camoufox_type` | Type into input by ref |
| `camoufox_select` | Select dropdown option |
| `camoufox_hover` | Hover by ref |
| `camoufox_scroll` | Scroll up/down |
| `camoufox_evaluate` | Run JavaScript in page context |
| `camoufox_wait` | Wait for page to settle |

### Content Extraction
| Tool | Description |
|------|-------------|
| `camoufox_read_page` | Extract page as clean markdown |
| `camoufox_screenshot` | Take annotated screenshot |
| `camoufox_get_dialogs` | Get captured JS dialogs |
| `camoufox_list_pages` | List all open pages |

### Cloudflare Bypass — Two Tiers

| Tier | Tool | Speed | What it does |
|------|------|-------|---------------|
| 1 | `camoufox_cloudscraper_fetch` | ~100—500ms | HTTP-level JS solver: IUAM, JS v1, JS v2 |
|   | `camoufox_cloudscraper_solve` | ~1—2s | Cookie injection into browser |
| 2 | `camoufox_flaresolverr_fetch` | ~1—15s | Turnstile, JS VM v3, CAPTCHA — returns content + links |
|   | `camoufox_flaresolverr_solve` | ~1—15s | **Full browser recovery via route interception** — browser works normally after |

| Tool | Description |
|------|-------------|
| `camoufox_flaresolverr_start` | Start FlareSolverr Docker container |
| `camoufox_flaresolverr_stop` | Stop FlareSolverr container |
| `camoufox_flaresolverr_health` | Check if FlareSolverr is running |

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
  flare_solve sets up Playwright route interception — ALL document requests
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
    camoufox_snapshot("page_abc")     # 21 interactive elements
    camoufox_read_page("page_abc")    # Full content
    camoufox_click("page_abc", "@e8") # Click file entries
    camoufox_scroll("page_abc")       # Scroll normally
```

## Architecture

```
camoufox-mcp/
├── camoufoxmcp/
│   ├── __init__.py              # v0.4.0
│   ├── __main__.py              # Entry point
│   ├── server.py                # FastMCP server + 22 tool definitions
│   ├── session.py               # BrowserSession lifecycle (Camoufox Firefox)
│   ├── snapshot.py              # Accessibility-tree snapshot + ref resolution
│   ├── markdown.py              # Clean markdown extraction
│   ├── vision.py                # Annotated screenshots
│   ├── cloudscraper_bridge.py   # Tier 1: HTTP JS solver + cookie injection
│   └── flaresolverr_bridge.py   # Tier 2: solve, fetch (raw + text), links, Docker mgmt
├── pyproject.toml
└── tests/
```

## Development

```bash
git clone https://github.com/overtimepog/camoufox-mcp.git
cd camoufox-mcp
pip install -e ".[dev]"
pytest tests/
```

## Why Camoufox over CloakBrowser?

| | CloakBrowser | Camoufox |
|---|---|---|
| Engine | Source-patched Chromium | Humanized Playwright (Firefox/Chromium) |
| Cloudflare | Passes Turnstile/reCAPTCHA | Two-tier bypass: cloudscraper → FlareSolverr |
| CF auto-management | Manual cookie import | Auto-start/stop Docker FlareSolverr |
| Browser recovery | N/A | Route interception: `flaresolverr_solve` recovers the entire browsing session |
| Maintenance | You maintain the fork | Active upstreams (askjoe, cloudscraper, FlareSolverr) |
| Platforms | Linux/Windows/macOS | Linux/Windows/macOS |

## License

Apache-2.0
