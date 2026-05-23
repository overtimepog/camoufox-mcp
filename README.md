# Camoufox MCP

> Stealth browser automation MCP server powered by [Camoufox](https://github.com/askjoe/camoufox) — a humanized Playwright Firefox fork with **three-tier Cloudflare bypass**.

## Features

- **Stealth by default** — randomized viewports, real human mouse/keyboard patterns, spoofed fingerprints
- **Three-tier Cloudflare bypass** — escalate from fast HTTP solver to guaranteed Docker-based bypass
- **Ref-based interaction** — snapshot-first: `[@eN]` refs from accessibility tree, no CSS selectors
- **Auto-managed FlareSolverr** — Tier 3 automatically starts/stops Docker container on demand
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

### Tier 3: FlareSolverr (optional, for hardest Cloudflare)

Tier 3 uses FlareSolverr (Docker-based headless Chromium) to bypass Turnstile, JS VM v3, and CAPTCHA challenges. The MCP server manages it automatically — it starts on first use, stops when you're done. Just have Docker installed.

```bash
# Only need Docker installed. The MCP server handles everything else.
# First Tier 3 call auto-pulls the image and starts the container.
```

## Tools (21 total)

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

### Cloudflare Bypass — Three Tiers

| Tier | Tool | Speed | What it solves |
|------|------|-------|----------------|
| 1 | `camoufox_cloudscraper_fetch` | ~100—500ms | IUAM, JS v1, JS v2 |
| 2 | `camoufox_cloudscraper_solve` | ~1—2s | Browser cookie injection |
| 3 | `camoufox_flaresolverr_fetch` | ~1—15s | Turnstile, JS VM v3, CAPTCHA (everything) |

| Tool | Description |
|------|-------------|
| `camoufox_flaresolverr_start` | Start FlareSolverr Docker container |
| `camoufox_flaresolverr_stop` | Stop FlareSolverr container |
| `camoufox_flaresolverr_health` | Check if FlareSolverr is running |

## Cloudflare Bypass Workflow

When `camoufox_navigate` returns `cloudflare_blocked: true`, escalate through the tiers:

```
Tier 1: cloudscraper_fetch(url)
  → Fast HTTP-level JS solver. Covers most CF protections.
  → If blocked: Tier 2

Tier 2: cloudscraper_solve(page_id)
  → Solves CF at HTTP level, injects clearance cookies into browser.
  → Re-navigate after success.
  → If blocked: Tier 3

Tier 3: flaresolverr_fetch(url)
  → Docker-based headless Chromium + puppeteer-extra stealth.
  → Auto-starts FlareSolverr if not running.
  → Bypasses Turnstile, JS VM v3, managed challenges, CAPTCHAs.
  → Guaranteed bypass for all known CF protections.
```

### Example

```python
# Navigate to a hard target
result = camoufox_navigate("page_abc", "https://vx-underground.org/")

if result.get("cloudflare_blocked"):
    # Tier 1: fast HTTP solver
    content = camoufox_cloudscraper_fetch("https://vx-underground.org/")

    if content.get("status") == "cf_blocked":
        # Tier 3: guaranteed bypass (auto-starts Docker if needed)
        content = camoufox_flaresolverr_fetch("https://vx-underground.org/")
        # → Returns real page content + cf_clearance cookie
```

## Architecture

```
camoufox-mcp/
├── camoufoxmcp/
│   ├── __init__.py              # v0.3.1
│   ├── __main__.py              # Entry point
│   ├── server.py                # FastMCP server + 21 tool definitions
│   ├── session.py               # BrowserSession lifecycle (Camoufox Firefox)
│   ├── snapshot.py              # Accessibility-tree snapshot + ref resolution
│   ├── markdown.py              # Clean markdown extraction
│   ├── vision.py                # Annotated screenshots
│   ├── cloudscraper_bridge.py   # Tier 1—2: HTTP JS solver + cookie injection
│   └── flaresolverr_bridge.py   # Tier 3: Docker Chromium, Docker lifecycle mgmt
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
| Cloudflare | Passes Turnstile/reCAPTCHA | Three-tier bypass: cloudscraper → FlareSolverr |
| CF auto-management | Manual cookie import | Auto-start/stop Docker FlareSolverr |
| Maintenance | You maintain the fork | Active upstreams (askjoe, cloudscraper, FlareSolverr) |
| Platforms | Linux/Windows/macOS | Linux/Windows/macOS |

## License

Apache-2.0
