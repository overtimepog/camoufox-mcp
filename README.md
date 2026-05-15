# Camoufox MCP

> Stealth browser automation MCP server powered by [Camoufox](https://github.com/askjoe/camoufox) — a humanized Playwright fork that beats Cloudflare, reCAPTCHA, and fingerprint checks.

## Features

- **Stealth by default** — randomized viewports, real human mouse/keyboard patterns, spoofed fingerprints
- **Human-verification delegation** — when Cloudflare blocks automation, the `human_verify` tool pauses execution and tells the user exactly what to click
- **Ref-based interaction** — snapshot-first: `[@eN]` refs from accessibility tree, no CSS selectors
- **Cloudflare bypass** — Camoufox's stealth Playwright already passes most CF challenges automatically
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

### With npx

```bash
npx camoufox-mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `camoufox_launch` | Start stealth browser (auto-creates first page) |
| `camoufox_navigate` | Navigate to URL with smart wait |
| `camoufox_snapshot` | Get interactive elements as `[@eN]` refs (primary page understanding) |
| `camoufox_click` | Click by ref |
| `camoufox_type` | Type into input by ref |
| `camoufox_select` | Select dropdown option |
| `camoufox_hover` | Hover by ref |
| `camoufox_scroll` | Scroll up/down |
| `camoufox_read_page` | Extract page as clean markdown |
| `camoufox_screenshot` | Annotated screenshot with element indices |
| `camoufox_evaluate` | Run JavaScript in page context |
| `camoufox_wait` | Wait for page to settle (no DOM mutations + network idle) |
| `camoufox_get_dialogs` | Get captured JS dialogs (alert/confirm/prompt) |
| `camoufox_snapshot_if_blocked` | **KEY TOOL** — captures Cloudflare challenge page, returns human-verification instructions |
| `camoufox_human_verify` | Resume after user completes verification in their browser |
| `camoufox_close` | Close browser |

## Human Verification Workflow

When Cloudflare blocks automation (it happens!), use the verification flow:

```
1. camoufox_navigate → gets blocked by Cloudflare challenge
2. camoufox_snapshot_if_blocked → detects challenge, pauses, returns instruction image
3. User opens verification_url in their own browser, solves it, confirms done
4. camoufox_human_verify → automation resumes with cookies from user's browser
```

### Example

```python
# Navigate to a hard target
result = camoufox_navigate("page_abc123", "https://hard-target.com/")

if result.get("cloudflare_blocked"):
    # Get the verification URL and instructions
    block_info = camoufox_snapshot_if_blocked("page_abc123")
    print(block_info["instruction"])  # "Open this URL in your browser and click Verify"
    print(block_info["verification_url"])
    
    # User completes verification in their browser...
    
    # Resume automation
    camoufox_human_verify("page_abc123")
    
    # Now continue
    page_content = camoufox_read_page("page_abc123")
```

## Architecture

```
camoufox-mcp/
├── camoufoxmcp/
│   ├── __init__.py
│   ├── __main__.py       # Entry point: mcp run camoufoxmcp
│   ├── server.py         # FastMCP server + all tool definitions
│   ├── session.py        # BrowserSession lifecycle management
│   ├── snapshot.py      # Accessibility-tree snapshot + ref resolution
│   ├── markdown.py      # Clean markdown extraction
│   └── vision.py        # Annotated screenshot
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
| Cloudflare | Passes Turnstile/reCAPTCHA | Passes most challenges (auto) |
| Human verification | Manual cookie import | Built-in delegation tool |
| Maintenance | You maintain the fork | Active upstream (askjoe) |
| Platforms | Linux/Windows/macOS | Linux/Windows/macOS |

Both are excellent. Camoufox is newer and more actively maintained; CloakBrowser gives you full control over the Chromium source patch. This MCP targets Camoufox for the plug-and-play experience and native Firefox support.

## License

Apache-2.0