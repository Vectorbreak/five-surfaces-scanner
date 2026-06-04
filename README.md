# Five Surfaces Scanner

**Open-source security scanner for MCP (Model Context Protocol) servers and AI-agent configs.** Finds the issues that actually get agents owned — prompt-injection sinks, tool impersonation, credential leakage, and unsafe configuration — organized by the **Five Surfaces** threat model.

> Built by [Vectorbreak Security](https://vectorbreak.com). This is the free, open tier. The full commercial scanner (deeper checks + auto-remediation) lives at **[vectorbreak.com](https://vectorbreak.com)**.

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
[![Live demo](https://img.shields.io/badge/live%20demo-online-22d3ee)](https://vectorbreak.github.io/five-surfaces-scanner/web/)

## ▶ Live demo

Interactive dashboard — paste an MCP config (or click **Load sample**), toggle the checks, and scan in your browser. Nothing leaves the page.

**[Open the live dashboard →](https://vectorbreak.github.io/five-surfaces-scanner/web/)**

---

## Why this exists

The moment you connect a language model to real tools and data — increasingly through MCP — you inherit an attack surface traditional app-security tooling wasn't built for. A single poisoned input can make an agent **leak credentials, impersonate a tool, or take actions nobody approved.**

Most "AI security" advice still treats LLMs like web apps. They aren't. This scanner checks the five places MCP/agent systems actually break.

## The Five Surfaces

| # | Surface | What it covers | Example checks |
|---|---------|----------------|----------------|
| 1 | **Model** | What the model can be talked into | prompt-injection text in tool descriptions/metadata |
| 2 | **Context** | What reaches the prompt (and who controls it) | tools that pull untrusted external content |
| 3 | **Tools** | What the agent can actually do | dangerous capabilities, tool name collisions/impersonation |
| 4 | **Identity** | Whose authority the agent acts with | secrets in config, plaintext transport, missing auth, broad bind |
| 5 | **Output** | What leaves the system, and to whom | outbound/exfiltration-capable tools |

Full methodology: **[The Five Surfaces of MCP Security](https://vectorbreak.com/five-surfaces)**

## Quick start

No dependencies — just Python 3.10+.

```bash
git clone https://github.com/Vectorbreak/five-surfaces-scanner.git
cd five-surfaces-scanner

# scan an MCP config
python five_surfaces_scanner.py examples/sample-mcp-config.json

# emit SARIF for CI / GitHub code scanning
python five_surfaces_scanner.py examples/sample-mcp-config.json --sarif results.sarif
```

Exit code is non-zero when HIGH-severity findings exist, so it drops straight into CI.

## Example output

```
Five Surfaces Scanner — examples/sample-mcp-config.json
============================================================
  ✗ IDENTITY HIGH   Server 'ops-helper' stores a credential in config env var 'OPENAI_API_KEY'.
  ✗ MODEL    HIGH   Tool 'lookup' description contains prompt-injection text.
  ✗ TOOLS    HIGH   Tool 'run_command' exposes a high-impact capability.
  ✗ TOOLS    HIGH   Tool name 'fetch_url' is defined by two servers (impersonation risk).
  ✗ CONTEXT  MEDIUM Tool 'fetch_url' fetches external content that enters the prompt.
  ✗ OUTPUT   MEDIUM Tool 'send_email' can send data outbound.
------------------------------------------------------------
  12 finding(s), 6 high.  Full scanner + fixes: https://vectorbreak.com
```

## What it checks (free tier)

- Prompt-injection text in tool descriptions and metadata (Model)
- Tools that pull untrusted external content into context (Context)
- Dangerous tool capabilities and tool-name collisions / impersonation (Tools)
- Secrets in config, plaintext transport, missing auth, public bind (Identity)
- Outbound / exfiltration-capable tools (Output)
- SARIF output for CI / GitHub code scanning

These are heuristics meant to catch the common, high-frequency mistakes fast. The commercial scanner adds dynamic testing and auto-remediation.

## Roadmap

- [ ] More MCP client config formats
- [ ] Additional per-surface check packs
- [ ] Auto-remediation suggestions (full version)

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Defensive checks only.

## License

MIT — see [LICENSE](LICENSE).

---

### About Vectorbreak Security
We help teams ship AI and MCP products without shipping the vulnerabilities that come with them — red-team assessments, MCP supply-chain audits, and incident response for LLM/agent systems. Creators of the Five Surfaces framework. → **[vectorbreak.com](https://vectorbreak.com)** · Lance@Vectorbreak.com
