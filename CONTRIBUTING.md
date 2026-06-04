# Contributing to Five Surfaces Scanner

Thanks for helping make MCP/agent deployments safer.

## Ways to contribute
- **New checks** — add heuristics for any of the five surfaces (Model, Context, Tools, Identity, Output).
- **New config formats** — support additional MCP client manifest shapes.
- **False-positive fixes** — tighten existing rules.
- **Examples** — add sample configs (sanitized — never real secrets) under `examples/`.

## Adding a check
Each finding maps to one surface and a severity (`HIGH` / `MEDIUM` / `LOW`). Add your
logic in `scan_config()` and emit with `rep.add(SURFACE, SEVERITY, rule_id, message, location)`.
Keep rules explainable — every finding should tell a user *why* it matters and *how* to fix it.

## Ground rules
- Defensive only. This project detects risky configurations; it does not generate attacks or exploits.
- No real credentials in test fixtures.
- Run `python five_surfaces_scanner.py examples/sample-mcp-config.json` before opening a PR.

## Reporting security issues
Email **Lance@Vectorbreak.com** rather than opening a public issue for sensitive reports.
