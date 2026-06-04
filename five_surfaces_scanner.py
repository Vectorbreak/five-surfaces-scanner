#!/usr/bin/env python3
"""
Five Surfaces Scanner (open / free tier)
=========================================
A lightweight, dependency-free security scanner for MCP (Model Context Protocol)
server configurations and AI-agent tool manifests. Heuristic checks organized by
the Five Surfaces threat model: Model, Context, Tools, Identity, Output.

This is the open foundation. Deeper checks + auto-remediation: https://vectorbreak.com

Usage:
    python five_surfaces_scanner.py path/to/mcp-config.json
    python five_surfaces_scanner.py path/to/mcp-config.json --sarif results.sarif

Exit code is non-zero if any HIGH severity findings are present (useful for CI).

(c) Vectorbreak Security — MIT License.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

SURFACES = ("MODEL", "CONTEXT", "TOOLS", "IDENTITY", "OUTPUT")

# --- heuristic signal sets -------------------------------------------------
INJECTION_PHRASES = [
    "ignore previous instructions", "ignore the above", "disregard",
    "system prompt", "you are now", "act as", "developer mode",
    "override", "reveal your", "print your instructions",
]
DANGEROUS_TOOL_HINTS = [
    "exec", "shell", "command", "run_command", "run_code", "eval",
    "subprocess", "os_system", "delete", "rm_", "drop_table", "write_file",
    "sudo", "terminal", "powershell", "bash",
]
CONTEXT_FETCH_HINTS = ["fetch", "http", "url", "browse", "scrape", "read_web", "request", "crawl"]
OUTPUT_EXFIL_HINTS = ["send", "email", "post", "upload", "webhook", "publish", "export", "notify"]
SECRET_KEY_HINTS = ["key", "secret", "token", "password", "passwd", "credential", "apikey", "api_key", "auth"]
SECRET_VALUE_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "OpenAI-style API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"[A-Za-z0-9_\-]{32,}"), "High-entropy secret-like string"),
]


@dataclass
class Finding:
    surface: str
    severity: str  # HIGH | MEDIUM | LOW
    rule: str
    message: str
    location: str = ""

    def __post_init__(self) -> None:
        assert self.surface in SURFACES, self.surface
        assert self.severity in ("HIGH", "MEDIUM", "LOW"), self.severity


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, *a: Any, **k: Any) -> None:
        self.findings.append(Finding(*a, **k))

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")


def _iter_servers(cfg: dict) -> list[tuple[str, dict]]:
    """Support common shapes: {'mcpServers': {...}} or {'servers': {...}} or flat."""
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(cfg.get(key), dict):
            return list(cfg[key].items())
    # flat fallback: treat top-level dict-of-dicts as servers
    return [(k, v) for k, v in cfg.items() if isinstance(v, dict)]


def _tools_of(server: dict) -> list[dict]:
    tools = server.get("tools")
    if isinstance(tools, list):
        return [t for t in tools if isinstance(t, dict)]
    if isinstance(tools, dict):
        return [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in tools.items()]
    return []


def scan_config(cfg: dict, target: str) -> Report:
    rep = Report(target=target)
    seen_tool_names: dict[str, str] = {}

    for sname, server in _iter_servers(cfg):
        loc = f"server:{sname}"

        # --- IDENTITY: secrets in env / config ---
        env = server.get("env", {})
        if isinstance(env, dict):
            for k, v in env.items():
                kl = str(k).lower()
                if any(h in kl for h in SECRET_KEY_HINTS):
                    rep.add("IDENTITY", "HIGH", "secret-in-config",
                            f"Server '{sname}' stores a credential in config env var '{k}'. "
                            f"Use a secrets manager / short-lived scoped tokens.", f"{loc}.env.{k}")
                if isinstance(v, str):
                    for pat, label in SECRET_VALUE_PATTERNS:
                        if pat.search(v):
                            rep.add("IDENTITY", "HIGH", "leaked-secret",
                                    f"Possible {label} hard-coded in '{sname}' env '{k}'.",
                                    f"{loc}.env.{k}")
                            break

        # --- IDENTITY: transport / exposure ---
        url = str(server.get("url", "") or server.get("endpoint", ""))
        if url.startswith("http://"):
            rep.add("IDENTITY", "MEDIUM", "plaintext-transport",
                    f"Server '{sname}' uses plaintext http:// transport.", f"{loc}.url")
        if "0.0.0.0" in url or "0.0.0.0" in json.dumps(server):
            rep.add("IDENTITY", "MEDIUM", "broad-bind",
                    f"Server '{sname}' appears bound to 0.0.0.0 (publicly exposed).", loc)
        if url and not any(t in server for t in ("auth", "headers", "token", "apiKey", "api_key")):
            rep.add("IDENTITY", "MEDIUM", "missing-auth",
                    f"Remote server '{sname}' has no visible auth configured.", loc)

        # --- per-tool checks ---
        for tool in _tools_of(server):
            tname = str(tool.get("name", "")).strip()
            desc = str(tool.get("description", ""))
            tl = tname.lower()
            tloc = f"{loc}.tool:{tname or '?'}"

            # TOOLS: dangerous capability
            if any(h in tl for h in DANGEROUS_TOOL_HINTS):
                rep.add("TOOLS", "HIGH", "dangerous-capability",
                        f"Tool '{tname}' exposes a high-impact capability. Require approval "
                        f"and least-privilege scoping.", tloc)

            # TOOLS: impersonation / name collision
            if tname:
                if tname in seen_tool_names and seen_tool_names[tname] != sname:
                    rep.add("TOOLS", "HIGH", "tool-name-collision",
                            f"Tool name '{tname}' is defined by both '{seen_tool_names[tname]}' "
                            f"and '{sname}' (impersonation risk).", tloc)
                seen_tool_names[tname] = sname

            # MODEL / CONTEXT: injection phrases in description
            dl = desc.lower()
            for phrase in INJECTION_PHRASES:
                if phrase in dl:
                    rep.add("MODEL", "HIGH", "injection-in-tool-desc",
                            f"Tool '{tname}' description contains prompt-injection text "
                            f"('{phrase}'). Tool metadata is trusted by the model.", tloc)
                    break

            # CONTEXT: pulls untrusted external content
            if any(h in tl for h in CONTEXT_FETCH_HINTS):
                rep.add("CONTEXT", "MEDIUM", "untrusted-context-source",
                        f"Tool '{tname}' fetches external content that enters the prompt. "
                        f"Sanitize and label provenance before reasoning on it.", tloc)

            # OUTPUT: exfiltration path
            if any(h in tl for h in OUTPUT_EXFIL_HINTS):
                rep.add("OUTPUT", "MEDIUM", "exfiltration-path",
                        f"Tool '{tname}' can send data outbound. Restrict destinations and "
                        f"scan payloads for secrets.", tloc)

    if not rep.findings:
        rep.add("MODEL", "LOW", "clean", "No heuristic issues found. Run the full scanner for deep checks.", target)
    return rep


# --- output ----------------------------------------------------------------
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def print_report(rep: Report) -> None:
    print(f"\nFive Surfaces Scanner — {rep.target}")
    print("=" * 60)
    for f in sorted(rep.findings, key=lambda x: (_SEV_ORDER[x.severity], x.surface)):
        mark = "✗" if f.severity in ("HIGH", "MEDIUM") else "✓"
        print(f"  {mark} {f.surface:<8} {f.severity:<6} {f.message}")
        if f.location:
            print(f"        ↳ {f.location}  [{f.rule}]")
    highs = rep.high
    total = len([f for f in rep.findings if f.rule != "clean"])
    print("-" * 60)
    print(f"  {total} finding(s), {highs} high.  Full scanner + fixes: https://vectorbreak.com")


def to_sarif(rep: Report) -> dict:
    level = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    results = [{
        "ruleId": f"five-surfaces/{f.surface.lower()}/{f.rule}",
        "level": level[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": rep.target},
                                            "region": {"snippet": {"text": f.location}}}}],
    } for f in rep.findings if f.rule != "clean"]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Five Surfaces Scanner",
                                "informationUri": "https://vectorbreak.com",
                                "version": "0.1.0"}},
            "results": results,
        }],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Five Surfaces Scanner for MCP/agent configs.")
    ap.add_argument("path", help="Path to an MCP config JSON file")
    ap.add_argument("--sarif", metavar="FILE", help="Write SARIF results to FILE")
    args = ap.parse_args(argv)

    p = Path(args.path)
    if not p.exists():
        print(f"error: {p} not found", file=sys.stderr)
        return 2
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"error: could not parse JSON: {e}", file=sys.stderr)
        return 2

    rep = scan_config(cfg if isinstance(cfg, dict) else {}, str(p))
    print_report(rep)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(rep), indent=2), encoding="utf-8")
        print(f"  SARIF written to {args.sarif}")
    return 1 if rep.high else 0


if __name__ == "__main__":
    raise SystemExit(main())
