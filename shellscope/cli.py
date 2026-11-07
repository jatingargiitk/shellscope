"""Command line interface for shellscope."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .parser import parse_command
from .rules import RuleSet, load_rules


def _default_rules_path() -> Optional[str]:
    # Prefer the copy shipped inside the package (pip install), then repo examples/.
    packaged = Path(__file__).resolve().parent / "default.rules"
    if packaged.is_file():
        return str(packaged)
    here = Path(__file__).resolve().parent.parent / "examples" / "deny.rules"
    if here.is_file():
        return str(here)
    return None


def _format_report(report, violations, as_json: bool) -> str:
    if as_json:
        return json.dumps(
            {
                "command": report.command,
                "effects": [e.to_dict() for e in report.effects],
                "warnings": report.warnings,
                "violations": [v.to_dict() for v in violations],
                "allowed": not violations,
            },
            indent=2,
            ensure_ascii=False,
        )
    lines: List[str] = []
    for e in report.effects:
        extra = f"  ({e.detail})" if e.detail else ""
        lines.append(f"  {e.kind:<8} {e.target}{extra}")
    if report.warnings:
        for w in report.warnings:
            lines.append(f"  warning: {w}")
    if violations:
        lines.append(f"DENY ({len(violations)} rule match(es)):")
        for v in violations:
            lines.append(f"  !! {v.reason}")
    else:
        lines.append("ALLOW")
    return "\n".join(lines)


def _hook_decision(allowed: bool, reason: str) -> dict:
    """JSON suitable for a Claude Code PreToolUse / Bash hook."""
    decision = "allow" if allowed else "deny"
    return {
        "decision": decision,
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }


def _extract_command_from_hook_payload(text: str) -> Optional[str]:
    """Accept raw command lines or Claude Code stdin JSON."""
    text = text.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return text
        # Common shapes
        for key in ("command",):
            if isinstance(data.get(key), str):
                return data[key]
        tool_input = data.get("tool_input") or data.get("toolInput") or {}
        if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
            return tool_input["command"]
        # nested tool_name / input
        inp = data.get("input")
        if isinstance(inp, dict) and isinstance(inp.get("command"), str):
            return inp["command"]
        return None
    return text


def cmd_check(args: argparse.Namespace) -> int:
    rules_path = args.rules
    if rules_path is None:
        rules_path = _default_rules_path()
    rules = load_rules(rules_path) if rules_path else RuleSet([])

    command = args.command
    if command is None and args.stdin:
        command = sys.stdin.read()
    if not command:
        print("shellscope: no command given", file=sys.stderr)
        return 2

    report = parse_command(command, cwd=args.cwd)
    violations = rules.check(report)
    print(_format_report(report, violations, args.json))
    return 1 if violations else 0


def cmd_hook(args: argparse.Namespace) -> int:
    rules_path = args.rules
    if rules_path is None:
        rules_path = _default_rules_path()
    rules = load_rules(rules_path) if rules_path else RuleSet([])

    exit_code = 0
    # Read all of stdin; support one JSON blob or line-oriented commands
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps(_hook_decision(True, "empty input")))
        return 0

    # Prefer single JSON document when stdin looks like one object
    stripped = raw.strip()
    payloads: List[str]
    if stripped.startswith("{") and stripped.endswith("}"):
        payloads = [stripped]
    else:
        payloads = [ln for ln in raw.splitlines() if ln.strip()]

    # For multi-line non-JSON, emit one decision per line (last printed wins for
    # single-hook consumers; Claude Code sends one JSON per invocation).
    results = []
    for item in payloads:
        command = _extract_command_from_hook_payload(item)
        if not command:
            results.append(_hook_decision(True, "no command in payload"))
            continue
        report = parse_command(command, cwd=args.cwd)
        violations = rules.check(report)
        if violations:
            reason = "; ".join(v.reason for v in violations)
            results.append(_hook_decision(False, reason))
            exit_code = 1
        else:
            kinds = sorted({e.kind for e in report.effects if e.kind != "binary"})
            summary = ", ".join(kinds) if kinds else "no file/network effects"
            results.append(_hook_decision(True, f"ok ({summary})"))

    if len(results) == 1:
        print(json.dumps(results[0], ensure_ascii=False))
    else:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="shellscope",
        description=(
            "Parse a shell command into read/write/delete/network effects "
            "and apply deny rules (coding-agent Bash hook)."
        ),
    )
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="parse a command and exit 1 on deny")
    p_check.add_argument("command", nargs="?", help="shell command string")
    p_check.add_argument(
        "-f", "--rules", "--file",
        dest="rules",
        default=None,
        help="deny rules file (default: packaged examples/deny.rules if present)",
    )
    p_check.add_argument("--cwd", default=None, help="resolve relative paths against this directory")
    p_check.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p_check.add_argument("--stdin", action="store_true", help="read command from stdin")
    p_check.set_defaults(func=cmd_check)

    p_hook = sub.add_parser(
        "hook",
        help="read command(s) or Claude Code PreToolUse JSON from stdin; print allow/deny JSON",
    )
    p_hook.add_argument(
        "-f", "--rules", "--file",
        dest="rules",
        default=None,
        help="deny rules file",
    )
    p_hook.add_argument("--cwd", default=None, help="resolve relative paths against this directory")
    p_hook.set_defaults(func=cmd_hook)

    # Also allow `shellscope "<cmd>"` as sugar for check? Keep explicit subcommands.
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
