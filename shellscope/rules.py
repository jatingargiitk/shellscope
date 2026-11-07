"""Deny-rule loading and matching for shellscope.

Line-based format (one rule per line)::

    # comment
    deny read  **/.env*
    deny write ~/.ssh/**
    deny delete /
    deny network *
    deny network evil.example.com
    deny binary nc
    deny command rm -rf /

Kinds: read, write, delete, network, binary, command.
Patterns use shell-style globs; ``**`` matches across ``/``.
``~`` expands to the home directory. Network patterns match the
host (and, if the pattern contains ``/`` or ``://``, the raw URL).
``command`` matches a substring (case-sensitive) of the original
command string, or a glob against it.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .parser import Effect, EffectReport


@dataclass
class Rule:
    kind: str       # read|write|delete|network|binary|command
    pattern: str    # glob or substring
    raw: str = ""   # original line

    def to_dict(self):
        return asdict(self)


@dataclass
class Violation:
    rule: Rule
    effect: Optional[Effect]
    reason: str

    def to_dict(self):
        return {
            "rule": self.rule.to_dict(),
            "effect": self.effect.to_dict() if self.effect else None,
            "reason": self.reason,
        }


def _expand_rule_path(pattern: str) -> str:
    return os.path.expanduser(pattern)


def _compile_glob(pattern: str) -> re.Pattern:
    """Translate a glob with ``**`` support into a regex."""
    pat = _expand_rule_path(pattern)
    # Normalize // 
    parts: List[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            parts.append("(.*/)?")
            i += 3
        elif pat.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pat[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            # run of non-special
            j = i
            while j < len(pat) and pat[j] not in "*?":
                # stop before ** handled above — single chars fine
                if pat.startswith("**", j):
                    break
                j += 1
            parts.append(re.escape(pat[i:j]))
            i = j
    return re.compile("^" + "".join(parts) + "$")


def _path_matches(pattern: str, path: str) -> bool:
    rx = _compile_glob(pattern)
    candidates = {path, os.path.normpath(path)}
    # Also try match against absolute and as-given
    home = os.path.expanduser("~")
    if path.startswith(home + os.sep) or path == home:
        candidates.add("~" + path[len(home):])
    for c in candidates:
        if rx.match(c):
            return True
        # basename-only patterns like ".env"
        if "/" not in pattern.rstrip("/") and not pattern.startswith("*"):
            if fnmatch.fnmatch(os.path.basename(c), pattern):
                return True
        # trailing-path segment match for patterns like "**/.env*"
        if rx.match(os.path.basename(c)):
            return True
    # Special-case: pattern "/" should match filesystem root exactly
    if pattern == "/" and os.path.normpath(path) == "/":
        return True
    # Pattern "/**" or "/**/" style — root wipe
    if pattern in ("/**", "/**/*", "**") and os.path.normpath(path) == "/":
        return True
    return False


def _network_matches(pattern: str, host_or_url: str) -> bool:
    pat = pattern.strip()
    if pat == "*":
        return True
    target = host_or_url
    if "://" in target:
        # raw URL vs host-only pattern
        if "://" in pat or "/" in pat.strip("*"):
            return fnmatch.fnmatch(target, pat) or bool(re.search(fnmatch.translate(pat), target))
        # compare hostname
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        return fnmatch.fnmatch(host, pat) or host == pat or host.endswith("." + pat.lstrip("*."))
    return (
        fnmatch.fnmatch(target, pat)
        or target == pat
        or target.endswith("." + pat.lstrip("*."))
        or bool(_compile_glob(pat).match(target))
    )


_RULE_LINE = re.compile(
    r"^(?:deny\s+)?(?P<kind>read|write|delete|network|binary|command)\s+(?P<pattern>.+?)\s*$",
    re.IGNORECASE,
)


def parse_rules_text(text: str) -> List[Rule]:
    rules: List[Rule] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        raw = line
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Allow "deny:" YAML-ish list items like "- read: .env" lightly
        line = re.sub(r"^-\s+", "", line)
        line = re.sub(r"^deny\s*:\s*", "deny ", line, flags=re.I)
        # "read: .env" form
        m_yaml = re.match(
            r"^(read|write|delete|network|binary|command)\s*:\s*(.+)$",
            line,
            re.I,
        )
        if m_yaml:
            rules.append(Rule(m_yaml.group(1).lower(), m_yaml.group(2).strip(), raw))
            continue
        m = _RULE_LINE.match(line)
        if not m:
            raise ValueError(f"line {lineno}: cannot parse rule: {raw!r}")
        rules.append(Rule(m.group("kind").lower(), m.group("pattern").strip(), raw))
    return rules


def load_rules(path: Optional[str] = None) -> "RuleSet":
    if path is None:
        return RuleSet([])
    text = Path(path).read_text(encoding="utf-8")
    return RuleSet(parse_rules_text(text), source=path)


class RuleSet:
    def __init__(self, rules: Sequence[Rule], source: str = ""):
        self.rules: List[Rule] = list(rules)
        self.source = source

    def check(self, report: EffectReport) -> List[Violation]:
        hits: List[Violation] = []
        for rule in self.rules:
            if rule.kind == "command":
                if self._command_match(rule.pattern, report.command):
                    hits.append(Violation(
                        rule, None,
                        f"command matches deny pattern {rule.pattern!r}",
                    ))
                continue
            for effect in report.effects:
                if effect.kind != rule.kind and not (
                    rule.kind == "binary" and effect.kind == "binary"
                ):
                    # binary rules only match binary effects; others match same kind
                    if rule.kind != effect.kind:
                        continue
                if rule.kind == "binary":
                    if fnmatch.fnmatch(effect.target, rule.pattern) or effect.target == rule.pattern:
                        hits.append(Violation(
                            rule, effect,
                            f"binary {effect.target!r} denied by {rule.pattern!r}",
                        ))
                elif rule.kind == "network":
                    if effect.kind == "network" and _network_matches(rule.pattern, effect.target):
                        hits.append(Violation(
                            rule, effect,
                            f"network {effect.target!r} denied by {rule.pattern!r}",
                        ))
                    # also allow matching against raw URL in effect.raw
                    elif effect.kind == "network" and effect.raw != effect.target:
                        if _network_matches(rule.pattern, effect.raw):
                            hits.append(Violation(
                                rule, effect,
                                f"network {effect.raw!r} denied by {rule.pattern!r}",
                            ))
                elif rule.kind in ("read", "write", "delete"):
                    if effect.kind == rule.kind and _path_matches(rule.pattern, effect.target):
                        hits.append(Violation(
                            rule, effect,
                            f"{rule.kind} of {effect.target!r} denied by {rule.pattern!r}",
                        ))
        return hits

    @staticmethod
    def _command_match(pattern: str, command: str) -> bool:
        if any(ch in pattern for ch in "*?["):
            return fnmatch.fnmatch(command, pattern) or fnmatch.fnmatch(command.strip(), pattern)
        return pattern in command
