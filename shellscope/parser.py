"""Practical shell-command effect parser (not a full POSIX shell).

Splits on top-level ``;`` / ``&&`` / ``||`` / ``|``, tokenizes with
``shlex``, pulls redirects, and classifies common binaries into
read / write / delete / network / binary effects.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple
from urllib.parse import urlparse


_READ_BINS = {
    "cat", "head", "tail", "less", "more", "bat", "nl", "wc",
    "file", "stat", "ls", "find", "grep", "egrep", "fgrep", "rg",
    "awk", "sed", "sort", "uniq", "diff", "cmp", "md5sum", "sha256sum",
    "type", "which", "realpath", "readlink", "basename", "dirname",
}
_WRITE_BINS = {
    "touch", "mkdir", "mktemp", "tee", "truncate",
    "chmod", "chown", "chgrp", "ln", "link",
}
_DELETE_BINS = {"rm", "rmdir", "unlink", "shred"}
_NETWORK_BINS = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
    "ftp", "telnet", "dig", "nslookup", "ping", "traceroute",
}
_COPY_MOVE = {"cp", "mv", "install", "rsync"}
_PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "awk", "sed"}
_WRAPPERS = {"sudo", "env", "command", "builtin", "time", "nohup", "nice", "stdbuf"}


@dataclass
class Effect:
    kind: str          # read | write | delete | network | binary
    target: str        # path, host/url, or binary name
    detail: str = ""
    raw: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class EffectReport:
    command: str
    effects: List[Effect] = field(default_factory=list)
    statements: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def by_kind(self, kind: str) -> List[Effect]:
        return [e for e in self.effects if e.kind == kind]

    def to_dict(self):
        return {
            "command": self.command,
            "effects": [e.to_dict() for e in self.effects],
            "statements": self.statements,
            "warnings": self.warnings,
        }


def _expand_path(token: str, cwd: str) -> str:
    if not token or token.startswith("-"):
        return token
    if "://" in token or token.startswith(("/dev/fd/", "/proc/")):
        return token
    expanded = os.path.expanduser(token)
    if not os.path.isabs(expanded):
        expanded = os.path.normpath(os.path.join(cwd, expanded))
    else:
        expanded = os.path.normpath(expanded)
    return expanded


def _is_remote_spec(token: str) -> bool:
    """scp/rsync-style user@host:path (not a Windows drive and not URL)."""
    if "://" in token:
        return True
    if "@" in token and ":" in token.split("@", 1)[1]:
        return True
    return False


def _split_top_level(text: str, seps: Tuple[str, ...]) -> List[Tuple[str, Optional[str]]]:
    parts: List[Tuple[str, Optional[str]]] = []
    buf: List[str] = []
    i = 0
    n = len(text)
    quote: Optional[str] = None
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote and (i == 0 or text[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        matched = None
        for sep in sorted(seps, key=len, reverse=True):
            if text.startswith(sep, i):
                matched = sep
                break
        if matched:
            chunk = "".join(buf).strip()
            if chunk:
                parts.append((chunk, matched))
            buf = []
            i += len(matched)
            continue
        buf.append(ch)
        i += 1
    chunk = "".join(buf).strip()
    if chunk:
        parts.append((chunk, None))
    return parts


_REDIR_OP = re.compile(r"^(?:(\d)?)(>>|>|<)$")


def _peel_redirects(tokens: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    out: List[str] = []
    redirs: List[Tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        m = re.match(r"^(\d?)(>>|>|<)(.+)$", tok)
        if m and m.group(3):
            redirs.append((m.group(2), m.group(3)))
            i += 1
            continue
        m2 = _REDIR_OP.match(tok)
        if m2 and i + 1 < len(tokens):
            redirs.append((m2.group(2), tokens[i + 1]))
            i += 2
            continue
        if tok in (">&", "&>") and i + 1 < len(tokens):
            redirs.append((">", tokens[i + 1]))
            i += 2
            continue
        out.append(tok)
        i += 1
    return out, redirs


def _is_flag(tok: str) -> bool:
    return tok.startswith("-") and tok != "-"


def _positional(tokens: List[str]) -> List[str]:
    args: List[str] = []
    seen_dd = False
    for t in tokens:
        if t == "--":
            seen_dd = True
            continue
        if not seen_dd and _is_flag(t):
            continue
        args.append(t)
    return args


def _host_from(arg: str) -> str:
    if "://" in arg:
        try:
            return urlparse(arg).hostname or arg
        except Exception:  # noqa: BLE001
            return arg
    if "@" in arg:
        hostpart = arg.split("@", 1)[1]
        return hostpart.split(":", 1)[0]
    if ":" in arg and not arg.startswith("/"):
        # host:path without user
        return arg.split(":", 1)[0]
    return arg


def _add_path_effect(report: EffectReport, kind: str, token: str, cwd: str, detail: str) -> None:
    if _is_remote_spec(token) and "://" not in token:
        host = _host_from(token)
        report.effects.append(Effect("network", host, detail, token))
        return
    if "://" in token:
        report.effects.append(Effect("network", _host_from(token), detail, token))
        return
    report.effects.append(Effect(kind, _expand_path(token, cwd), detail, token))


def _classify_simple(tokens: List[str], cwd: str, report: EffectReport) -> None:
    if not tokens:
        return

    # Skip leading VAR=value assignments
    i = 0
    while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
        i += 1
    if i >= len(tokens):
        return
    tokens = tokens[i:]

    binary = os.path.basename(tokens[0])
    report.effects.append(Effect("binary", binary, "invokes binary", tokens[0]))

    rest = tokens[1:]
    rest, redirs = _peel_redirects(rest)
    for op, target in redirs:
        if op in (">", ">>"):
            _add_path_effect(report, "write", target, cwd, f"redirect {op}")
        elif op == "<":
            _add_path_effect(report, "read", target, cwd, "redirect <")

    pos = _positional(rest)

    if binary in _DELETE_BINS:
        for a in pos:
            _add_path_effect(report, "delete", a, cwd, binary)
        return

    if binary in _COPY_MOVE or binary == "scp":
        if binary == "scp":
            report  # already recorded as binary; treat like network+paths
        if len(pos) >= 2:
            sources, dest = pos[:-1], pos[-1]
            for s in sources:
                if binary == "scp" or _is_remote_spec(s):
                    _add_path_effect(report, "read", s, cwd, f"{binary} source")
                else:
                    _add_path_effect(report, "read", s, cwd, f"{binary} source")
                    if binary == "mv":
                        _add_path_effect(report, "delete", s, cwd, "mv removes source")
            if binary == "scp" or _is_remote_spec(dest):
                _add_path_effect(report, "write", dest, cwd, f"{binary} dest")
            else:
                kind = "write"
                _add_path_effect(report, kind, dest, cwd, f"{binary} dest")
        elif len(pos) == 1:
            _add_path_effect(report, "write", pos[0], cwd, binary)
        return

    if binary in _NETWORK_BINS:
        if binary in ("curl", "wget"):
            i = 0
            while i < len(rest):
                t = rest[i]
                if t in ("-o", "--output") and i + 1 < len(rest):
                    _add_path_effect(report, "write", rest[i + 1], cwd, f"{binary} -o")
                    i += 2
                    continue
                if t.startswith("--output="):
                    _add_path_effect(report, "write", t.split("=", 1)[1], cwd, f"{binary} --output")
                    i += 1
                    continue
                if t == "-O":
                    i += 1
                    continue
                if _is_flag(t):
                    i += 1
                    continue
                host = _host_from(t)
                report.effects.append(Effect("network", host or t, binary, t))
                i += 1
            return
        if binary in ("nc", "ncat", "netcat"):
            args = [t for t in rest if not _is_flag(t)]
            if args:
                report.effects.append(Effect("network", args[0], binary, args[0]))
            return
        if binary in ("ssh", "sftp"):
            args = [t for t in rest if not _is_flag(t)]
            if args:
                host = _host_from(args[0])
                report.effects.append(Effect("network", host, binary, args[0]))
            return
        for a in pos:
            report.effects.append(Effect("network", _host_from(a) or a, binary, a))
        return

    if binary in _WRITE_BINS:
        files = pos
        if binary == "chmod" and pos:
            # chmod [-R] mode file...  — drop the mode token
            files = pos[1:] if pos else []
        elif binary in ("chown", "chgrp") and pos:
            files = pos[1:] if pos else []
        elif binary == "ln":
            # ln [-s] target linkname — last is write, earlier are reads
            if len(pos) >= 2:
                for s in pos[:-1]:
                    _add_path_effect(report, "read", s, cwd, "ln target")
                _add_path_effect(report, "write", pos[-1], cwd, "ln name")
                return
        for a in files:
            _add_path_effect(report, "write", a, cwd, binary)
        return

    if binary in _READ_BINS:
        files = pos
        if binary in _PATTERN_FIRST and len(pos) >= 2:
            files = pos[1:]
        for a in files:
            _add_path_effect(report, "read", a, cwd, binary)
        return

    # Unknown binary: heuristic path-like args as soft reads
    for a in pos:
        if (
            "/" in a
            or a.startswith((".", "~"))
            or "*" in a
            or a.endswith((".py", ".sh", ".txt", ".json", ".yml", ".yaml", ".env", ".toml", ".cfg", ".ini"))
        ):
            _add_path_effect(report, "read", a, cwd, f"{binary} arg (heuristic)")


def parse_command(command: str, cwd: Optional[str] = None) -> EffectReport:
    """Parse *command* into an :class:`EffectReport`.

    Not a full POSIX shell: no ``$()`` / backtick expansion, no ``eval``
    body analysis, no arithmetic or arrays. Those cases emit warnings.
    """
    cwd = os.path.abspath(cwd or os.getcwd())
    report = EffectReport(command=command)

    if re.search(r"(?<![\\])`|\$\(|\$\{", command):
        report.warnings.append(
            "command contains substitution (`…`/$()/); inner commands are not expanded"
        )
    if re.search(r"\beval\b", command):
        report.warnings.append(
            "eval detected; effects inside the evaluated string are not analyzed"
        )

    statements = _split_top_level(command.strip(), (";", "&&", "||"))
    for stmt, _sep in statements:
        report.statements.append(stmt)
        for segment, _ in _split_top_level(stmt, ("|",)):
            segment = segment.strip()
            if not segment:
                continue
            if segment.startswith("!"):
                segment = segment[1:].lstrip()
            try:
                tokens = shlex.split(segment, posix=True)
            except ValueError as e:
                report.warnings.append(f"shlex failed on {segment!r}: {e}")
                continue
            if not tokens:
                continue
            # Unwrap sudo/env/time/…
            while tokens and os.path.basename(tokens[0]) in _WRAPPERS:
                w = os.path.basename(tokens[0])
                report.effects.append(Effect("binary", w, "wrapper", tokens[0]))
                tokens = tokens[1:]
                while tokens and _is_flag(tokens[0]) and w in ("sudo", "env", "nice", "stdbuf"):
                    flag = tokens[0]
                    tokens = tokens[1:]
                    if flag in ("-u", "-g", "-C", "-S") and tokens and not tokens[0].startswith("-"):
                        tokens = tokens[1:]
                while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                    tokens = tokens[1:]
            if tokens:
                _classify_simple(tokens, cwd, report)

    return report
