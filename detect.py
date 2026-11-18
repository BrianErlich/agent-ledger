#!/usr/bin/env python3
"""agent-ledger detectors.  Tested on Python 3.12, stdlib only, no network.

    detect.py [--db ledger.db] [--stats] [--version]

Reads sessions / turns / tool_calls (schema: SCHEMA.md), writes table `events`.
Idempotent: deletes and recomputes every event. Event kinds are listed in SCHEMA.md.
Transcript text is DATA: nothing here follows or executes it.

Optional: LEDGER_WATCH_PATHS=/srv/private:/mnt/backup (colon-separated absolute paths) adds a
`watched_path` boundary subkind for commands that name those paths.
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import re
import shlex
import sqlite3
import sys
import warnings
from urllib.parse import quote

DETECTOR_VERSION = "detect-1.2"

# Which row type each kind is judged on (useful when hand-labelling a sample to measure the heuristics).
KIND_ROWTYPES = {
    "boundary_attempt": ("tool_call",),
    "tool_denied": ("tool_call",),
    "subagent_launch": ("tool_call",),
    "cross_chat_msg": ("tool_call", "user_turn"),
    "classifier_stop": ("tool_call", "user_turn", "assistant_turn"),
    "model_swap": ("assistant_turn",),
    "compaction": ("user_turn",),
    "user_decision": ("user_turn",),
    "correction": ("user_turn",),
    "overrule": ("user_turn",),
    "concept_explained": ("assistant_turn",),
}
MECHANICAL = ("boundary_attempt", "tool_denied", "classifier_stop", "model_swap", "compaction",
              "subagent_launch", "cross_chat_msg")
HEURISTIC = ("user_decision", "correction", "overrule", "concept_explained")

# --------------------------------------------------------------------------- redaction
_REDACT = [
    (re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{16,}"), "[REDACTED:sk]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED:ghp]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED:github_pat]"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED:slack]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:akia]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{12,}"), "Bearer [REDACTED:bearer]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED:privkey]"),
    (re.compile(r"\b[MNO][A-Za-z\d_\-]{23,25}\.[\w\-]{6}\.[\w\-]{27,}\b"), "[REDACTED:discord]"),
    (re.compile(r"\beyJ[\w\-]{10,}\.[\w\-]{10,}\.[\w\-]*"), "[REDACTED:jwt]"),
    (re.compile(r"(?i)\b((?:api[_\-]?key|secret|token|passw(?:or)?d|authorization)\s*[=:]\s*)(?!\[REDACTED)[^\s'\"]{8,}"),
     r"\1[REDACTED:kv]"),
]


def redact(s: str | None) -> str:
    if not s:
        return ""
    for rx, rep in _REDACT:
        s = rx.sub(rep, s)
    return s


def clip(s: str | None, n: int = 300) -> str:
    return redact(s)[:n]


# --------------------------------------------------------------------------- shell scanner
class Word:
    __slots__ = ("text", "quoted", "via", "heredoc")

    def __init__(self, text: str, quoted: bool, via: str | None = None):
        self.text = text
        self.quoted = quoted
        self.via = via          # "heredoc_subst" for words from $(..)/`..` inside an unquoted heredoc
        self.heredoc = None     # detect-1.2: on a `<<DELIM` redirect word, the heredoc body (data, never run)

    def __repr__(self):
        return f"W({self.text!r}{',q' if self.quoted else ''})"


_SEPS = set(";|&()\n")


def _match_paren(s: str, i: int) -> int:
    """s[i] is the char after '$('; return index of the matching ')' (or len(s))."""
    depth = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                i += 2 if s[i] == "\\" else 1
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _heredoc_substs(body: str) -> list[str]:
    """detect-1.1: the $(..) and `..` substitutions bash expands inside an UNQUOTED heredoc body."""
    res, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
        elif body.startswith("$((", i):
            j = body.find("))", i + 3)
            i = n if j < 0 else j + 2
        elif body.startswith("$(", i):
            j = _match_paren(body, i + 2)
            res.append(body[i + 2:j])
            i = j + 1
        elif c == "`":
            j = body.find("`", i + 1)
            if j < 0:
                break
            res.append(body[i + 1:j])
            i = j + 1
        else:
            i += 1
    return res


def parse_shell(cmd: str, depth: int = 0) -> list[list[Word]]:
    """Split a shell string into simple commands (lists of Words).  Comments, quoted text and
    heredoc bodies never become command words; $(..), backticks and bash -c strings are recursed."""
    out: list[list[Word]] = []
    if depth > 5 or not cmd:
        return out
    cur: list[Word] = []
    buf: list[str] = []
    quoted = False
    inword = False
    pending_heredocs: list[tuple[str, bool]] = []
    i, n = 0, len(cmd)

    def end_word():
        nonlocal buf, quoted, inword
        if inword:
            cur.append(Word("".join(buf), quoted))
        buf, quoted, inword = [], False, False

    def end_cmd():
        nonlocal cur
        end_word()
        if cur:
            out.append(cur)
        cur = []

    while i < n:
        c = cmd[i]
        if c in " \t":
            end_word()
            i += 1
        elif c == "\\":
            if i + 1 < n and cmd[i + 1] == "\n":
                i += 2
                continue
            buf.append(cmd[i + 1] if i + 1 < n else "")
            inword = True
            i += 2
        elif c == "\n":
            end_cmd()
            i += 1
            if pending_heredocs:
                for delim, strip, hq, hw in pending_heredocs:
                    body = []
                    while i < n:
                        j = cmd.find("\n", i)
                        line = cmd[i:n if j < 0 else j]
                        i = n if j < 0 else j + 1
                        if (line.lstrip("\t") if strip else line) == delim:
                            break
                        body.append(line.lstrip("\t") if strip else line)
                    hw.heredoc = "\n".join(body)
                    if not hq:   # unquoted delimiter: bash runs the body's substitutions
                        for inner in _heredoc_substs("\n".join(body)):
                            for sub in parse_shell(inner, depth + 1):
                                for w in sub:
                                    w.via = "heredoc_subst"
                                out.append(sub)
                pending_heredocs = []
        elif c == "#" and not inword:
            j = cmd.find("\n", i)
            i = n if j < 0 else j
        elif c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                j = n
            buf.append(cmd[i + 1:j])
            inword = quoted = True
            i = j + 1
        elif c == '"':
            inword = quoted = True
            i += 1
            while i < n and cmd[i] != '"':
                if cmd[i] == "\\" and i + 1 < n:
                    # bash: inside "..", backslash escapes only $ ` " \ and newline (1.2; was: any char,
                    # which mangled `python3 -c "..\n.."` bodies)
                    if cmd[i + 1] in '$`"\\':
                        buf.append(cmd[i + 1])
                    elif cmd[i + 1] != "\n":
                        buf.append(cmd[i:i + 2])
                    i += 2
                elif cmd.startswith("$(", i) and not cmd.startswith("$((", i):
                    j = _match_paren(cmd, i + 2)
                    out.extend(parse_shell(cmd[i + 2:j], depth + 1))
                    buf.append("$(..)")
                    i = j + 1
                elif cmd[i] == "`":
                    j = cmd.find("`", i + 1)
                    j = n if j < 0 else j
                    out.extend(parse_shell(cmd[i + 1:j], depth + 1))
                    buf.append("`..`")
                    i = j + 1
                else:
                    buf.append(cmd[i])
                    i += 1
            i += 1
        elif cmd.startswith("$((", i):
            j = cmd.find("))", i + 3)
            j = n - 2 if j < 0 else j
            buf.append("$((..))")
            inword = True
            i = j + 2
        elif cmd.startswith("$(", i):
            j = _match_paren(cmd, i + 2)
            out.extend(parse_shell(cmd[i + 2:j], depth + 1))
            buf.append("$(..)")
            inword = True
            i = j + 1
        elif c == "`":
            j = cmd.find("`", i + 1)
            j = n if j < 0 else j
            out.extend(parse_shell(cmd[i + 1:j], depth + 1))
            buf.append("`..`")
            inword = True
            i = j + 1
        elif c == "<" and cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
            m = re.match(r"<<(-?)\s*(\\?)(['\"]?)([A-Za-z_][\w\-]*)\3", cmd[i:])
            if m:
                end_word()
                hw = Word(m.group(0), True)  # redirect operator word, harmless; carries the body (1.2)
                pending_heredocs.append((m.group(4), bool(m.group(1)), bool(m.group(2) or m.group(3)), hw))
                cur.append(hw)
                i += m.end()
            else:
                buf.append(c)
                inword = True
                i += 1
        elif c == "&" and (
            (inword and buf and buf[-1].endswith((">", "<")))
            or cmd.startswith("&>", i)
        ):
            buf.append(c)
            inword = True
            i += 1
        elif c in _SEPS:
            end_cmd()
            i += 1
            # swallow a doubled separator
            while i < n and cmd[i] in "|&" and c in "|&":
                i += 1
        else:
            buf.append(c)
            inword = True
            i += 1
    end_cmd()
    return out


_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}",
             "time", "esac", "in", "function", "coproc"}
_SKIP_SEGMENT = {"for", "case", "select"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\+)?=")
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
# wrapper -> options that take a following argument
_WRAPPERS = {
    "env": {"-u", "-C", "-S"}, "nohup": set(), "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "stdbuf": set(), "setsid": set(), "exec": {"-a"},
    "builtin": set(), "command": set(), "xargs": {"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"},
    "watch": {"-n", "-d"}, "chrt": set(), "taskset": set(), "unbuffer": set(), "flock": {"-w", "-E"},
}
_SUDOS = {"sudo", "doas", "pkexec"}
_SUDO_ARGOPTS = {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U", "-R"}
_NET = {"ssh", "scp", "sftp", "rsync", "curl", "wget", "ping", "ping6", "nc", "ncat", "netcat", "telnet",
        "socat", "traceroute", "tracepath", "mtr"}
_SCANNERS = {"nmap", "masscan", "arp-scan", "zmap", "netdiscover"}
_DOCKERS = {"docker", "docker-compose", "podman", "lxc", "lxd"}
_SHUTDOWN = {"shutdown", "halt", "poweroff"}
_SYSCTL_POWER = {"reboot", "poweroff", "halt", "kexec", "soft-reboot"}
_SYSCTL_RO = {"status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-unit-files",
              "list-timers", "list-sockets", "cat", "help", "list-dependencies", "list-jobs"}
_NOPATH = {"echo", "printf"}
_NOEXEC = {"which", "type", "man", "whereis", "help", "apropos", "whatis", "info"}

_IP4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d])")
_LOCALHOST = re.compile(r"(?:^|[@/\[])(?:[A-Za-z0-9\-]+\.)*[A-Za-z0-9\-]+\.local(?=$|[:/\]\s])", re.I)
_TSNET = re.compile(r"(?:^|[@/])(?:[A-Za-z0-9\-]+\.)*[A-Za-z0-9\-]+\.ts\.net(?=$|[:/\s])", re.I)
_FE80 = re.compile(r"(?<![\w:])fe80:", re.I)
_P_CRED = r"(?:~|\$HOME|\$\{HOME\}|/root|/home/[A-Za-z0-9_\-]+|/Users/[A-Za-z0-9_.\-]+)/\.(?:aws|ssh|config/gcloud)(?=/|$|[\s\"'])"


def _watch_pattern():
    """LEDGER_WATCH_PATHS: colon-separated absolute paths whose mention is a `watched_path` boundary hit."""
    ps = [p.rstrip("/") for p in os.environ.get("LEDGER_WATCH_PATHS", "").split(":") if p.startswith("/") and len(p) > 1]
    if not ps:
        return None
    return "(?:" + "|".join(re.escape(p) for p in sorted(set(ps), key=len, reverse=True)) + r")(?=/|$|[\s\"'])"


_PATH_CACHE: dict = {}


def _path_rx():
    """[(subkind, rx_anywhere, rx_at_start)]; rebuilt when LEDGER_WATCH_PATHS changes."""
    key = os.environ.get("LEDGER_WATCH_PATHS", "")
    if key not in _PATH_CACHE:
        pats = [("credential_dir", _P_CRED, r"(?<![\w.\-])")]
        w = _watch_pattern()
        if w:
            pats.append(("watched_path", w, r"(?<![\w.~/\-])"))
        _PATH_CACHE.clear()
        _PATH_CACHE[key] = [(name, re.compile(pre + pat), re.compile("^" + pat)) for name, pat, pre in pats]
    return _PATH_CACHE[key]


def _ip_class(ip: str) -> str | None:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
    except ValueError:
        return None
    if max(a, b, c, d) > 255:
        return None
    if a == 192 and b == 168:
        return "lan_net"
    if a == 10:
        return "lan_net"
    if a == 172 and 16 <= b <= 31:
        return "lan_net"
    if a == 100 and 64 <= b <= 127:
        return "tailnet_net"
    return None


def _net_subkinds(args: list[Word]) -> list[str]:
    found = []
    for w in args:
        t = w.text
        for m in _IP4.finditer(t):
            k = _ip_class(m.group(1))
            if k and k not in found:
                found.append(k)
        if _TSNET.search(t) and "tailnet_net" not in found:
            found.append("tailnet_net")
        if (_FE80.search(t) or _LOCALHOST.search(t)) and "local_host" not in found:
            found.append("local_host")
    return found


def _path_subkinds(args: list[Word]) -> list[str]:
    found = []
    for w in args:
        t = w.text
        stripped = re.sub(r"^--?[A-Za-z][\w\-]*=", "", t)
        for name, rx_any, rx_start in _path_rx():
            if name in found:
                continue
            if w.quoted:
                if rx_start.match(stripped):
                    found.append(name)
            elif rx_any.search(t):
                found.append(name)
    return found


def _strip_opts(args: list[Word], argopts: set[str]) -> list[Word]:
    i = 0
    while i < len(args):
        t = args[i].text
        if t == "--":
            i += 1
            break
        if t.startswith("-") and len(t) > 1 or _ASSIGN.match(t):
            i += 2 if t in argopts else 1
            continue
        break
    return args[i:]


def _unwrap(words: list[Word]) -> list[tuple[str, list[Word], bool]]:
    """Return [(name, args, via_sudo)] for the effective command(s) of one simple command."""
    results: list[tuple[str, list[Word], bool]] = []
    ws = list(words)
    via_sudo = False
    guard = 0
    while ws and guard < 12:
        guard += 1
        while ws and (_ASSIGN.match(ws[0].text) and not ws[0].quoted or ws[0].text in _KEYWORDS):
            ws = ws[1:]
        if not ws:
            break
        name = os.path.basename(ws[0].text)
        if name in _SKIP_SEGMENT:
            return results
        args = ws[1:]
        if name in _SUDOS:
            results.append((name, args, False))
            ws = _strip_opts(args, _SUDO_ARGOPTS)
            via_sudo = True
            continue
        if name in _WRAPPERS:
            if name == "command" and any(a.text in ("-v", "-V") for a in args[:2]):
                return results
            if name == "timeout":
                rest = _strip_opts(args, _WRAPPERS[name])
                ws = rest[1:] if rest else []
            elif name == "watch":
                rest = _strip_opts(args, _WRAPPERS[name])
                ws = rest
            else:
                ws = _strip_opts(args, _WRAPPERS[name])
            continue
        results.append((name, args, via_sudo))
        break
    return results


def _commands_in(words: list[Word], depth: int) -> list[tuple[str, list[Word], list[Word]]]:
    """Expand one simple command to [(name, args, original_words)], recursing into shell -c / eval / find -exec."""
    res = []
    for name, args, _ in _unwrap(words):
        res.append((name, args, words))
        if name in _SHELLS:
            for k, a in enumerate(args):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a.text) and k + 1 < len(args):
                    for sub in parse_shell(args[k + 1].text, depth + 1):
                        res.extend(_commands_in(sub, depth + 1))
                    break
        elif name == "eval" and depth < 4:
            for sub in parse_shell(" ".join(a.text for a in args), depth + 1):
                res.extend(_commands_in(sub, depth + 1))
        elif name == "find":
            for k, a in enumerate(args):
                if a.text in ("-exec", "-execdir", "-ok", "-okdir"):
                    sub = []
                    for b in args[k + 1:]:
                        if b.text in (";", "+"):
                            break
                        sub.append(b)
                    if sub:
                        res.extend(_commands_in(sub, depth + 1))
    return res


# --------------------------------------------------------------------------- python bodies (detect-1.2)
# Python run by a shell call (`python3 -c CODE`, `python3 [-] <<EOF` heredoc, `python3 file.py` whose
# content was written earlier in the record) is PARSED with `ast` (never compiled or run). Shell-outs
# whose command is a literal become command strings for the same scanner. Anything not literal is
# counted as unresolved, never a hit.
PY_STATS: collections.Counter = collections.Counter()
PY_UNRESOLVED: list[tuple[str, str]] = []      # (api, reason), cleared by run()
_PY_NAME = re.compile(r"python(?:[23](?:\.\d+)?)?")
_PY_ARGOPTS = {"-W", "-X", "--check-hash-based-pycs"}
_PY_FLAGS = set("bBdEhiIOPqsSuvVx")
_UNRES = "__unresolved__"
_SP_EXEC = {"run", "call", "check_call", "check_output", "Popen"}
_SP_SHELL = {"getoutput", "getstatusoutput"}
_MODULES = {"subprocess", "os", "pty", "socket", "asyncio", "shlex", "posix"}


def _py_parse(code: str):
    """-> (tree|None, status ok|partial|failed). On SyntaxError (redaction, 8 KB/2,048-byte caps) retry
    on the whole lines before the error, up to 3 times: those statements are real code."""
    src = code
    for attempt in range(4):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")      # SyntaxWarning (bad escapes) from stored code
                return ast.parse(src), ("ok" if attempt == 0 else "partial")
        except SyntaxError as e:
            lines = src.split("\n")
            ln = min((e.lineno or 1) - 1, len(lines) - 1)   # keep the lines before the error line
            if ln <= 0:
                break
            src = "\n".join(lines[:ln])
            if not src.strip():
                break
        except (ValueError, RecursionError, MemoryError, OverflowError):
            break
    return None, "failed"


class _PyScan:
    """Walk one parsed module and collect shell-outs. Results: cmds [(api, kind 'shell'|'argv', value, lineno)],
    sockets [(api, host, port)], unresolved [(api, reason)]."""

    def __init__(self, tree):
        self.mods: dict[str, str] = {m: m for m in _MODULES}       # local name -> module
        self.funcs: dict[str, str] = {}                            # local name -> module.func
        self.assigned: dict[str, list] = collections.defaultdict(list)
        self.cmds, self.sockets, self.unresolved = [], [], []
        self.uses_socket = False
        nodes = list(ast.walk(tree))
        for nd in nodes:
            if isinstance(nd, ast.Import):
                for a in nd.names:
                    top = a.name.split(".")[0]
                    if a.asname and a.name in _MODULES:
                        self.mods[a.asname] = a.name
                    if top == "socket" or a.name == "socket":
                        self.uses_socket = True
            elif isinstance(nd, ast.ImportFrom) and nd.module:
                if nd.module == "socket":
                    self.uses_socket = True
                for a in nd.names:
                    if nd.module in _MODULES:
                        self.funcs[a.asname or a.name] = f"{nd.module}.{a.name}"
            elif isinstance(nd, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.With, ast.NamedExpr)):
                tgts = (nd.targets if isinstance(nd, ast.Assign) else
                        [nd.target] if isinstance(nd, (ast.AnnAssign, ast.AugAssign, ast.For, ast.NamedExpr)) else
                        [it.optional_vars for it in nd.items if it.optional_vars is not None])
                val = nd.value if isinstance(nd, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
                for t in tgts:
                    for nm in ast.walk(t):
                        if isinstance(nm, ast.Name):
                            # only `NAME = <value>` with a plain Name target is resolvable; anything else poisons
                            ok = isinstance(nd, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and t is nm and val is not None
                            self.assigned[nm.id].append(val if ok else None)
            elif isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                for a in ast.walk(nd.args):
                    if isinstance(a, ast.arg):
                        self.assigned[a.arg].append(None)
            elif isinstance(nd, ast.comprehension):
                for nm in ast.walk(nd.target):
                    if isinstance(nm, ast.Name):
                        self.assigned[nm.id].append(None)
            elif isinstance(nd, ast.ExceptHandler) and nd.name:
                self.assigned[nd.name].append(None)
        if self.uses_socket:
            self.mods.setdefault("socket", "socket")
        for nd in nodes:
            if isinstance(nd, ast.Call):
                self._call(nd)

    # ---- literal resolution (no guessing: a Name resolves only if assigned exactly once, to a literal)
    def lit(self, nd, depth=0):
        if depth > 6 or nd is None:
            return None
        if isinstance(nd, ast.Constant):
            if isinstance(nd.value, str):
                return nd.value
            if isinstance(nd.value, bytes):
                return nd.value.decode("utf-8", "replace")
            return None
        if isinstance(nd, ast.BinOp) and isinstance(nd.op, ast.Add):
            a, b = self.lit(nd.left, depth + 1), self.lit(nd.right, depth + 1)
            return a + b if isinstance(a, str) and isinstance(b, str) else None
        if isinstance(nd, ast.Name):
            vals = self.assigned.get(nd.id, [])
            if len(vals) == 1 and vals[0] is not None:
                return self.lit(vals[0], depth + 1)
        return None

    def argv(self, nd, depth=0):
        """-> (list[str] with _UNRES placeholders, n_unresolved) or None when argv[0] is not literal."""
        if depth > 6 or nd is None:
            return None
        if isinstance(nd, ast.Name):
            vals = self.assigned.get(nd.id, [])
            if len(vals) == 1 and vals[0] is not None:
                return self.argv(vals[0], depth + 1)
            return None
        if isinstance(nd, ast.Call) and self.qual(nd.func) == "shlex.split" and nd.args:
            s = self.lit(nd.args[0])
            if s is None:
                return None
            try:
                return shlex.split(s), 0
            except ValueError:
                return None
        if isinstance(nd, (ast.List, ast.Tuple)):
            out, bad = [], 0
            for e in nd.elts:
                v = self.lit(e)
                if v is None:
                    out.append(_UNRES)
                    bad += 1
                else:
                    out.append(v)
            if not out or out[0] == _UNRES:
                return None
            return out, bad
        return None

    def qual(self, f) -> str | None:
        if isinstance(f, ast.Name):
            return self.funcs.get(f.id)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.mods:
            return f"{self.mods[f.value.id]}.{f.attr}"
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name):
            if self.mods.get(f.value.value.id) == "asyncio" and f.value.attr == "subprocess":
                return f"asyncio.{f.attr}"
        return None

    @staticmethod
    def _kw(call, name):
        return next((k.value for k in call.keywords if k.arg == name), None)

    def _emit_argv(self, api, nd, ln, prog=None):
        av = self.argv(nd)
        if av is None:
            if isinstance(nd, ast.Constant) or (isinstance(nd, ast.Name) and self.lit(nd) is not None):
                s = self.lit(nd)
                if s is not None:   # a bare string as argv (POSIX: the program path, no args)
                    av = ([s], 0)
        if av is None:
            self.unresolved.append((api, "argv not literal"))
            return
        argv, bad = av
        if prog is not None:
            argv = [prog] + argv[1:]
        if bad:
            self.unresolved.append((api, f"{bad} argv element(s) not literal (argv[0] known)"))
        self.cmds.append((api, "argv", argv, ln))

    def _emit_shell(self, api, nd, ln):
        s = self.lit(nd)
        if s is None:
            self.unresolved.append((api, "shell string not literal"))
            return
        self.cmds.append((api, "shell", s, ln))

    def _call(self, c: ast.Call):
        q = self.qual(c.func)
        ln = getattr(c, "lineno", 0)
        a = c.args
        if q is None:
            if self.uses_socket and isinstance(c.func, ast.Attribute) and c.func.attr in ("connect", "connect_ex", "sendto"):
                addr = a[-1] if c.func.attr == "sendto" and len(a) >= 2 else (a[0] if a and c.func.attr != "sendto" else None)
                self._socket(f".{c.func.attr}", addr)
            return
        mod, fn = q.split(".", 1)
        first = a[0] if a else self._kw(c, "args")
        if mod == "subprocess" and fn in _SP_EXEC:
            if first is None:
                return
            sh = self._kw(c, "shell")
            if sh is None or (isinstance(sh, ast.Constant) and not sh.value):
                self._emit_argv(q, first, ln)
            elif isinstance(sh, ast.Constant) and sh.value:
                av = self.argv(first)
                if av is not None:      # shell=True with a list: argv[0] is the shell command string
                    self.cmds.append((q, "shell", av[0][0], ln))
                else:
                    self._emit_shell(q, first, ln)
            else:
                self.unresolved.append((q, "shell= not literal"))
        elif (mod == "subprocess" and fn in _SP_SHELL) or (mod in ("os", "posix") and fn in ("system", "popen")) \
                or (mod == "asyncio" and fn == "create_subprocess_shell"):
            if first is not None:
                self._emit_shell(q, first, ln)
        elif mod == "asyncio" and fn == "create_subprocess_exec":
            if a and not any(isinstance(x, ast.Starred) for x in a):
                self._emit_argv(q, ast.List(elts=list(a)), ln)
            else:
                self.unresolved.append((q, "argv not literal"))
        elif mod == "pty" and fn == "spawn":
            if first is not None:
                self._emit_argv(q, first, ln)
        elif mod in ("os", "posix") and re.fullmatch(r"(exec|spawn)[lv]p?e?|posix_spawnp?", fn):
            off = 1 if fn.startswith("spawn") else 0
            if len(a) <= off + 1 or any(isinstance(x, ast.Starred) for x in a):
                self.unresolved.append((q, "argv not literal"))
                return
            prog = self.lit(a[off])
            if prog is None:
                self.unresolved.append((q, "program not literal"))
                return
            if fn.startswith("posix_spawn") or re.fullmatch(r"(?:exec|spawn)vp?e?", fn):
                self._emit_argv(q, a[off + 1], ln, prog=prog)
            else:   # l-variants: positional argv, trailing env for *e
                tail = list(a[off + 1:-1] if fn.endswith("e") else a[off + 1:])
                if not tail:
                    tail = [ast.Constant(prog)]
                self._emit_argv(q, ast.List(elts=tail), ln, prog=prog)
        elif q == "socket.create_connection":
            self._socket(q, first)

    def _socket(self, api, addr):
        if isinstance(addr, ast.Tuple) and addr.elts:
            host = self.lit(addr.elts[0])
            if host is None:
                self.unresolved.append((f"socket{api}" if api.startswith(".") else api, "address not literal"))
                return
            port = addr.elts[1].value if len(addr.elts) > 1 and isinstance(addr.elts[1], ast.Constant) else "?"
            self.sockets.append((f"socket{api}" if api.startswith(".") else api, host, port))


def python_shellouts(code: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]], str]:
    """Parse Python source (never run it). -> (commands [(api, shell_string, via)], unresolved [(api, reason)],
    status ok|partial|failed). Socket connects come back as ('socket.connect', 'HOST:PORT', 'python_socket')."""
    tree, status = _py_parse(code)
    if tree is None:
        return [], [], status
    try:
        s = _PyScan(tree)
    except RecursionError:
        return [], [], "failed"
    out = []
    for api, kind, val, _ln in s.cmds:
        out.append((api, val if kind == "shell" else shlex.join(val), "python_subprocess"))
    for api, host, port in s.sockets:
        out.append((api, f"{host}:{port}", "python_socket"))
    return out, s.unresolved, status


def _py_code_of(args: list[Word]) -> tuple[str | None, str | None, str | None]:
    """For `python [opts] ...` args -> (inline_code, script_path, how). how: 'c' | 'stdin' | 'file' | None."""
    heredoc = next((w.heredoc for w in args if w.heredoc is not None), None)
    k = 0
    while k < len(args):
        w = args[k]
        t = w.text
        if w.heredoc is not None or (t.startswith("<<") and w.quoted):
            k += 1
            continue
        if re.fullmatch(r"\d*>>?|\d*>&|&>|<", t):      # redirect operator + target
            if t == "<" and k + 1 < len(args):
                return None, args[k + 1].text, "file"
            k += 2
            continue
        if re.match(r"\d*>|&>", t):
            k += 1
            continue
        if t.startswith("<") and not t.startswith("<<"):
            return None, t[1:], "file"
        if t == "-c" or (re.fullmatch(r"-[A-Za-z]+", t) and t.endswith("c") and set(t[1:-1]) <= _PY_FLAGS):
            return (args[k + 1].text if k + 1 < len(args) else None), None, "c"
        if t.startswith("-c") and len(t) > 2:
            return t[2:], None, "c"
        if t in ("-m",) or (t.startswith("-") and t.endswith("m") and set(t[1:-1]) <= _PY_FLAGS and len(t) > 1):
            return None, None, None
        if t in _PY_ARGOPTS:
            k += 2
            continue
        if t == "-":
            return heredoc, None, "stdin" if heredoc is not None else None
        if t.startswith("-"):
            k += 1
            continue
        return None, t, "file"
    if heredoc is not None:
        return heredoc, None, "stdin"
    return None, None, None


_HOME = os.path.expanduser("~")


def effective_cwd(cwd: str | None, prior: list[list[Word]]) -> str | None:
    """The directory after the `cd` commands that precede this one in the same shell string (literal
    targets only; `cd -`, pushd/popd or a non-literal target -> None, i.e. unknown)."""
    for ws in prior:
        name = os.path.basename(ws[0].text) if ws else ""
        if name in ("pushd", "popd"):
            return None
        if name == "cd":
            args = [w.text for w in ws[1:] if w.text in ("-",) or not w.text.startswith("-")]
            if not args:
                cwd = _HOME
            elif len(args) != 1 or args[0] == "-":
                return None
            else:
                cwd = resolve_path(args[0], cwd)
                if cwd is None:
                    return None
    return cwd


def resolve_path(p: str, cwd: str | None) -> str | None:
    """Absolute path for a script/file word, or None when it cannot be known without guessing."""
    if not p or "$(" in p or "`" in p or "*" in p:
        return None
    if p.startswith("~/"):
        p = _HOME + p[1:]
    elif p.startswith(("$HOME/", "${HOME}/")):
        p = _HOME + p[p.index("/"):]
    if "$" in p:
        return None
    if not p.startswith("/"):
        if not cwd:
            return None
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def shell_file_writes(cmd: str, cwd: str | None = None) -> list[tuple[str, str]]:
    """detect-1.2: [(abs_path, content)] for `cat > f <<EOF` / `tee f <<EOF` heredoc writes in a shell string."""
    res = []
    parsed = parse_shell(cmd)
    for idx, words in enumerate(parsed):
        body = next((w.heredoc for w in words if w.heredoc is not None), None)
        if body is None or not words:
            continue
        name = os.path.basename(words[0].text)
        tgt = None
        if name == "cat":
            for k, w in enumerate(words):
                if w.text in (">", ">|") and k + 1 < len(words):
                    tgt = words[k + 1].text
                elif w.text.startswith(">") and not w.text.startswith((">>", ">&")) and len(w.text) > 1:
                    tgt = w.text[1:].lstrip("|")
        elif name == "tee" and not any(w.text in ("-a", "--append") for w in words[1:]):
            tgt = next((w.text for w in words[1:] if not w.text.startswith(("-", "<", ">"))), None)
        if tgt:
            p = resolve_path(tgt, effective_cwd(cwd, parsed[:idx]))
            if p:
                res.append((p, body))
    return res


def scan_command(cmd: str) -> list[tuple[str, str]]:
    """Return [(subkind, evidence)] for boundary_attempt in a Bash command string."""
    return [(s, e) for s, e, _ in scan_command_ex(cmd)]


def scan_command_ex(cmd: str, files: dict | None = None, cwd: str | None = None,
                    _depth: int = 0) -> list[tuple[str, str, str | None]]:
    """Return [(subkind, evidence, via)]; via='heredoc_subst' when the hit came from a substitution
    inside an unquoted heredoc body (detect-1.1), 'python_subprocess' / 'python_socket' from Python run
    inline (`-c`, stdin heredoc), 'python_file:<path>' from a script whose content `files` holds
    (detect-1.2), else None. One entry per subkind."""
    hits: dict[str, str] = {}
    vias: dict[str, str | None] = {}

    def add(sub: str, words: list[Word]):
        if sub not in hits:
            ws = list(words)
            while ws and ((_ASSIGN.match(ws[0].text) and not ws[0].quoted) or ws[0].text in _KEYWORDS):
                ws = ws[1:]
            hits[sub] = " ".join(w.text for w in ws)
            vias[sub] = next((w.via for w in words if w.via), None)

    def add_py(code: str, via_base: str | None):
        PY_STATS["python_bodies"] += 1
        found, unres, status = python_shellouts(code)
        PY_STATS[f"parse_{status}"] += 1
        PY_STATS["unresolved"] += len(unres)
        PY_UNRESOLVED.extend(unres)
        for api, sub_cmd, via in found:
            v = via_base or via
            PY_STATS["shellouts" if via == "python_subprocess" else "socket_literal"] += 1
            if via == "python_socket":
                host = sub_cmd.rsplit(":", 1)[0]
                for sub in _net_subkinds([Word(host, True)]):
                    if sub not in hits:
                        hits[sub], vias[sub] = f"{api} {sub_cmd}", v
                continue
            if _depth >= 4:
                continue
            for sub, ev, _v in scan_command_ex(sub_cmd, files, cwd, _depth + 1):
                if sub not in hits:
                    hits[sub], vias[sub] = ev, v

    parsed = parse_shell(cmd)
    for idx, words in enumerate(parsed):
        for name, args, orig in _commands_in(words, 0):
            if name in _NOEXEC:
                continue
            if name in ("sudo", "doas", "pkexec"):
                add("sudo", orig)
            elif name == "su":
                add("su", orig)
            elif name == "reboot":
                add("reboot", orig)
            elif name in _SHUTDOWN:
                add("shutdown", orig)
            elif name == "systemctl":
                if not any(a.text == "--user" for a in args):
                    verb = next((a.text for a in args if not a.text.startswith("-")), "")
                    if verb in _SYSCTL_POWER:
                        add("shutdown", orig)
                    elif verb in _SYSCTL_RO or not verb:
                        add("systemctl_readonly", orig)
                    else:
                        add("systemctl", orig)
            elif name in _DOCKERS:
                add("docker", orig)
            elif name in _SCANNERS:
                add("scanner", orig)
            if name in _NET:
                for sub in _net_subkinds(args):
                    add(sub, orig)
            if name not in _NOPATH:
                for sub in _path_subkinds([Word(name, False)] + args):
                    add(sub, orig)
            if _PY_NAME.fullmatch(name):
                code, script, how = _py_code_of(args)
                if code is not None:
                    add_py(code, None)
                elif how == "file" and script:
                    p = resolve_path(script, effective_cwd(cwd, parsed[:idx]))
                    if p is None:
                        PY_STATS["script_path_unresolved"] += 1
                    elif files is not None and files.get(p) is not None:
                        PY_STATS["script_linked"] += 1
                        add_py(files[p][0], f"python_file:{p}")
                    elif files is not None and p in files:
                        PY_STATS["script_state_unknown"] += 1     # an Edit we could not apply
                    else:
                        PY_STATS["script_not_in_record"] += 1
    return [(k, v, vias.get(k)) for k, v in hits.items()]


# --------------------------------------------------------------------------- text helpers
_TAGS = ("system-reminder|task-notification|agent-message|cross-session-message|command-name|"
         "command-message|command-args|local-command-stdout|local-command-stderr|local-command-caveat|"
         "artifact-content-[a-z\\-]+|user-prompt-submit-hook|environment_context")
_TAG_RE = re.compile(r"<(" + _TAGS + r")\b[^>]*>.*?</\1>", re.S | re.I)
_TAG_OPEN_RE = re.compile(r"<(" + _TAGS + r")\b[^>]*>.*\Z", re.S | re.I)  # unterminated

MACHINE_PREFIXES = (
    "Another Claude session sent", "[Subagent hand-back]", "This session is being continued",
    "Your response above was stopped by a safety classifier", "Caveat: The messages below",
    "[Request interrupted", "<artifact-content", "# AGENTS.md instructions",
    "The user doesn't want to proceed", "Stop hook feedback", "[tool_result]",
)
_LAUNCH_RX = re.compile(r"^You are (?:now )?the [\w\-\. ]{2,60}?(?:session|worker|WORKER|agent|subagent)\b")
_SUBAGENT_RX = re.compile(r"^You are subagent\b", re.I)
PASTE_LIMIT = 1500


def human_text(text: str | None) -> str | None:
    """Return the cleaned text of a user turn typed by the human, or None if it is machine-generated."""
    if not text:
        return None
    t = _TAG_RE.sub("", text)
    t = _TAG_OPEN_RE.sub("", t)
    t = t.replace("[tool_result]", "").replace("[image]", "").strip()
    if not t:
        return None
    t = t.replace("’", "'").replace("‘", "'")
    for p in MACHINE_PREFIXES:
        if t.startswith(p):
            return None
    if _LAUNCH_RX.match(t) or _SUBAGENT_RX.match(t):
        return None
    if len(t) > PASTE_LIMIT:
        return None
    return t


_ASK_END = re.compile(r"\?[\s\*_`\"')\]>\-]*$")
_ASK_PHRASES = re.compile(
    r"\b(?:ok\?|okay\?|shall i|should i|do you want|would you like|want me to|your call|say go|say the word|"
    r"let me know|go ahead\?|approve\b|approval|your decision|tell me (?:whether|if|which)|reply (?:yes|go)|"
    r"which (?:one|option|do you)|confirm)", re.I)


_ADDRESS = re.compile(r"\b(?:you|your|you'?re|you'?ll|you'?d)\b", re.I)


def addressed_user(text: str | None) -> bool:
    """detect-1.1 ask-test: the previous assistant turn addressed the user (an ask, or second-person
    address in its last 700 chars), not only a literal question."""
    if not text:
        return False
    return is_ask(text) or bool(_ADDRESS.search(text.strip()[-700:]))


def is_ask(text: str | None) -> bool:
    if not text:
        return False
    t = text.strip()
    tail = t[-700:]
    if _ASK_END.search(t[-200:]):
        return True
    return bool(_ASK_PHRASES.search(tail))


_REC_RX = re.compile(r"\b(?:i recommend|my recommendation|i'?d suggest|i suggest|i'?d recommend|i would recommend|my pick|recommendation:)", re.I)

_APP_START = re.compile(
    r"^[\W_]*(?:yes|yeah|yea|yep|yup|ya|y|ok|okay|k|sure thing|sure|ship it|same doc|(?:looks|sounds) (?:good|great|fine)|(?:i\s+)?approved?|do it|proceed|sounds good|lgtm|looks good|"
    r"please do|fine|agreed|confirmed?|let'?s go|yes please|push it|merge it|go(?=\s*[.,!]|\s*$|\s+(?:ahead|for it|on|with|time|and))"
    r"|go ahead)\b", re.I)
_REF_START = re.compile(
    r"^[\W_]*(?:no(?=\s*[,.!;:]|\s*$|\s+(?:don'?t|do not|not|stop|wait|hold|let'?s|i\s|thanks|thank|that|keep|leave|instead|just|please|way|need)\b)"
    r"(?!\s+(?:problem|worries|rush|issue))|nope|nah|don'?t|do not|stop(?=\s*[,.!;:]|\s*$|\s+(?:it|that|this|now|doing|the|and|please|everything))|"
    r"wait(?=\s*[,.!;:]|\s*$|\s+(?:for|until|a\s+(?:sec|min|moment)|before|don'?t|no\b))|hold(?:\s+on|\s+off)?(?=\s*[,.!;:]|\s*$|\s+(?:on|off|up|that|it|the|your))|"
    r"not yet|negative|cancel|abort|never ?mind|hang on|let'?s not|i'?d rather not|not now|actually,?\s+(?:no|don'?t|wait|hold))\b", re.I)
_APP_ANY = re.compile(r"\b(?:go ahead|ship it|do it|approved|proceed|(?:sounds|looks) (?:good|great|fine)|please do|lgtm|let'?s go|"
                      r"go for it|yes please|sure thing|same doc)\b", re.I)
_REF_ANY = re.compile(r"\b(?:not yet|hold off|hold on|wait for|don'?t (?:do|push|ship|merge|send|run|deploy|publish)|do not (?:do|push|ship|merge|send|run|deploy|publish)|never ?mind)\b", re.I)


_CHOICE = re.compile(r"^\W*(?:option\s+)?[A-Za-z1-9]\W*$|\b(?:go with|let'?s (?:do|go with)|use|pick|choose|prefer|option|"
                     r"the (?:first|second|third|last|latter|former)|both|either|neither|all of (?:it|them)|everything)\b", re.I)


def classify_decision(t: str) -> tuple[str, str] | None:
    """-> (subkind, how) or None.  t is cleaned human text."""
    head = t[:200]
    a_s, r_s = bool(_APP_START.match(head)), bool(_REF_START.match(head))
    a_a = any(not re.search(r"(?:n'?t|not|never|\bwithout)\s+(?:\w+\s+)?$", head[max(0, m.start() - 16):m.start()], re.I)
              for m in _APP_ANY.finditer(head))
    r_a = bool(_REF_ANY.search(head))
    approve, refuse = a_s or a_a, r_s or r_a
    if approve and not refuse:
        return "approve", "start" if a_s else "contains"
    if refuse and not approve:
        return "refuse", "start" if r_s else "contains"
    if approve and refuse:
        return "other", "mixed"
    return None


_CORR = [
    ("repeat", re.compile(r"(?<!like )(?<!as )(?<!as i )\bi said\b|\bi (?:already )?(?:told|asked) you\b|\bi didn'?t ask\b|\byou were supposed to\b|\byou forgot\b|\byou missed\b|\bi never said\b", re.I)),
    ("blame", re.compile(r"\bwhy (?:did|would|are|were) you\b", re.I)),
    ("stop", re.compile(r"(?:^|[.!?,;\n]\s*)(?:please\s+)?stop\b|\bdon'?t do that\b|\byou shouldn'?t\b|\byou should not\b|\bundo (?:that|it|this)\b|\brevert that\b|\bnever do that\b", re.I)),
    ("wrong", re.compile(r"(?:^|[.!?\n]\s*)no[,.!]|^no\s+(?:that|it|you|this|i|not|don)|(?:^|[.!?\n]\s*)(?:wrong|incorrect)\b|"
                         r"\b(?:that'?s|that is|this is|it'?s|you'?re|you are|is|are|was|were)\s+(?:just\s+|totally\s+|completely\s+)?(?:wrong|incorrect)\b(?!\s+(?:word|way|place|time|order|one))|\bthat'?s not\b|\bthat is not\b|\bthat isn'?t\b|\bnot what i\b", re.I)),
]


def classify_corrections(t: str) -> list[tuple[str, str]]:
    """detect-1.1: every matching correction subkind (one event each)."""
    head = t[:600]
    res = []
    for sub, rx in _CORR:
        m = rx.search(head)
        if m:
            res.append((sub, head[max(0, m.start() - 20): m.end() + 40]))
    return res


def classify_correction(t: str) -> tuple[str, str] | None:
    head = t[:600]
    for sub, rx in _CORR:
        m = rx.search(head)
        if m:
            return sub, head[max(0, m.start() - 20): m.end() + 40]
    return None


_CONCEPT_PHRASES = re.compile(
    r"\b(?:means that|the concept is|the concept of|in other words|the idea is|the idea behind|put simply|simply put|"
    r"stands for|think of it as|think of this as|which means that|is defined as|this means|that means|what that means|"
    r"the reason is|the trade-?off|the catch is|the risk is|why this matters|the rule is)\b", re.I)
_BOLD_LEAD = re.compile(r"\*\*([^*\n]{2,60}?)(?::\*\*[ \t]+|\*\*[ \t]*[:\u2014\u2013][ \t]+|\*\*[ \t]+-[ \t]+)(\S[^\n]{40,})")
_DEFINING = re.compile(r"^(?:an?|the)\b[^.]{0,80}?\b(?:is|are)\b|\b(?:means|refers to|stands for|is when|are when)\b|\b(?:is|are) (?:an?|the)\b", re.I)
_BOLD_SKIP = re.compile(r"^(?:option|recommend|rec\b|q\b|question|note|next|status|risk|cost|decision|ask|done|result|why|what|"
                        r"summary|tl;?dr|do |fix|plan|step|a\b|b\b|c\b|\d)", re.I)


def classify_concept(t: str) -> tuple[str, str] | None:
    m = _CONCEPT_PHRASES.search(t)
    if m:
        return "phrase", t[max(0, m.start() - 100): m.end() + 120]
    for m in _BOLD_LEAD.finditer(t):
        if not _BOLD_SKIP.match(m.group(1).strip()) and _DEFINING.search(m.group(2)):
            return "bold_term", f"**{m.group(1)}**: {m.group(2)[:200]}"
    return None


# --------------------------------------------------------------------------- denial / stop phrases
_DENY_RULES = [
    ("classifier_denial", re.compile(r"denied by the Claude Code auto mode classifier", re.I)),
    ("classifier_no_verdict", re.compile(r"auto mode classifier gave no verdict", re.I)),
    ("user_declined", re.compile(r"The user doesn'?t want to proceed|user rejected|rejected by the user", re.I)),
    ("tool_blocked", re.compile(r"^\s*<tool_use_error>\s*Blocked", re.I)),
    ("hook_block", re.compile(r"hook[^\n]{0,60}(?:block|den(?:y|ied)|refus)|(?:block|den(?:y|ied))[^\n]{0,40}\bhook", re.I)),
    ("permission_denied", re.compile(r"Permission (?:for|to use)[^\n]{0,120}(?:denied|rejected)|requires approval|built-in Claude Code safety check", re.I)),
]
_DENIED_KIND_MAP = {"user-rejected": "user_declined", "automode-blocked": "classifier_denial", "classifier-error": "classifier_no_verdict",
                    "permission-rule": "permission_denied", "blocked-rule": "tool_blocked",
                    "perm-reject": "permission_denied"}
_STOP_META = re.compile(r"^\s*Your response above was stopped by a safety classifier", re.I)
_STOP_TOOL = re.compile(r"stopped by a safety classifier", re.I)
_STOP_API = re.compile(r"safeguards flagged this message|triggered cyber-related safeguards", re.I)
_REASON = re.compile(r"Reason:\s*\[([^\]]{1,80})\]")


# --------------------------------------------------------------------------- db plumbing
def table_cols(con, table):
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})")]


def sel(con, table, wanted, alias=None):
    have = set(table_cols(con, table))
    return ", ".join((c if c in have else f"NULL AS {c}") for c in wanted)


EVENTS_DDL = """CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, session_id TEXT, turn_uuid TEXT, tool_call_id TEXT, ts TEXT,
  kind TEXT, subkind TEXT, detail TEXT, confidence TEXT, evidence TEXT, detector_version TEXT);
CREATE INDEX IF NOT EXISTS ix_events_kind ON events(kind, subkind);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS ix_events_turn ON events(turn_uuid);
CREATE INDEX IF NOT EXISTS ix_events_tool ON events(tool_call_id);"""


class Ev:
    __slots__ = ("session_id", "turn_uuid", "tool_call_id", "ts", "kind", "subkind", "detail", "confidence", "evidence")

    def __init__(self, session_id, turn_uuid, tool_call_id, ts, kind, subkind, detail, confidence, evidence):
        self.session_id, self.turn_uuid, self.tool_call_id, self.ts = session_id, turn_uuid, tool_call_id, ts
        self.kind, self.subkind = kind, subkind
        self.detail, self.confidence, self.evidence = clip(detail), confidence, clip(evidence)


BASH_NAMES = {"Bash", "bash", "shell", "local_shell", "exec_command"}


def bash_command(name, input_summary, input_json) -> str | None:
    """Full command string of a shell-ish tool call, else None."""
    if name == "Bash":
        return input_summary or ""
    if name in BASH_NAMES:
        try:
            j = json.loads(input_json) if input_json else {}
        except ValueError:
            j = {}
        c = j.get("command") or j.get("cmd")
        if isinstance(c, list):
            import shlex
            return shlex.join(str(x) for x in c)
        if isinstance(c, str):
            return c
        return input_summary or ""
    if name == "exec":  # Codex JS source with embedded tools.exec_command({cmd: "..."}) / write_stdin({chars})
        return codex_exec_commands(input_summary or "")
    return None


_JS_LIT = r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)"
_JS_KEY_LIT = re.compile(r"\b(?:cmd|chars)\s*:\s*" + _JS_LIT)
_JS_KEY_ARR = re.compile(r"\bcmd\s*:\s*\[([^\]]{0,4000})\]")
_JS_KEY_IDENT = re.compile(r"\b(cmd|chars)\s*:\s*([A-Za-z_$][\w$]*)\b(?!\s*[(.\[])|[{,]\s*(cmd)\s*(?=[,}])")


def _js_lit(lit: str) -> str:
    if lit[0] == '"':
        try:
            return json.loads(lit)
        except ValueError:
            return lit[1:-1]
    body = lit[1:-1]
    if lit[0] == "`":
        body = re.sub(r"\$\{[^}]*\}", "X", body)        # template holes: unknown at rest
    return body.replace("\\n", "\n").replace("\\'", "'").replace("\\`", "`")


def codex_exec_commands(src: str) -> str | None:
    """detect-1.1: shell commands inside a Codex `exec` (JS) call, treated like Bash. Handles
    cmd/chars literals, cmd arrays, and cmd passed as a variable or shorthand ({cmd, ...}) whose
    value is a const/let/var literal in the same source."""
    import shlex
    cmds = [_js_lit(m.group(1)) for m in _JS_KEY_LIT.finditer(src)]
    for m in _JS_KEY_ARR.finditer(src):
        parts = [_js_lit(x.group(1)) for x in re.finditer(_JS_LIT, m.group(1))]
        if parts:
            cmds.append(shlex.join(parts))
    for m in _JS_KEY_IDENT.finditer(src):
        ident = m.group(2) or m.group(3)
        d = re.search(r"\b(?:const|let|var)\s+" + re.escape(ident) + r"\s*=\s*" + _JS_LIT, src)
        if d:
            cmds.append(_js_lit(d.group(1)))
    return "\n".join(cmds) if cmds else None


def _track_file_write(files: dict, name, summ, ij, tid) -> None:
    """detect-1.2: keep the last known content of each written .py file (Write; Edit applied when the old text
    is found in the known content, else the file's state becomes unknown)."""
    if name not in ("Write", "Edit", "MultiEdit") or not (summ or "").endswith(".py"):
        return
    try:
        j = json.loads(ij) if ij else {}
    except ValueError:
        return
    p = j.get("file_path")
    if not isinstance(p, str) or not p.startswith("/"):
        return
    p = os.path.normpath(p)
    if name == "Write":
        c = j.get("content")
        files[p] = (c, tid) if isinstance(c, str) else None
        return
    cur = files.get(p)
    if cur is None:
        if p in files:
            return
        files[p] = None            # edited, but its content is not in the record
        return
    text = cur[0]
    edits = j.get("edits") if name == "MultiEdit" else [j]
    for e in edits or []:
        old, new = e.get("old_string"), e.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or "...[truncated" in old + new or old not in text:
            files[p] = None
            return
        text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
    files[p] = (text, tid)


# --------------------------------------------------------------------------- detectors
def detect_tool_calls(con) -> list[Ev]:
    evs: list[Ev] = []
    cols = ["id", "turn_uuid", "session_id", "ts", "name", "input_summary", "input_json", "result_excerpt",
            "is_error", "denied", "denied_kind"]
    forked = set()
    if "forked_copy" in table_cols(con, "turns"):
        forked = {u for (u,) in con.execute("SELECT uuid FROM turns WHERE forked_copy=1")}
    # detect-1.2: turn cwd (to resolve relative script paths) and the content of .py files written in the
    # record (Write, Edit applied to a known Write, `cat > f.py <<EOF`), keyed by absolute path, filesystem-wide
    # in ts order. Content is only parsed, never run.
    cwds = dict(con.execute("SELECT uuid, cwd FROM turns")) if "cwd" in table_cols(con, "turns") else {}
    files: dict[str, tuple[str, str] | None] = {}
    for r in con.execute(f"SELECT {sel(con, 'tool_calls', cols)} FROM tool_calls ORDER BY ts, rowid"):
        if r[1] in forked:
            continue
        (tid, turn, sid, ts, name, summ, ij, res, is_err, denied, dkind) = r
        _track_file_write(files, name, summ, ij, tid)
        # boundary_attempt: INPUT only, never result_excerpt
        cmd = bash_command(name, summ, ij)
        if cmd:
            cwd = cwds.get(turn)
            for p, body in shell_file_writes(cmd, cwd):
                if p.endswith(".py"):
                    files[p] = (body, tid)
            for sub, ev, via in scan_command_ex(cmd, files, cwd):
                det = f"via={via}; {cmd}" if via else cmd
                evs.append(Ev(sid, turn, tid, ts, "boundary_attempt", sub, det, "mechanical", ev))
        if name in ("send_message", "followup_task"):  # Codex agent-to-agent
            try:
                j = json.loads(ij) if ij else {}
            except ValueError:
                j = {}
            to = j.get("to") or j.get("target") or j.get("agent") or j.get("recipient") or "?"
            evs.append(Ev(sid, turn, tid, ts, "cross_chat_msg", "send", f"to {to}", "mechanical", summ or ""))
        if name == "SendMessage":
            try:
                j = json.loads(ij) if ij else {}
            except ValueError:
                j = {}
            evs.append(Ev(sid, turn, tid, ts, "cross_chat_msg", "send", f"to {j.get('to', '?')}", "mechanical", summ or ""))
        if name in ("Agent", "Task", "spawn_agent"):
            try:
                j = json.loads(ij) if ij else {}
            except ValueError:
                j = {}
            desc = j.get("description") or summ or ""
            st = j.get("subagent_type") or "general"
            evs.append(Ev(sid, turn, tid, ts, "subagent_launch", st, f"{desc} [{st}]", "mechanical", desc))
        # denial / stops: from the result side, that is what the record is
        res = res or ""
        is_stop = (dkind == "classifier-stop") or (bool(is_err) and bool(_STOP_TOOL.search(res[:400])))
        if is_stop:
            evs.append(Ev(sid, turn, tid, ts, "classifier_stop", "tool_interrupted", f"{name}: {res[:200]}", "mechanical", res[:200]))
            continue
        sub = None
        if denied and dkind in _DENIED_KIND_MAP:
            sub = _DENIED_KIND_MAP[dkind]
        if sub is None and (denied or is_err):
            for s, rx in _DENY_RULES:
                if rx.search(res[:600]):
                    sub = s
                    break
            if sub is None and denied:
                sub = "other"
        if sub == "permission_denied" and denied and dkind == "perm-reject":
            for s, rx in _DENY_RULES:  # perm-reject is generic: prefer the phrase when there is one
                if rx.search(res[:600]):
                    sub = s
                    break
        if sub:
            m = _REASON.search(res)
            extra = f" reason={m.group(1)}" if m else ""
            evs.append(Ev(sid, turn, tid, ts, "tool_denied", sub, f"{name}{extra}: {res[:160]}", "mechanical", res[:200]))
    return evs


def detect_turns(con) -> list[Ev]:
    evs: list[Ev] = []
    tcols = ["uuid", "session_id", "ts", "type", "role", "model", "requested_model", "is_sidechain", "text",
             "stop_reason", "is_compact_summary", "subtype", "is_meta", "origin_kind", "inherited", "forked_copy"]
    src = {}
    if "source" in table_cols(con, "sessions"):
        src = dict(con.execute("SELECT session_id, source FROM sessions"))
    last_model: dict[str, tuple[str, str]] = {}
    last_asst_text: dict[str, tuple[str, str, str]] = {}  # session -> (uuid, ts, text)
    last_compact: dict[str, str] = {}
    decision_prior: list[tuple[str, str, str, str]] = []
    pending_boundaries: list[tuple] = []
    q = f"SELECT {sel(con, 'turns', tcols)} FROM turns ORDER BY session_id, ts, rowid"
    for r in con.execute(q):
        (uuid, sid, ts, typ, role, model, rmodel, side, text, stop_reason, compact, subtype, is_meta,
         origin_kind, inherited, forked) = r
        n0, d0 = len(evs), len(decision_prior)
        text = text or ""
        side = bool(side)
        # ---- compaction
        if compact or typ == "summary":
            evs.append(Ev(sid, uuid, None, ts, "compaction", "summary", text[:200], "mechanical", text[:200]))
            last_compact[sid] = ts
        elif typ == "system" and (subtype == "compact_boundary" or text.startswith("Conversation compacted")):
            pending_boundaries.append((sid, uuid, ts))
        # ---- classifier stops
        if typ == "user" and _STOP_META.match(text):
            evs.append(Ev(sid, uuid, None, ts, "classifier_stop", "meta_notice", text[:200], "mechanical", text[:200]))
        if (stop_reason == "refusal" or (typ == "assistant" and model == "<synthetic>" and _STOP_API.search(text))
                or (typ == "system" and subtype == "model_refusal_no_fallback")):
            evs.append(Ev(sid, uuid, None, ts, "classifier_stop", "api_refusal", text[:200] or subtype or "refusal", "mechanical", text[:200] or "refusal"))
        # ---- inbound cross-chat notice
        if typ == "user" and not side and (text.startswith("Another Claude session sent")
                                           or text.lstrip().startswith(("<agent-message", "<cross-session-message"))):
            who = re.search(r'from(?:-name)?="([^"]{1,60})"', text)
            evs.append(Ev(sid, uuid, None, ts, "cross_chat_msg", "inbound", f"from {who.group(1) if who else '?'}", "mechanical", text[:200]))
        # ---- model swap (assistant, non-sidechain)
        if typ == "assistant" and role == "assistant" and not side and model and model != "<synthetic>":
            prev = last_model.get(sid)
            cur = (rmodel or "", model)
            if prev is not None:
                if prev[0] and cur[0] and prev[0] != cur[0]:
                    evs.append(Ev(sid, uuid, None, ts, "model_swap", "requested", f"requested {prev[0]} -> {cur[0]} (served {prev[1]} -> {cur[1]})", "mechanical", f"{prev[0]}->{cur[0]}"))
                elif prev[1] != cur[1]:
                    evs.append(Ev(sid, uuid, None, ts, "model_swap", "served", f"served {prev[1]} -> {cur[1]}", "mechanical", f"{prev[1]}->{cur[1]}"))
            last_model[sid] = cur
        # ---- human-turn heuristics
        if typ == "user" and role == "user" and not side:
            human = None
            if (src.get(sid, "claude") == "claude" and not compact and not is_meta and not inherited
                    and origin_kind in (None, "human")):
                human = human_text(text)
            if human:
                prior = last_asst_text.pop(sid, None)
                evs.extend(_human_events(sid, uuid, ts, human, prior, decision_prior))
        elif typ == "assistant" and role == "assistant" and not side and text.strip() and model != "<synthetic>":
            last_asst_text[sid] = (uuid, ts, text)
        if forked:  # copied prefix of a forked session: keep state, emit nothing (the original owns the events)
            del evs[n0:]
            del decision_prior[d0:]
    # compaction boundaries without a summary row nearby
    comp = [(e.session_id, _secs(e.ts)) for e in evs if e.kind == "compaction"]
    for sid, uuid, ts in pending_boundaries:
        if not any(s == sid and abs(t - _secs(ts)) < 120 for s, t in comp):
            evs.append(Ev(sid, uuid, None, ts, "compaction", "boundary", "Conversation compacted", "mechanical", "compact_boundary"))
    # concept_explained: assistant turn immediately before a user_decision
    for sid, a_uuid, a_ts, a_text, dec_uuid in decision_prior:
        c = classify_concept(a_text)
        if c:
            evs.append(Ev(sid, a_uuid, None, a_ts, "concept_explained", c[0], f"before decision {dec_uuid}: {c[1]}", "heuristic", c[1]))
    return evs


def _secs(ts: str | None) -> float:
    import datetime
    try:
        return datetime.datetime.fromisoformat((ts or "").replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _human_events(sid, uuid, ts, t, prior, decision_prior) -> list[Ev]:
    evs: list[Ev] = []
    p_uuid, p_ts, p_text = prior if prior else (None, None, "")
    ask = addressed_user(p_text)
    dec = classify_decision(t)
    corrs = classify_corrections(t)
    corr = corrs[0] if corrs else None
    if ask:
        if dec:
            evs.append(Ev(sid, uuid, None, ts, "user_decision", dec[0], f"[{dec[1]}] {t[:200]}", "heuristic", t[:200]))
        elif len(t) <= 80 and _CHOICE.search(t):
            evs.append(Ev(sid, uuid, None, ts, "user_decision", "other", f"[reply] {t[:200]}", "heuristic", t[:200]))
        if p_uuid:
            decision_prior.append((sid, p_uuid, p_ts, p_text, uuid))
    for c_sub, c_ev in corrs:   # detect-1.1: one event per matching subkind
        evs.append(Ev(sid, uuid, None, ts, "correction", c_sub, t[:200], "heuristic", c_ev))
    if p_text and _REC_RX.search(p_text) and ((dec and dec[0] == "refuse") or corr):
        m = _REC_RX.search(p_text)
        sub = "refuse" if (dec and dec[0] == "refuse") else "correction"
        evs.append(Ev(sid, uuid, None, ts, "overrule", sub,
                      f"rec: ...{p_text[max(0, m.start() - 40): m.end() + 120]}... | reply: {t[:120]}", "heuristic", t[:200]))
    return evs


def run(db: str, quiet: bool = False) -> dict:
    con = sqlite3.connect(db, timeout=120)
    con.executescript(EVENTS_DDL)
    PY_STATS.clear()
    PY_UNRESOLVED.clear()
    evs = detect_tool_calls(con) + detect_turns(con)
    evs.sort(key=lambda e: (e.ts or "", e.session_id or "", e.kind, e.subkind, e.turn_uuid or "", e.tool_call_id or ""))
    with con:
        # the events table holds ONE detector's output: older versions are replaced, so no reader
        # can double count across versions
        con.execute("DELETE FROM events")
        con.executemany(
            "INSERT INTO events(session_id, turn_uuid, tool_call_id, ts, kind, subkind, detail, confidence, evidence, detector_version)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(e.session_id, e.turn_uuid, e.tool_call_id, e.ts, e.kind, e.subkind, e.detail, e.confidence, e.evidence, DETECTOR_VERSION)
             for e in evs])
    counts = collections.Counter((e.kind, e.subkind) for e in evs)
    con.close()
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=False, default=None,
                    help="database path (default: $LEDGER_DIR/ledger.db, else ~/.local/share/agent-ledger/ledger.db)")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--stats", action="store_true", help="also print per-session counts")
    ap.add_argument("--per-session-tsv", help="write events per kind per session to this TSV")
    a = ap.parse_args(argv)
    if a.version:
        print(DETECTOR_VERSION)
        return 0
    if a.db is None:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import paths
        a.db = paths.default_db()
    if not os.path.exists(a.db):
        print(f"detect.py: no database at {a.db}; run ingest.py first", file=sys.stderr)
        return 2
    counts = run(a.db)
    per_kind = collections.Counter()
    for (k, s), n in counts.items():
        per_kind[k] += n
    print(f"detector_version {DETECTOR_VERSION}  db {a.db}")
    for k in sorted(per_kind):
        subs = ", ".join(f"{s}={n}" for (kk, s), n in sorted(counts.items()) if kk == k)
        print(f"{k:18s} {per_kind[k]:6d}  [{subs}]")
    if PY_STATS:   # detect-1.2: Python bodies parsed for shell-outs (unresolved = non-literal, not a hit)
        print("python bodies      " + ", ".join(f"{k}={v}" for k, v in sorted(PY_STATS.items())))
        if PY_UNRESOLVED:
            print("python unresolved  " + ", ".join(f"{k}={v}" for k, v in collections.Counter(
                f"{api} ({why})" for api, why in PY_UNRESOLVED).most_common(8)))
    if a.per_session_tsv:
        con = sqlite3.connect(f"file:{quote(a.db)}?mode=ro", uri=True)
        kinds = sorted(per_kind)
        with open(a.per_session_tsv, "w") as f:
            f.write("\t".join(["session_id", "source", "cwd", "thread_name"] + kinds) + "\n")
            for sid, src, cwd, name in con.execute("SELECT session_id, COALESCE(source,''), COALESCE(cwd,''), COALESCE(thread_name,'') FROM sessions ORDER BY first_ts"):
                cnt = dict(con.execute("SELECT kind, COUNT(*) FROM events WHERE session_id=? AND detector_version=? GROUP BY kind", (sid, DETECTOR_VERSION)))
                f.write("\t".join([sid, src, cwd, name.replace("\t", " ")] + [str(cnt.get(k, 0)) for k in kinds]) + "\n")
    if a.stats:
        con = sqlite3.connect(f"file:{quote(a.db)}?mode=ro", uri=True)
        print("\nper session (session_id, cwd, kind=count ...)")
        for sid, cwd, in con.execute("SELECT session_id, COALESCE(cwd,'') FROM sessions ORDER BY first_ts"):
            rows = con.execute("SELECT kind, COUNT(*) FROM events WHERE session_id=? AND detector_version=? GROUP BY kind", (sid, DETECTOR_VERSION)).fetchall()
            if rows:
                print(sid[:8], cwd[-40:], " ".join(f"{k}={n}" for k, n in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
