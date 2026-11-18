#!/usr/bin/env python3
"""agent-ledger ingest: load local AI coding-agent transcripts into one SQLite DB (with FTS5).

Stdlib only (sqlite3, json, re; the `zstd` binary for Codex rollouts). Incremental and idempotent:
Claude files are read from the saved byte offset, Codex .zst rollouts are re-decompressed and
the saved number of decompressed bytes skipped. See SCHEMA.md for the schema and mapping.

Reads ONLY the transcript roots (see paths.py; each can be overridden):
<claude-root>/**/*.jsonl (default ~/.claude/projects), <codex-root>/**/*.jsonl.zst (default
~/.codex/sessions), the Codex session index, and an optional --archive-root of extra .jsonl files.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import paths  # noqa: E402

HOME = paths.home()
CLAUDE_ROOT = paths.claude_root()
ARCHIVE_ROOT = paths.archive_root()      # None = no archive directory
CODEX_ROOT = paths.codex_root()
CODEX_INDEX = paths.codex_index()
ZSTD = shutil.which('zstd')         # needed only for Codex .jsonl.zst rollouts

SCHEMA_VERSION = '1'
BATCH = 1000
MAX_TEXT = 100_000        # cap on turns.text
MAX_CMD = 65_536          # cap on Bash command in input_summary
MAX_FIELD = 8192          # cap on any single string inside input_json
MAX_RESULT = 2048         # result_excerpt
SUMMARY_FALLBACK = 300

# ----------------------------------------------------------------------------- redaction

REDACTIONS = [
    ('privkey', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')),
    ('privkey', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$')),   # END cut off by truncation
    ('sk-ant', re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}')),
    ('sk', re.compile(r'(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}')),   # sk-proj-…; not task-/risk-
    ('aiza', re.compile(r'AIza[0-9A-Za-z_-]{35}')),                # Google API key
    ('jwt', re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ('github_pat', re.compile(r'github_pat_[A-Za-z0-9_]{30,}')),
    ('ghp', re.compile(r'ghp_[A-Za-z0-9]{30,}')),
    ('akia', re.compile(r'AKIA[0-9A-Z]{16}')),
    ('slack', re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}')),
    ('bearer', re.compile(r'(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}')),
    ('discord', re.compile(r'[MNO][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}')),   # O-prefixed tokens too
]
# .env-style whole lines (applied with env=True: .env paths and tool results)
ENV_LINE = re.compile(r'(?m)^([A-Z_]{4,})=(?!\[REDACTED)(\S{12,})$')
# Secret-named assignments, any case, optional `export`, applied to EVERY string (text, tool
# inputs incl. Write/Edit payloads, results), at line start or after ; & |. The name must contain a secret word, so `ROOT='/home/..'`
# style code is untouched. Values that are $VAR references or already redacted are left alone.
ENV_ASSIGN = re.compile(r'(?im)((?:^|(?<!\\)[;&|])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{2,})\s*=\s*[\'"]?)'
                        r'(?![\[$])([^\s\'"]{8,})')   # value never eats a quote: stored commands stay parseable
SECRET_WORDS = {'KEY', 'KEYS', 'APIKEY', 'TOKEN', 'TOKENS', 'SECRET', 'SECRETS', 'PASS', 'PASSWD', 'PASSWORD',
                'PASSWORDS', 'PASSPHRASE', 'PWD', 'CREDENTIAL', 'CREDENTIALS', 'CREDS', 'AUTH', 'BEARER',
                'COOKIE', 'COOKIES', 'PRIVATE'}
_NAME_SPLIT = re.compile(r'_+|(?<=[a-z0-9])(?=[A-Z])')


class _SecretName:
    """The secret word must be a whole component of the name (DB_PASSWORD, apiKey, export TOKEN), so
    `passed`, `author`, `cumulative_imported_passages` are not hits; the shell's PWD/OLDPWD are cwd paths."""
    @staticmethod
    def search(name):
        if name.upper() in ('PWD', 'OLDPWD'):
            return False
        return any(p.upper() in SECRET_WORDS for p in _NAME_SPLIT.split(name) if p)


NAME_CHECK = _SecretName()
# File names under the credential directories in a home directory (.aws, .config/gcloud, .ssh) are
# masked: they can name keys and credential files. .ssh keeps its ordinary, non-secret files and public keys.
SENSITIVE_PATH = re.compile(r'(?<![\w.])((?:(?:~|\$HOME|\$\{HOME\}|/home/[A-Za-z0-9_-]+|/Users/[A-Za-z0-9_.-]+)/)?'
                            r'(?:\.aws|\.config/gcloud|\.ssh)/)([A-Za-z0-9_.-][^\s\'"`;|&()<>,\]\\]*)')
SSH_OK = re.compile(r'^(?:config|authorized_keys|known_hosts|[\w.-]+\.pub)$')
SENSITIVE_DIR = re.compile(r'(?<![\w.])(?:~|\$HOME|\$\{HOME\}|/root|/home/[A-Za-z0-9_-]+|/Users/[A-Za-z0-9_.-]+)/'
                           r'(?:\.aws|\.config/gcloud|\.ssh)\b')
SENSITIVE_WITHHELD = '[result withheld: command touches a credential directory]'

RED_COUNTS = {}   # kind -> count (this run)


def _bump(kind):
    RED_COUNTS[kind] = RED_COUNTS.get(kind, 0) + 1


def redact(s, env=False):
    """Replace secrets with [REDACTED:<kind>]; env=True also masks KEY=value lines."""
    if not s:
        return s
    for kind, rx in REDACTIONS:
        if rx.search(s):
            s = rx.sub(lambda m, k=kind: (_bump(k), '[REDACTED:%s]' % k)[1], s)
    if '=' in s:
        def _a(m):
            if not NAME_CHECK.search(m.group(2)):
                return m.group(0)
            _bump('env_assign')
            return m.group(1) + '[REDACTED:env]'
        s = ENV_ASSIGN.sub(_a, s)
    if '.ssh/' in s or '.aws/' in s or '/gcloud/' in s:   # cheap pre-check; relative paths count too
        def _c(m):
            if m.group(1).endswith('.ssh/') and SSH_OK.match(m.group(2)):
                return m.group(0)
            _bump('sensitive_path')
            return m.group(1) + '[sensitive-path]'
        s = SENSITIVE_PATH.sub(_c, s)
    if env and '=' in s:
        def _e(m):
            _bump('env')
            return '%s=[REDACTED:env]' % m.group(1)
        s = ENV_LINE.sub(_e, s)
    return s


def red_cut(s, n, env=False, marker=True):
    """Redact then truncate to n chars (redact first so a token cannot be cut in half)."""
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    head = redact(s[:n + 1024], env)
    if len(s) > n + 1024 or len(head) > n:
        cut = head[:n]
        if marker:
            cut += '...[truncated %d chars]' % max(1, len(s) - n)
        return cut
    return head


def cut_bytes(s, n=MAX_RESULT):
    """result_excerpt is capped at n BYTES of UTF-8 (not chars); never splits a character."""
    if s is None:
        return None
    b = s.encode('utf-8')
    if len(b) <= n:
        return s
    return b[:n].decode('utf-8', 'ignore')


def red_json(obj, env=False):
    """Walk a JSON value: redact every string and truncate strings > MAX_FIELD."""
    if isinstance(obj, str):
        return red_cut(obj, MAX_FIELD, env)
    if isinstance(obj, list):
        return [red_json(x, env) for x in obj]
    if isinstance(obj, dict):
        return {k: red_json(v, env) for k, v in obj.items()}
    return obj


# ----------------------------------------------------------------------------- schema

DDL = """
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY, source TEXT, cwd TEXT, project_group TEXT, thread_name TEXT,
  file_path TEXT, archived INT, first_ts TEXT, last_ts TEXT, n_user INT, n_assistant INT, models TEXT,
  parent_session_id TEXT, thread_source TEXT, n_files INT, forked_from TEXT, n_copied INT);
CREATE TABLE IF NOT EXISTS turns(
  uuid TEXT PRIMARY KEY, session_id TEXT, parent_uuid TEXT, ts TEXT, type TEXT, role TEXT,
  model TEXT, requested_model TEXT, is_sidechain INT, agent_id TEXT, text TEXT, thinking_chars INT,
  input_tokens INT, output_tokens INT, cache_write_tokens INT, cache_read_tokens INT,
  stop_reason TEXT, cwd TEXT, git_branch TEXT, version TEXT, is_compact_summary INT, raw_keys TEXT,
  msg_id TEXT, request_id TEXT, subtype TEXT, thinking_tokens INT, cache_write_1h_tokens INT,
  effort TEXT, permission_mode TEXT, prompt_id TEXT, origin_kind TEXT, is_meta INT, forked_copy INT, orig_uuid TEXT);
CREATE TABLE IF NOT EXISTS tool_calls(
  id TEXT PRIMARY KEY, turn_uuid TEXT, session_id TEXT, ts TEXT, name TEXT, input_summary TEXT,
  input_json TEXT, result_excerpt TEXT, result_chars INT, is_error INT, denied INT,
  denied_kind TEXT, permission_decision TEXT);
CREATE TABLE IF NOT EXISTS ingest_files(
  path TEXT PRIMARY KEY, size INT, mtime REAL, byte_offset INT, lines INT, rows_turns INT,
  rows_tools INT, last_run TEXT, source TEXT, archived INT, dup_skipped INT);
CREATE TABLE IF NOT EXISTS ingest_type_counts(
  path TEXT, type TEXT, lines INT, rows_inserted INT, PRIMARY KEY(path, type));
CREATE TABLE IF NOT EXISTS redaction_counts(kind TEXT PRIMARY KEY, n INT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS turns_session_ts ON turns(session_id, ts);
CREATE INDEX IF NOT EXISTS turns_ts ON turns(ts);
CREATE INDEX IF NOT EXISTS turns_msg ON turns(msg_id);
CREATE INDEX IF NOT EXISTS turns_type ON turns(type);
CREATE INDEX IF NOT EXISTS tools_turn ON tool_calls(turn_uuid);
CREATE INDEX IF NOT EXISTS tools_session_ts ON tool_calls(session_id, ts);
CREATE INDEX IF NOT EXISTS tools_name ON tool_calls(name);
CREATE VIRTUAL TABLE IF NOT EXISTS turns_fts USING fts5(text, content='turns', content_rowid='rowid');
CREATE VIRTUAL TABLE IF NOT EXISTS tools_fts USING fts5(input_summary, result_excerpt, content='tool_calls', content_rowid='rowid');
CREATE TRIGGER IF NOT EXISTS turns_ai AFTER INSERT ON turns BEGIN
  INSERT INTO turns_fts(rowid, text) VALUES (new.rowid, new.text); END;
CREATE TRIGGER IF NOT EXISTS turns_ad AFTER DELETE ON turns BEGIN
  INSERT INTO turns_fts(turns_fts, rowid, text) VALUES ('delete', old.rowid, old.text); END;
CREATE TRIGGER IF NOT EXISTS turns_au AFTER UPDATE OF text ON turns BEGIN
  INSERT INTO turns_fts(turns_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
  INSERT INTO turns_fts(rowid, text) VALUES (new.rowid, new.text); END;
CREATE TRIGGER IF NOT EXISTS tools_ai AFTER INSERT ON tool_calls BEGIN
  INSERT INTO tools_fts(rowid, input_summary, result_excerpt) VALUES (new.rowid, new.input_summary, new.result_excerpt); END;
CREATE TRIGGER IF NOT EXISTS tools_ad AFTER DELETE ON tool_calls BEGIN
  INSERT INTO tools_fts(tools_fts, rowid, input_summary, result_excerpt) VALUES ('delete', old.rowid, old.input_summary, old.result_excerpt); END;
CREATE TRIGGER IF NOT EXISTS tools_au AFTER UPDATE OF input_summary, result_excerpt ON tool_calls BEGIN
  INSERT INTO tools_fts(tools_fts, rowid, input_summary, result_excerpt) VALUES ('delete', old.rowid, old.input_summary, old.result_excerpt);
  INSERT INTO tools_fts(rowid, input_summary, result_excerpt) VALUES (new.rowid, new.input_summary, new.result_excerpt); END;
CREATE VIEW IF NOT EXISTS v_api_messages AS SELECT * FROM turns WHERE output_tokens IS NOT NULL;
CREATE VIEW IF NOT EXISTS v_tool_denials AS
  SELECT c.id, c.ts, c.session_id, c.name, c.input_summary, c.denied_kind, c.permission_decision, c.result_excerpt
  FROM tool_calls c WHERE c.denied = 1;
"""

TURN_COLS = ['uuid', 'session_id', 'parent_uuid', 'ts', 'type', 'role', 'model', 'requested_model',
             'is_sidechain', 'agent_id', 'text', 'thinking_chars', 'input_tokens', 'output_tokens',
             'cache_write_tokens', 'cache_read_tokens', 'stop_reason', 'cwd', 'git_branch', 'version',
             'is_compact_summary', 'raw_keys', 'msg_id', 'request_id', 'subtype', 'thinking_tokens',
             'cache_write_1h_tokens', 'effort', 'permission_mode', 'prompt_id', 'origin_kind',
             'is_meta', 'forked_copy', 'orig_uuid']
TOOL_COLS = ['id', 'turn_uuid', 'session_id', 'ts', 'name', 'input_summary', 'input_json',
             'result_excerpt', 'result_chars', 'is_error', 'denied', 'denied_kind', 'permission_decision']
SQL_TURN = 'INSERT OR IGNORE INTO turns(%s) VALUES (%s)' % (','.join(TURN_COLS), ','.join('?' * len(TURN_COLS)))
SQL_TOOL = 'INSERT OR IGNORE INTO tool_calls(%s) VALUES (%s)' % (','.join(TOOL_COLS), ','.join('?' * len(TOOL_COLS)))
SQL_RESULT = ('UPDATE tool_calls SET result_excerpt=?, result_chars=?, is_error=?, denied=?, denied_kind=?, '
              'permission_decision=? WHERE id=? AND result_chars IS NULL')
SQL_NULL_TOK = ('UPDATE turns SET input_tokens=NULL, output_tokens=NULL, cache_write_tokens=NULL, '
                'cache_read_tokens=NULL, thinking_tokens=NULL, cache_write_1h_tokens=NULL WHERE uuid=?')

USAGE_COLS = ['input_tokens', 'output_tokens', 'cache_write_tokens', 'cache_read_tokens',
              'thinking_tokens', 'cache_write_1h_tokens']
SQL_SET_TOK = 'UPDATE turns SET %s WHERE uuid=?' % ', '.join('%s=?' % k for k in USAGE_COLS)


def claude_usage_vals(u):
    """Token columns from a Claude message.usage dict."""
    d = u.get('output_tokens_details') or {}
    cc = u.get('cache_creation') or {}
    return {'input_tokens': u.get('input_tokens'), 'output_tokens': u.get('output_tokens') or 0,
            'cache_write_tokens': u.get('cache_creation_input_tokens'),
            'cache_read_tokens': u.get('cache_read_input_tokens'),
            'thinking_tokens': d.get('thinking_tokens') if isinstance(d, dict) else None,
            'cache_write_1h_tokens': cc.get('ephemeral_1h_input_tokens') if isinstance(cc, dict) else None}


# Claude record types that are never stored as rows (counted only).
SKIP_TYPES = {'attachment', 'queue-operation', 'last-prompt', 'bridge-session', 'mode',
              'api-request-blob', 'api-request-shape', 'file-history-snapshot', 'file-history-delta',
              'atis-latch', 'cost-state', 'frame-link', 'artifact-autoreact-ledger',
              'artifact-comment-monitor'}
TYPE_PEEK = re.compile(rb'^\{"type":"([A-Za-z0-9_-]+)"')


def open_db(path):
    os.umask(0o077)
    new = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=60)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA temp_store=MEMORY')
    conn.executescript(DDL)
    conn.execute("INSERT OR REPLACE INTO meta VALUES('schema_version', ?)", (SCHEMA_VERSION,))
    conn.commit()
    os.chmod(path, 0o600)
    for ext in ('-wal', '-shm'):
        try:
            os.chmod(path + ext, 0o600)
        except OSError:
            pass
    return conn


# ----------------------------------------------------------------------------- helpers

def text_of(content):
    """Join the text of a tool_result `content` (str or list of blocks)."""
    if content is None:
        return ''
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict):
                t = b.get('type')
                if t == 'text' or 'text' in b:
                    out.append(str(b.get('text', '')))
                elif t == 'image':
                    out.append('[image]')
                else:
                    out.append('[%s]' % t)
            else:
                out.append(str(b))
        return '\n'.join(out)
    return str(content)


def summarize_input(name, inp):
    if isinstance(inp, dict):
        n = name or ''
        if n == 'Bash' and isinstance(inp.get('command'), str):
            return red_cut(inp['command'], MAX_CMD)
        if n in ('Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'):
            p = inp.get('file_path') or inp.get('notebook_path') or inp.get('path')
            if isinstance(p, str):
                return red_cut(p, 2000)
        if n in ('Glob', 'Grep') and isinstance(inp.get('pattern'), str):
            s = inp['pattern'] + ((' @ ' + inp['path']) if isinstance(inp.get('path'), str) else '')
            return red_cut(s, 2000)
        if n in ('Agent', 'Task') and isinstance(inp.get('description'), str):
            return red_cut(inp['description'], 2000)
    try:
        s = json.dumps(inp, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        s = str(inp)
    return red_cut(s[:SUMMARY_FALLBACK + 64], SUMMARY_FALLBACK, marker=False)


def is_env_path(inp):
    if not isinstance(inp, dict):
        return False
    p = inp.get('file_path') or inp.get('path') or ''
    return isinstance(p, str) and os.path.basename(p).startswith('.env')


DENY_TEXT = [
    ('user-rejected', "The user doesn't want to proceed with this tool use"),
    ('automode-blocked', 'denied by the Claude Code auto mode classifier'),
    ('permission-rule', 'denied by a built-in Claude Code safety check'),
    ('classifier-stop', 'stopped by a safety classifier'),
    ('classifier-error', 'auto mode classifier gave no verdict'),
    ('blocked-rule', '<tool_use_error>Blocked:'),
]
KIND_MAP = {'user-rejected': 'user-rejected', 'automode-blocked': 'automode-blocked',
            'permission-rule': 'permission-rule'}


def classify_denial(rec, is_error, rtext):
    """Return (denied, kind, permission_decision_json) for one tool_result of a user record."""
    pd = rec.get('permissionDecision')
    pdj = None
    if isinstance(pd, dict):
        pdj = json.dumps({k: pd[k] for k in ('decision', 'source', 'reasonType', 'reasonCode') if k in pd},
                         separators=(',', ':'))
    if not is_error:
        return 0, None, pdj
    kind = rec.get('toolDenialKind')
    head = rtext[:400]
    if kind in KIND_MAP:
        return 1, KIND_MAP[kind], pdj
    for k, phrase in DENY_TEXT:
        if phrase in head:
            return 1, k, pdj
    if isinstance(pd, dict) and pd.get('decision') == 'reject':
        return 1, 'perm-reject', pdj
    return 0, None, pdj


def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ----------------------------------------------------------------------------- ingest context

class Ctx:
    def __init__(self, conn):
        self.conn = conn
        self.known = {}
        self.fp = {}               # uuid -> (ts, type): tells a re-read from an id collision
        for uid, sid_, ts_, ty_ in conn.execute('SELECT uuid, session_id, ts, type FROM turns'):
            self.known[uid] = sid_
            self.fp[uid] = (ts_, ty_)
        self.owner = {}            # shared uuid -> owning session id (from fork_prepass)
        # msg_id -> (output_tokens, uuid) of the row currently holding the usage
        self.best = {r[0]: (r[2] or 0, r[1]) for r in conn.execute(
            'SELECT msg_id, uuid, output_tokens FROM turns WHERE msg_id IS NOT NULL AND output_tokens IS NOT NULL')}
        self.turn_buf = []
        self.tool_buf = []
        self.pending = {}          # tool id -> tool row (list) still in tool_buf
        self.result_upd = []
        self.null_tok = []
        self.touched = set()       # session ids touched this run
        self.totals = {'turns': 0, 'tools': 0, 'dups': 0, 'lines': 0}
        # per-file
        self.f_turns = self.f_tools = self.f_dups = 0
        self.type_lines = {}
        self.type_rows = {}
        self.titles = {}           # session_id -> ai-title
        self.usage_bumps = 0       # known rows whose usage was raised
        self.usage_bump_delta = 0  # output tokens added by those raises

    def flush(self):
        c = self.conn
        if self.turn_buf:
            c.executemany(SQL_TURN, self.turn_buf)
            self.turn_buf = []
        if self.tool_buf:
            c.executemany(SQL_TOOL, self.tool_buf)
            self.tool_buf = []
            self.pending = {}
        if self.result_upd:
            c.executemany(SQL_RESULT, self.result_upd)
            self.result_upd = []
        if self.null_tok:
            c.executemany(SQL_NULL_TOK, [(u,) for u in self.null_tok])
            self.null_tok = []

    def maybe_flush(self):
        if len(self.turn_buf) >= BATCH or len(self.tool_buf) >= BATCH:
            self.flush()

    def add_turn(self, row, rtype):
        self.turn_buf.append(row)
        self.known[row[0]] = row[1]
        self.fp[row[0]] = (row[3], row[4])
        self.f_turns += 1
        self.type_rows[rtype] = self.type_rows.get(rtype, 0) + 1
        self.touched.add(row[1])

    def add_tool(self, row):
        self.tool_buf.append(row)
        self.pending[row[0]] = row
        self.f_tools += 1

    def set_result(self, tool_id, excerpt, chars, is_err, denied, kind, pdj):
        row = self.pending.get(tool_id)
        if row is not None:
            row[7], row[8], row[9], row[10], row[11], row[12] = excerpt, chars, is_err, denied, kind, pdj
        else:
            self.result_upd.append((excerpt, chars, is_err, denied, kind, pdj, tool_id))

    def bump_usage(self, msg_id, uuid, vals):
        """A row that is ALREADY stored (known uuid) is seen again carrying usage.
        If its output_tokens beat the current holder of msg_id, move/raise the usage onto it
        (keep the max; exactly one usage row per msg_id). Returns True if the DB changed."""
        out = vals['output_tokens'] or 0
        cur = self.best.get(msg_id)
        if cur is not None and out <= cur[0]:
            return False
        self.flush()              # the stored row may still sit in turn_buf / null_tok
        if cur is not None and cur[1] != uuid:
            self.conn.execute(SQL_NULL_TOK, (cur[1],))
        self.conn.execute(SQL_SET_TOK, [vals[k] for k in USAGE_COLS] + [uuid])
        self.best[msg_id] = (out, uuid)
        self.usage_bumps += 1
        self.usage_bump_delta += out - (cur[0] if cur is not None else 0)
        return True

    def usage_row(self, msg_id, uuid, out_tokens):
        """Decide whether this row holds the usage for msg_id. Returns True if it should."""
        cur = self.best.get(msg_id)
        if cur is None:
            self.best[msg_id] = (out_tokens, uuid)
            return True
        if out_tokens > cur[0]:
            self.null_tok.append(cur[1])
            self.best[msg_id] = (out_tokens, uuid)
            return True
        return False


def blank_turn():
    return dict.fromkeys(TURN_COLS)


def row_of(d):
    return [d[c] for c in TURN_COLS]


# ----------------------------------------------------------------------------- Claude

def handle_claude_record(ctx, r, t, fileinfo, line_pos, last_ts):
    """Process one parsed Claude record of type t. Returns the ts to carry forward."""
    sid = r.get('sessionId') or r.get('session_id') or fileinfo['sid']
    agent = r.get('agentId') or fileinfo['agent_id']
    ts = r.get('timestamp') or last_ts
    keys = json.dumps(list(r.keys()), separators=(',', ':'))

    if t == 'ai-title':
        if r.get('aiTitle'):
            ctx.titles[sid] = r['aiTitle']
        return last_ts

    d = blank_turn()
    d.update(session_id=sid, ts=ts, type=t, is_sidechain=1 if r.get('isSidechain') else 0,
             agent_id=agent, cwd=r.get('cwd'), git_branch=r.get('gitBranch'), version=r.get('version'),
             raw_keys=keys, parent_uuid=r.get('parentUuid'), is_meta=1 if r.get('isMeta') else 0,
             prompt_id=r.get('promptId'))

    if t == 'permission-mode':
        d['uuid'] = 'pm:' + hashlib.sha1(('%s|%d' % (fileinfo['path'], line_pos)).encode()).hexdigest()[:24]
        d['permission_mode'] = r.get('permissionMode')
        d['is_sidechain'] = 1 if agent else 0
    elif t == 'api-request':
        d['uuid'] = r.get('id')
        p = r.get('params') or {}
        d['model'] = p.get('model')
        d['subtype'] = r.get('querySource')
        d['request_id'] = r.get('id')
        oc = p.get('output_config') or {}
        d['effort'] = oc.get('effort') if isinstance(oc, dict) else None
        d['is_sidechain'] = 1 if agent else 0
    elif t == 'system':
        d['uuid'] = r.get('uuid')
        d['subtype'] = r.get('subtype')
        d['requested_model'] = r.get('originalModel')
        d['request_id'] = r.get('requestId')
    elif t == 'summary':
        d['uuid'] = r.get('uuid') or 'summary:' + str(r.get('leafUuid') or hashlib.sha1(
            ('%s|%d' % (fileinfo['path'], line_pos)).encode()).hexdigest()[:24])
        d['text'] = red_cut(r.get('summary'), MAX_TEXT)
    elif t in ('user', 'assistant'):
        d['uuid'] = r.get('uuid')
    else:
        return last_ts  # unknown record type: counted only
    if not d['uuid']:
        return last_ts
    copy = False
    ow = ctx.owner.get(d['uuid'])
    if (ow is not None and ow != sid) or (d['uuid'] in ctx.known and ctx.known[d['uuid']] != sid):
        # same uuid held by another session (fork-session copy): keep as a flagged copy, never reuse the PK
        copy = True
        d['orig_uuid'] = d['uuid']
        d['uuid'] = '%s@%s' % (d['orig_uuid'], sid)
        d['forked_copy'] = 1
    else:
        d['forked_copy'] = 0
    if d['uuid'] in ctx.known:
        ctx.f_dups += 1
        if t == 'assistant' and not copy:
            # a re-seen record may carry a later, larger usage for the same message
            msg = r.get('message') or {}
            u = msg.get('usage') if isinstance(msg, dict) else None
            if msg.get('id') and u:
                ctx.bump_usage(msg['id'], d['uuid'], claude_usage_vals(u))
        return r.get('timestamp') or last_ts
    if t in ('permission-mode', 'api-request') and not d['agent_id']:
        d['is_sidechain'] = 0

    if t == 'user':
        msg = r.get('message') or {}
        d['role'] = msg.get('role', 'user')
        content = msg.get('content')
        parts = []
        results = []
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for b in content:
                if not isinstance(b, dict):
                    continue
                bt = b.get('type')
                if bt == 'text':
                    parts.append(str(b.get('text', '')))
                elif bt == 'tool_result':
                    parts.append('[tool_result]')
                    results.append(b)
                elif bt == 'image':
                    parts.append('[image]')
                else:
                    parts.append('[%s]' % bt)
        d['text'] = red_cut('\n'.join(parts), MAX_TEXT) if parts else None
        d['is_compact_summary'] = 1 if r.get('isCompactSummary') else 0
        d['permission_mode'] = r.get('permissionMode')
        o = r.get('origin')
        d['origin_kind'] = o.get('kind') if isinstance(o, dict) else None
        for b in ([] if copy else results):
            rt = text_of(b.get('content'))
            is_err = 1 if b.get('is_error') else 0
            denied, kind, pdj = classify_denial(r, is_err, rt)
            ctx.set_result(b.get('tool_use_id'), cut_bytes(red_cut(rt, MAX_RESULT, env=True, marker=False)),
                           len(rt), is_err, denied, kind, pdj)
    elif t == 'assistant':
        msg = r.get('message') or {}
        d['role'] = msg.get('role', 'assistant')
        d['model'] = msg.get('model')
        d['requested_model'] = r.get('requestedModel')
        d['msg_id'] = msg.get('id')
        d['request_id'] = r.get('requestId')
        d['stop_reason'] = msg.get('stop_reason')
        d['effort'] = r.get('effort')
        content = msg.get('content')
        parts = []
        think = 0
        tools = []
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for b in content:
                if not isinstance(b, dict):
                    continue
                bt = b.get('type')
                if bt == 'text':
                    parts.append(str(b.get('text', '')))
                elif bt == 'thinking':
                    think += len(b.get('thinking') or '')
                elif bt == 'tool_use':
                    tools.append(b)
        d['text'] = red_cut('\n'.join(parts), MAX_TEXT) if parts else None
        d['thinking_chars'] = think
        u = msg.get('usage') or {}
        if d['msg_id'] and u and not copy:
            vals = claude_usage_vals(u)
            if ctx.usage_row(d['msg_id'], d['uuid'], vals['output_tokens']):
                d.update(vals)
        for b in ([] if copy else tools):
            inp = b.get('input')
            nm = b.get('name')
            env = is_env_path(inp)
            summ = summarize_input(nm, inp)
            if env:
                summ = redact(summ, env=True)
            ij = json.dumps(red_json(inp, env), ensure_ascii=False, separators=(',', ':'))
            ctx.add_tool([b.get('id'), d['uuid'], sid, ts, nm, summ, ij, None, None, None, 0, None, None])
    ctx.add_turn(row_of(d), t)
    return ts


def process_claude_file(ctx, path, group, archived, fileinfo, offset):
    """Stream the file from offset. Returns (new_offset, lines)."""
    lines = 0
    pos = offset
    last_ts = None
    with open(path, 'rb') as f:
        f.seek(offset)
        while True:
            line = f.readline()
            if not line:
                break
            complete = line.endswith(b'\n')
            line_pos = pos
            stripped = line.strip()
            if not stripped:
                pos += len(line)
                lines += 1
                continue
            m = TYPE_PEEK.match(stripped)
            t = m.group(1).decode() if m else None
            skip_t = t if t in SKIP_TYPES else (
                'attachment' if t is None and stripped.startswith(b'{"parentUuid"') and
                stripped[:300].find(b',"attachment":{') > 0 else None)
            if skip_t and not complete:
                # a half-written trailing line of a skipped type must not be consumed either
                try:
                    json.loads(stripped.decode('utf-8', 'replace'))
                except ValueError:
                    break
            if t in SKIP_TYPES:
                pos += len(line)
                lines += 1
                ctx.type_lines[t] = ctx.type_lines.get(t, 0) + 1
                continue
            if skip_t == 'attachment':
                pos += len(line)
                lines += 1
                ctx.type_lines['attachment'] = ctx.type_lines.get('attachment', 0) + 1
                continue
            try:
                r = json.loads(stripped.decode('utf-8', 'replace'))
            except ValueError:
                if not complete:
                    break          # partial trailing line: leave for the next run
                pos += len(line)
                lines += 1
                ctx.type_lines['_bad'] = ctx.type_lines.get('_bad', 0) + 1
                continue
            pos += len(line)
            lines += 1
            if not isinstance(r, dict):
                ctx.type_lines['_nonobj'] = ctx.type_lines.get('_nonobj', 0) + 1
                continue
            rt = r.get('type')
            ctx.type_lines[rt] = ctx.type_lines.get(rt, 0) + 1
            if rt in SKIP_TYPES:
                continue
            last_ts = handle_claude_record(ctx, r, rt, fileinfo, line_pos, last_ts)
            ctx.maybe_flush()
    return pos, lines


# ----------------------------------------------------------------------------- Codex

def codex_text(content):
    out = []
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and b.get('type') in ('input_text', 'output_text', 'text'):
                out.append(str(b.get('text', '')))
    elif isinstance(content, str):
        out.append(content)
    return '\n'.join(out)


EXIT_RX = re.compile(r'"exit_code":\s*(-?\d+)')


def cx_resolve(ctx, uuid, ts, typ, path):
    """Codex ids are <thread>:<ordinal>, and a resumed rollout of the same thread can reuse an
    ordinal for a different record. Returns the uuid to store under, or None for a true re-read
    (same ts and type already stored). A collision gets '<thread>:<ordinal>@<file tag>'."""
    fp = ctx.fp.get(uuid)
    if fp is None:
        return uuid
    if fp == (ts, typ):
        return None
    alt = '%s@%s' % (uuid, hashlib.sha1(os.path.basename(path).encode()).hexdigest()[:8])
    return None if alt in ctx.fp else alt


def process_codex_file(ctx, path, fileinfo, offset):
    """Stream a .jsonl.zst rollout; skip `offset` decompressed bytes. Returns (new_offset, lines, meta)."""
    proc = subprocess.Popen([ZSTD, '-dc', '-q', path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    skipped = 0
    while skipped < offset:
        chunk = proc.stdout.read(min(1 << 20, offset - skipped))
        if not chunk:
            break
        skipped += len(chunk)
    tid = fileinfo['sid']
    st = {'cwd': None, 'model': None, 'effort': None, 'meta': None}
    if offset:
        # resuming a grown rollout: restore the state established by the part we already read
        saved = ctx.conn.execute('SELECT v FROM meta WHERE k=?', ('cxstate:' + path,)).fetchone()
        if saved:
            sv = json.loads(saved[0])
            tid = sv.get('tid') or tid
            fileinfo['sid'] = tid
            st.update(cwd=sv.get('cwd'), model=sv.get('model'), effort=sv.get('effort'))
    pos = offset
    lines = 0
    for line in proc.stdout:
        if not line.endswith(b'\n'):
            try:
                json.loads(line)
            except ValueError:
                break
        pos += len(line)
        lines += 1
        stripped = line.strip()
        if not stripped:
            continue
        try:
            r = json.loads(stripped.decode('utf-8', 'replace'))
        except ValueError:
            ctx.type_lines['_bad'] = ctx.type_lines.get('_bad', 0) + 1
            continue
        rt = r.get('type')
        pl = r.get('payload') if isinstance(r.get('payload'), dict) else {}
        pt = pl.get('type')
        label = rt if not pt else '%s/%s' % (rt, pt)
        ctx.type_lines[label] = ctx.type_lines.get(label, 0) + 1
        ts = r.get('timestamp')
        ordinal = r.get('ordinal')
        uuid = '%s:%s' % (tid, ordinal if ordinal is not None else pos)
        inherited = 1 if (r.get('metadata') or {}).get('inherited_user_message') else 0

        if rt == 'session_meta':
            if st['meta'] is None:
                st['meta'] = pl
                tid = pl.get('id') or tid
                fileinfo['sid'] = tid
                st['cwd'] = pl.get('cwd')
            continue
        if rt == 'turn_context':
            st['model'] = pl.get('model') or st['model']
            st['cwd'] = pl.get('cwd') or st['cwd']
            st['effort'] = pl.get('effort') or st['effort']
            continue
        if rt == 'event_msg' and pt == 'thread_settings_applied':
            ts_ = pl.get('thread_settings') or {}
            st['model'] = ts_.get('model') or st['model']
            st['effort'] = ts_.get('reasoning_effort') or st['effort']
            continue

        d = blank_turn()
        d.update(uuid=uuid, session_id=tid, ts=ts, is_sidechain=0, cwd=st['cwd'], model=st['model'],
                 effort=st['effort'], forked_copy=inherited,
                 raw_keys=json.dumps(list(r.keys()), separators=(',', ':')))
        kind = None
        tool_row = None
        if rt == 'response_item' and pt == 'message':
            role = pl.get('role')
            d['type'] = role if role in ('user', 'assistant') else 'developer'
            d['role'] = role
            d['msg_id'] = None
            d['subtype'] = pl.get('phase')
            if role in ('user', 'assistant'):
                txt = codex_text(pl.get('content'))
                d['text'] = red_cut(txt, MAX_TEXT) if txt else None
            kind = 'turn'
        elif rt == 'response_item' and pt == 'agent_message':
            d['type'] = 'agent_message'
            txt = codex_text(pl.get('content'))
            pre = '[%s -> %s] ' % (pl.get('author'), pl.get('recipient'))
            d['text'] = red_cut(pre + txt, MAX_TEXT)
            kind = 'turn'
        elif rt == 'response_item' and pt in ('function_call', 'custom_tool_call'):
            d['type'] = 'tool_call'
            d['role'] = 'assistant'
            d['subtype'] = pt
            cid = pl.get('call_id')
            nm = pl.get('name')
            if pt == 'custom_tool_call':
                raw = pl.get('input')
                summ = red_cut(raw if isinstance(raw, str) else json.dumps(raw), MAX_CMD)
                ij = json.dumps(red_json({'input': raw}), ensure_ascii=False, separators=(',', ':'))
            else:
                raw = pl.get('arguments')
                try:
                    obj = json.loads(raw) if isinstance(raw, str) else raw
                except ValueError:
                    obj = {'arguments': raw}
                summ = summarize_input(nm, obj)
                ij = json.dumps(red_json(obj), ensure_ascii=False, separators=(',', ':'))
            tool_row = [cid, uuid, tid, ts, nm, summ, ij, None, None, None, 0, None, None]
            kind = 'turn'
        elif rt == 'response_item' and pt in ('function_call_output', 'custom_tool_call_output'):
            out = pl.get('output')
            rtxt = text_of(out)
            is_err = 1 if any(int(x) != 0 for x in EXIT_RX.findall(rtxt[:200000])) else 0
            ctx.set_result(pl.get('call_id'), cut_bytes(red_cut(rtxt, MAX_RESULT, env=True, marker=False)),
                           len(rtxt), is_err, 0, None, None)
            continue
        elif rt == 'response_item' and pt == 'compaction' or rt == 'compacted':
            d['type'] = 'compaction'
            d['is_compact_summary'] = 1
            kind = 'turn'
        elif rt == 'token_usage_record':
            rid = pl.get('response_id')
            d['type'] = 'token_usage'
            d['msg_id'] = rid
            u = pl.get('usage') or {}
            out_t = u.get('output_tokens') or 0
            cached = u.get('cached_input_tokens') or 0
            in_t = max((u.get('input_tokens') or 0) - cached, 0)
            cvals = {'input_tokens': in_t, 'output_tokens': out_t,
                     'cache_read_tokens': cached, 'cache_write_tokens': u.get('cache_write_input_tokens') or 0,
                     'thinking_tokens': u.get('reasoning_output_tokens'), 'cache_write_1h_tokens': None}
            nu = cx_resolve(ctx, uuid, ts, 'token_usage', path)
            if nu is None:
                # a stored record re-read; raise its usage if larger, never null it
                ctx.f_dups += 1
                if rid:
                    ctx.bump_usage(rid, uuid, cvals)
                continue
            uuid = d['uuid'] = nu
            if rid and not ctx.usage_row(rid, uuid, out_t):
                continue
            d.update(cvals)
            kind = 'turn'
        elif rt == 'event_msg' and pt in ('task_started', 'task_complete', 'turn_aborted'):
            d['type'] = pt
            ta = pl.get('turn_attribution') or {}
            d['subtype'] = ta.get('turn_trigger') if isinstance(ta, dict) else None
            d['parent_uuid'] = pl.get('turn_id')
            kind = 'turn'
        if kind == 'turn':
            nu = cx_resolve(ctx, uuid, ts, d['type'], path)
            if nu is None:
                ctx.f_dups += 1
                continue
            uuid = d['uuid'] = nu
            if tool_row is not None:
                tool_row[1] = uuid
                ctx.add_tool(tool_row)
            if d['forked_copy'] is None:
                d['forked_copy'] = 0
            ctx.add_turn(row_of(d), label)
            ctx.maybe_flush()
    proc.stdout.close()
    proc.wait()
    ctx.conn.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', ('cxstate:' + path, json.dumps(
        {'tid': tid, 'cwd': st['cwd'], 'model': st['model'], 'effort': st['effort']})))
    return pos, lines, st['meta'], proc.returncode



# ----------------------------------------------------------------------------- fork detection

STORED_TYPES = (b'{"parentUuid"', b'{"type":"api-request"', b'{"type":"summary"')


def _uuid_of(r):
    if not isinstance(r, dict):
        return None
    t = r.get('type')
    if t in SKIP_TYPES or t in ('api-request-blob', 'api-request-shape'):
        return None
    return r.get('uuid') or (r.get('id') if t == 'api-request' else None)


def _iter_uuid_records(path, limit=None):
    """Yield (uuid, sessionId, ts) for stored-type records of a Claude file."""
    n = 0
    with open(path, 'rb') as f:
        for line in f:
            if not line.startswith(STORED_TYPES):
                continue
            if line[:300].find(b',"attachment":{') > 0:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            u = _uuid_of(r)
            if u:
                yield u, r.get('sessionId'), r.get('timestamp')
                n += 1
                if limit and n >= limit:
                    return


def fork_prepass(files):
    """Find uuids that live in more than one session (--fork-session copies, or an
    archived copy of part of another session's file) and pick each one's owner.

    Full scan of the stored-type records of every Claude file (lines of skipped types are not parsed).
    Owner of a shared uuid = the holder session with the earliest 'native' record, where a native record is one
    held by that session alone (a fork's copied prefix is older than the fork itself, so the parent wins);
    sessions with no native record never own anything; ties break on session id.
    Returns {uuid: owner_session_id} for uuids held by more than one session."""
    holders = {}                 # uuid -> sid, or set(sid) when shared
    ts_of = {}
    for o in files:
        if o['source'] != 'claude':
            continue
        for u, sid, ts in _iter_uuid_records(o['path']):
            sid = sid or o['sid']
            cur = holders.get(u)
            if cur is None:
                holders[u] = sid
                ts_of[u] = ts or ''
            elif isinstance(cur, set):
                cur.add(sid)
            elif cur != sid:
                holders[u] = {cur, sid}
    native = {}
    shared = {}
    for u, h in holders.items():
        if isinstance(h, set):
            shared[u] = h
        else:
            t = ts_of[u]
            if t and (h not in native or t < native[h]):
                native[h] = t
    return {u: min(h, key=lambda x: (native.get(x, '9999'), x)) for u, h in shared.items()}


# ----------------------------------------------------------------------------- driver

def discover():
    """All source files: list of dicts. Order: live main, live subagent, archived."""
    out = []
    for dp, dn, fn in os.walk(CLAUDE_ROOT):
        for n in fn:
            if not n.endswith('.jsonl'):
                continue
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, CLAUDE_ROOT).split(os.sep)
            group = rel[0]
            sub = 'subagents' in rel
            if sub:
                sid = rel[1]
                agent = n[:-6][len('agent-'):] if n.startswith('agent-') else n[:-6]
            else:
                sid = n[:-6]
                agent = None
            out.append(dict(path=p, source='claude', group=group, archived=0, sub=sub, sid=sid, agent_id=agent))
    for dp, dn, fn in (os.walk(ARCHIVE_ROOT) if ARCHIVE_ROOT else ()):
        for n in fn:
            if n.endswith('.jsonl'):
                p = os.path.join(dp, n)
                m = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$', n)
                out.append(dict(path=p, source='claude', group='archive', archived=1, sub=False,
                                sid=m.group(1) if m else n[:-6], agent_id=None))
    for dp, dn, fn in os.walk(CODEX_ROOT):
        for n in fn:
            if n.endswith('.jsonl.zst'):
                p = os.path.join(dp, n)
                m = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl\.zst$', n)
                out.append(dict(path=p, source='codex', group='codex', archived=0, sub=False,
                                sid=m.group(1) if m else n, agent_id=None))
    for o in out:
        o['rank'] = (1 if o['source'] == 'codex' else 0, o['archived'], 1 if o['sub'] else 0, o['path'])
    out.sort(key=lambda o: o['rank'])
    return out


def load_codex_index():
    names = {}
    try:
        with open(CODEX_INDEX, 'rb') as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get('id') and r.get('thread_name'):
                    if r['id'] not in names or (r.get('updated_at') or '') >= names[r['id']][1]:
                        names[r['id']] = (r['thread_name'], r.get('updated_at') or '')
    except OSError:
        pass
    return {k: v[0] for k, v in names.items()}


def refresh_sessions(ctx, files_by_sid, cx_names, cx_meta):
    """Upsert sessions rows for the sessions touched in this run and recompute aggregates."""
    c = ctx.conn
    for sid in sorted(ctx.touched):
        info = files_by_sid.get(sid)
        row = c.execute('SELECT 1 FROM sessions WHERE session_id=?', (sid,)).fetchone()
        first = c.execute('SELECT cwd FROM turns WHERE session_id=? AND cwd IS NOT NULL ORDER BY ts LIMIT 1',
                          (sid,)).fetchone()
        if row is None:
            meta = cx_meta.get(sid) or {}
            c.execute('INSERT INTO sessions(session_id, source, cwd, project_group, file_path, archived, '
                      'parent_session_id, thread_source) VALUES (?,?,?,?,?,?,?,?)',
                      (sid, info['source'] if info else 'claude', first[0] if first else None,
                       info['group'] if info else None, info['path'] if info else None,
                       info['archived'] if info else 0, meta.get('parent_thread_id'), meta.get('thread_source')))
        elif info and not info['archived']:
            c.execute('UPDATE sessions SET archived=0, file_path=?, project_group=? WHERE session_id=? AND archived=1',
                      (info['path'], info['group'], sid))
        a = c.execute("SELECT min(ts), max(ts), sum(type='user'), sum(type='assistant') FROM turns "
                      "WHERE session_id=? AND COALESCE(forked_copy,0)=0", (sid,)).fetchone()
        if a[0] is None:
            a = c.execute("SELECT min(ts), max(ts), 0, 0 FROM turns WHERE session_id=?", (sid,)).fetchone()
        ncop = c.execute('SELECT count(*) FROM turns WHERE session_id=? AND forked_copy=1', (sid,)).fetchone()[0]
        ff = c.execute('SELECT o.session_id FROM turns c JOIN turns o ON o.uuid=c.orig_uuid '
                       'WHERE c.session_id=? AND c.forked_copy=1 ORDER BY c.ts DESC LIMIT 1', (sid,)).fetchone()
        c.execute('UPDATE sessions SET n_copied=?, forked_from=COALESCE(?, forked_from) WHERE session_id=?',
                  (ncop, ff[0] if ff else None, sid))
        models = [r[0] for r in c.execute('SELECT DISTINCT model FROM turns WHERE session_id=? AND model IS NOT NULL '
                                          'ORDER BY model', (sid,))]
        c.execute('UPDATE sessions SET first_ts=?, last_ts=?, n_user=?, n_assistant=?, models=?, '
                  'cwd=COALESCE(cwd, ?) WHERE session_id=?',
                  (a[0], a[1], a[2] or 0, a[3] or 0, json.dumps(models), first[0] if first else None, sid))
        if sid in ctx.titles:
            c.execute('UPDATE sessions SET thread_name=? WHERE session_id=?', (ctx.titles[sid], sid))
        elif sid in cx_names:
            c.execute('UPDATE sessions SET thread_name=? WHERE session_id=?', (cx_names[sid], sid))
    # n_files: every ingested file whose path contains the session id (main, subagents/, archived copy)
    for sid in ctx.touched:
        n = c.execute('SELECT count(*) FROM ingest_files WHERE instr(path, ?) > 0', (sid,)).fetchone()[0]
        c.execute('UPDATE sessions SET n_files=? WHERE session_id=?', (n or 1, sid))


def _scrub_json(obj, env):
    if isinstance(obj, str):
        return redact(obj, env)
    if isinstance(obj, list):
        return [_scrub_json(x, env) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_json(v, env) for k, v in obj.items()}
    return obj


def withhold_sensitive_results(conn):
    """A result of a command that names a credential directory (`ls` of .ssh, `cat` of a file in .aws) can list
    or print credential files, so the excerpt is withheld. Returns rows changed."""
    n = 0
    rows = conn.execute("SELECT rowid, input_summary FROM tool_calls WHERE result_excerpt IS NOT NULL AND "
                        "result_excerpt != ? AND (input_summary LIKE '%.ssh%' OR input_summary LIKE '%.aws%' "
                        "OR input_summary LIKE '%gcloud%')", (SENSITIVE_WITHHELD,)).fetchall()
    for rid, summ in rows:
        if summ and (SENSITIVE_DIR.search(summ) or '[sensitive-path]' in summ):
            conn.execute('UPDATE tool_calls SET result_excerpt=? WHERE rowid=?', (SENSITIVE_WITHHELD, rid))
            n += 1
    return n


def rescrub(db_path, verbose=True):
    """Re-apply the CURRENT redaction patterns in place to every stored text column (turns.text,
    tool_calls.input_summary / input_json / result_excerpt), enforce the result byte cap, withhold
    credential-directory results, then rebuild both FTS indexes. Prints counters per pattern, no values."""
    t0 = time.time()
    conn = open_db(db_path)
    RED_COUNTS.clear()
    changed = {'turns.text': 0, 'tool_calls.input_summary': 0, 'tool_calls.input_json': 0,
               'tool_calls.result_excerpt': 0, 'result_bytecap': 0}
    conn.execute('DROP TRIGGER IF EXISTS turns_au')
    conn.execute('DROP TRIGGER IF EXISTS tools_au')    # FTS is rebuilt once at the end instead
    upd = []
    for rid, txt in conn.execute('SELECT rowid, text FROM turns WHERE text IS NOT NULL'):
        new = redact(txt)
        if new != txt:
            upd.append((new, rid))
    conn.executemany('UPDATE turns SET text=? WHERE rowid=?', upd)
    changed['turns.text'] = len(upd)
    upd = []
    for rid, summ, ij, res, name in conn.execute(
            'SELECT rowid, input_summary, input_json, result_excerpt, name FROM tool_calls'):
        try:
            inp = json.loads(ij) if ij else None
        except ValueError:
            inp = None
        env = is_env_path(inp)
        n_summ = redact(summ, env)
        n_ij = ij
        if inp is not None:
            new_inp = _scrub_json(inp, env)
            if new_inp != inp:
                n_ij = json.dumps(new_inp, ensure_ascii=False, separators=(',', ':'))
        elif ij:
            n_ij = redact(ij, env)
        n_res = redact(res, env=True)
        capped = cut_bytes(n_res)
        if capped != n_res:
            changed['result_bytecap'] += 1
        n_res = capped
        if (n_summ, n_ij, n_res) != (summ, ij, res):
            changed['tool_calls.input_summary'] += n_summ != summ
            changed['tool_calls.input_json'] += n_ij != ij
            changed['tool_calls.result_excerpt'] += n_res != res
            upd.append((n_summ, n_ij, n_res, rid))
    conn.executemany('UPDATE tool_calls SET input_summary=?, input_json=?, result_excerpt=? WHERE rowid=?', upd)
    changed['sensitive_results_withheld'] = withhold_sensitive_results(conn)
    conn.executescript(DDL)                             # restores the two update triggers
    conn.execute("INSERT INTO turns_fts(turns_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO tools_fts(tools_fts) VALUES('rebuild')")
    stamp = {'at': iso_now(), 'patterns': dict(sorted(RED_COUNTS.items())), 'rows': changed}
    conn.execute("INSERT OR REPLACE INTO meta VALUES('rescrub_last', ?)", (json.dumps(stamp),))
    conn.commit()
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    conn.close()
    os.chmod(db_path, 0o600)
    if verbose:
        print('rescrub %s in %.1fs' % (os.path.basename(db_path), time.time() - t0))
        print('  hits per pattern: %s' % json.dumps(stamp['patterns'], sort_keys=True))
        print('  rows changed: %s' % json.dumps(changed, sort_keys=True))
    return stamp


USAGE_RECONCILE_VERSION = '1'


def reconcile_usage(ctx, verbose=True, codex_files=None):
    """Retroactive usage fix: re-read the already-ingested bytes of every Claude file (0..byte_offset)
    and raise stored usage where a duplicate record carried a larger output_tokens. Incremental runs
    never re-read those bytes, so without this the old undercount would stay. Reads only lines that
    are assistant records with a usage block; writes only token columns. Idempotent."""
    t0 = time.time()
    n0, d0 = ctx.usage_bumps, ctx.usage_bump_delta
    rows = ctx.conn.execute("SELECT path, byte_offset FROM ingest_files WHERE source='claude'").fetchall()
    for path, off in rows:
        try:
            f = open(path, 'rb')
        except OSError:
            continue
        with f:
            pos = 0
            for line in f:
                pos += len(line)
                if pos > (off or 0):
                    break
                if b'"assistant"' not in line or b'"usage"' not in line:
                    continue
                try:
                    r = json.loads(line.decode('utf-8', 'replace'))
                except ValueError:
                    continue
                if not isinstance(r, dict) or r.get('type') != 'assistant':
                    continue
                uid, sid = r.get('uuid'), r.get('sessionId') or r.get('session_id')
                msg = r.get('message') or {}
                u = msg.get('usage') if isinstance(msg, dict) else None
                if not uid or not u or not msg.get('id') or ctx.known.get(uid) != sid:
                    continue   # forked copies (stored as uuid@sid) never hold usage
                ctx.bump_usage(msg['id'], uid, claude_usage_vals(u))
    # Codex: re-read every rollout from 0. Re-reads are recognised by (ts, type) and skipped (their usage
    # raised if larger); records dropped earlier by an ordinal collision are inserted now.
    saved_red = dict(RED_COUNTS)
    added = 0
    for o in (codex_files or []):
        if not ZSTD or not os.path.exists(o['path']):
            continue
        ctx.f_turns = ctx.f_tools = ctx.f_dups = 0
        ctx.type_lines, ctx.type_rows = {}, {}
        fi = dict(o)
        process_codex_file(ctx, o['path'], fi, 0)
        ctx.flush()
        if ctx.f_turns or ctx.f_tools:
            added += ctx.f_turns
            ctx.conn.execute('UPDATE ingest_files SET rows_turns=rows_turns+?, rows_tools=rows_tools+?, '
                             'dup_skipped=dup_skipped-? WHERE path=?',
                             (ctx.f_turns, ctx.f_tools, ctx.f_turns, o['path']))
            for ty, n in ctx.type_rows.items():
                ctx.conn.execute('UPDATE ingest_type_counts SET rows_inserted=rows_inserted+? WHERE path=? AND type=?',
                                 (n, o['path'], ty))
    RED_COUNTS.clear()
    RED_COUNTS.update(saved_red)
    ctx.conn.execute("INSERT OR REPLACE INTO meta VALUES('usage_reconciled', ?)", (USAGE_RECONCILE_VERSION,))
    ctx.conn.commit()
    if verbose:
        print('codex rescan: %d files, +%d recovered rows (id collisions)' % (len(codex_files or []), added))
        print('usage reconcile: %d files, %d rows raised, +%d output tokens in %.1fs' % (
            len(rows), ctx.usage_bumps - n0, ctx.usage_bump_delta - d0, time.time() - t0), flush=True)


def run(db_path, files, verbose=True, reconcile=False):
    t0 = time.time()
    conn = open_db(db_path)
    ctx = Ctx(conn)
    done = conn.execute("SELECT v FROM meta WHERE k='usage_reconciled'").fetchone()
    if reconcile or (done is None and conn.execute('SELECT 1 FROM ingest_files LIMIT 1').fetchone()):
        indexed = {r[0] for r in conn.execute("SELECT path FROM ingest_files WHERE source='codex'")}
        reconcile_usage(ctx, verbose, [o for o in files if o['source'] == 'codex' and o['path'] in indexed])
    elif done is None:
        conn.execute("INSERT OR REPLACE INTO meta VALUES('usage_reconciled', ?)", (USAGE_RECONCILE_VERSION,))
    cx_names = load_codex_index()
    cx_meta = {}
    run_ts = iso_now()
    files_by_sid = {}
    sess_files = {}                    # sid -> set of paths (this run + prior), for n_files
    for o in files:
        files_by_sid.setdefault(o['sid'], o)
    grand = {'files': 0, 'skipped_unchanged': 0}
    pending_work = False
    for o in files:
        try:
            st0 = os.stat(o['path'])
        except OSError:
            continue
        r0 = conn.execute('SELECT size, mtime FROM ingest_files WHERE path=?', (o['path'],)).fetchone()
        if not (r0 and r0[0] == st0.st_size and r0[1] == st0.st_mtime):
            pending_work = True
            break
    if pending_work:
        t_pp = time.time()
        ctx.owner = fork_prepass(files)
        if verbose:
            print('fork prepass: %d shared uuids in %.1fs' % (len(ctx.owner), time.time() - t_pp), flush=True)
    for o in files:
        path = o['path']
        try:
            st = os.stat(path)
        except OSError:
            continue
        row = conn.execute('SELECT size, mtime, byte_offset FROM ingest_files WHERE path=?', (path,)).fetchone()
        if row and row[0] == st.st_size and row[1] == st.st_mtime:
            grand['skipped_unchanged'] += 1
            continue
        if o['source'] == 'codex' and not ZSTD:
            print('  WARN: zstd not found on PATH; skipping %s' % path, file=sys.stderr)
            continue
        offset = row[2] if row and st.st_size >= row[2] and o['source'] == 'claude' else 0
        if row and o['source'] == 'codex':
            offset = row[2]
        ctx.f_turns = ctx.f_tools = ctx.f_dups = 0
        ctx.type_lines = {}
        ctx.type_rows = {}
        fi = dict(o)
        t1 = time.time()
        rc = 0
        if o['source'] == 'claude':
            new_off, nlines = process_claude_file(ctx, path, o['group'], o['archived'], fi, offset)
        else:
            new_off, nlines, meta, rc = process_codex_file(ctx, path, fi, offset)
            if meta:
                cx_meta[fi['sid']] = meta
                files_by_sid.setdefault(fi['sid'], o)
            if rc not in (0, None):
                print('  WARN: zstd exit %s for %s' % (rc, path), file=sys.stderr)
        ctx.flush()
        if o['source'] == 'codex':
            files_by_sid[fi['sid']] = o
        # per-file bookkeeping
        conn.execute(
            'INSERT INTO ingest_files(path,size,mtime,byte_offset,lines,rows_turns,rows_tools,last_run,source,archived,dup_skipped) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, '
            'byte_offset=excluded.byte_offset, lines=lines+excluded.lines, rows_turns=rows_turns+excluded.rows_turns, '
            'rows_tools=rows_tools+excluded.rows_tools, last_run=excluded.last_run, dup_skipped=dup_skipped+excluded.dup_skipped',
            (path, st.st_size, st.st_mtime, new_off, nlines, ctx.f_turns, ctx.f_tools, run_ts, o['source'],
             o['archived'], ctx.f_dups))
        for ty, n in ctx.type_lines.items():
            conn.execute('INSERT INTO ingest_type_counts(path,type,lines,rows_inserted) VALUES (?,?,?,?) '
                         'ON CONFLICT(path,type) DO UPDATE SET lines=lines+excluded.lines, '
                         'rows_inserted=rows_inserted+excluded.rows_inserted',
                         (path, ty, n, ctx.type_rows.get(ty, 0)))
        for ty, n in ctx.type_rows.items():
            if ty not in ctx.type_lines:
                conn.execute('INSERT INTO ingest_type_counts(path,type,lines,rows_inserted) VALUES (?,?,?,?) '
                             'ON CONFLICT(path,type) DO UPDATE SET rows_inserted=rows_inserted+excluded.rows_inserted',
                             (path, ty, 0, n))
        conn.commit()
        ctx.totals['turns'] += ctx.f_turns
        ctx.totals['tools'] += ctx.f_tools
        ctx.totals['dups'] += ctx.f_dups
        ctx.totals['lines'] += nlines
        grand['files'] += 1
        if verbose:
            print('%-8s %6.1f MB  +%6d turns +%6d tools  dups %-5d lines %-7d %5.1fs  %s' % (
                o['source'], st.st_size / 1e6, ctx.f_turns, ctx.f_tools, ctx.f_dups, nlines,
                time.time() - t1, os.path.relpath(path, HOME)), flush=True)
    refresh_sessions(ctx, files_by_sid, cx_names, cx_meta)
    withhold_sensitive_results(conn)
    for kind, n in RED_COUNTS.items():
        conn.execute('INSERT INTO redaction_counts(kind,n) VALUES (?,?) ON CONFLICT(kind) DO UPDATE SET n=n+excluded.n',
                     (kind, n))
    conn.execute("INSERT OR REPLACE INTO meta VALUES('last_run', ?)", (run_ts,))
    conn.commit()
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    conn.close()
    os.chmod(db_path, 0o600)
    if verbose:
        print('DONE in %.1fs: %d files processed (%d unchanged), +%d turns, +%d tool_calls, %d dup records skipped, %d lines'
              % (time.time() - t0, grand['files'], grand['skipped_unchanged'], ctx.totals['turns'],
                 ctx.totals['tools'], ctx.totals['dups'], ctx.totals['lines']))
        print('redactions this run: %s' % (json.dumps(RED_COUNTS, sort_keys=True) if RED_COUNTS else '{}'))
        print('usage rows raised this run (re-seen records): %d (+%d output tokens)' % (
            ctx.usage_bumps, ctx.usage_bump_delta))
        print('db size: %.1f MB' % (os.path.getsize(db_path) / 1e6))
    return ctx.totals


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--db', help='database path (default: $LEDGER_DIR/ledger.db, else ~/.local/share/agent-ledger/ledger.db)')
    ap.add_argument('--claude-root', help='Claude Code transcripts directory (default: ~/.claude/projects)')
    ap.add_argument('--codex-root', help='Codex rollouts directory (default: ~/.codex/sessions)')
    ap.add_argument('--codex-index', help='Codex session_index.jsonl (default: ~/.codex/session_index.jsonl)')
    ap.add_argument('--archive-root', help='optional directory of archived Claude .jsonl transcripts')
    ap.add_argument('--only', choices=['claude', 'codex'], help='restrict to one source')
    ap.add_argument('--rebuild-fts', action='store_true', help='rebuild both FTS indexes and exit')
    ap.add_argument('--reconcile-usage', action='store_true',
                    help='re-read already-ingested Claude bytes and raise usage rows to the per-message max')
    ap.add_argument('--rescrub', action='store_true',
                    help='re-apply current redaction patterns to every stored text column, rebuild FTS, exit')
    ap.add_argument('-q', '--quiet', action='store_true')
    a = ap.parse_args()
    global CLAUDE_ROOT, CODEX_ROOT, CODEX_INDEX, ARCHIVE_ROOT
    CLAUDE_ROOT = os.path.expanduser(a.claude_root) if a.claude_root else CLAUDE_ROOT
    CODEX_ROOT = os.path.expanduser(a.codex_root) if a.codex_root else CODEX_ROOT
    CODEX_INDEX = os.path.expanduser(a.codex_index) if a.codex_index else CODEX_INDEX
    ARCHIVE_ROOT = os.path.expanduser(a.archive_root) if a.archive_root else ARCHIVE_ROOT
    db = a.db or paths.default_db()
    os.makedirs(os.path.dirname(os.path.abspath(db)), mode=0o700, exist_ok=True)
    if a.rescrub:
        rescrub(db, verbose=not a.quiet)
        return
    if a.rebuild_fts:
        conn = open_db(db)
        conn.execute("INSERT INTO turns_fts(turns_fts) VALUES('rebuild')")
        conn.execute("INSERT INTO tools_fts(tools_fts) VALUES('rebuild')")
        conn.commit()
        return
    files = discover()
    if a.only:
        files = [o for o in files if o['source'] == a.only]
    run(db, files, verbose=not a.quiet, reconcile=a.reconcile_usage)


if __name__ == '__main__':
    main()
