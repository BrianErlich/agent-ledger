"""Default locations, all overridable by environment variables or command-line options.

    LEDGER_DIR           directory that holds ledger.db
                         (default: $XDG_DATA_HOME/agent-ledger, i.e. ~/.local/share/agent-ledger)
    LEDGER_CLAUDE_ROOT   Claude Code transcripts        (default: ~/.claude/projects)
    LEDGER_CODEX_ROOT    Codex CLI rollouts             (default: ~/.codex/sessions)
    LEDGER_CODEX_INDEX   Codex session index            (default: ~/.codex/session_index.jsonl)
    LEDGER_ARCHIVE_ROOT  optional extra directory of archived Claude .jsonl transcripts (default: none)
"""
import os


def home():
    return os.path.expanduser("~")


def data_dir():
    d = os.environ.get("LEDGER_DIR")
    if d:
        return os.path.expanduser(d)
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(home(), ".local", "share")
    return os.path.join(xdg, "agent-ledger")


def default_db():
    return os.path.join(data_dir(), "ledger.db")


def _env_path(name, default):
    v = os.environ.get(name)
    if v:
        return os.path.expanduser(v)
    return default


def claude_root():
    return _env_path("LEDGER_CLAUDE_ROOT", os.path.join(home(), ".claude", "projects"))


def codex_root():
    return _env_path("LEDGER_CODEX_ROOT", os.path.join(home(), ".codex", "sessions"))


def codex_index():
    return _env_path("LEDGER_CODEX_INDEX", os.path.join(home(), ".codex", "session_index.jsonl"))


def archive_root():
    """None unless LEDGER_ARCHIVE_ROOT is set."""
    v = os.environ.get("LEDGER_ARCHIVE_ROOT")
    return os.path.expanduser(v) if v else None
