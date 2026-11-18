"""The `agent-ledger` CLI's definition of a "human turn" (a prompt the person typed).

detect.py's heuristic detectors do not use this module; they apply their own, slightly different rule
(see "events" in SCHEMA.md).

A row counts when BOTH hold:
  1. SQL (HUMAN_SQL, aliases t=turns, s=sessions): a user-type, non-copy row with a timestamp, not a
     compaction summary, and either
       - Claude: role 'user', main thread (is_sidechain=0), not is_meta, origin_kind='human'; or
       - Codex: a thread started by the user (thread_source='user'; guardian/subagent threads excluded).
  2. Python (human_clean): after removing harness tags (<system-reminder>, <task-notification>, ...)
     something is left, and it is not a tool result, a peer message, a subagent hand-back, a launch
     brief ("You are the ... session"), a classifier notice, or Codex-injected context.
It is a filtered estimate, not verified authorship.
"""
import re

HUMAN_SQL = ("t.type='user' AND t.forked_copy=0 AND t.ts IS NOT NULL AND COALESCE(t.is_compact_summary,0)=0 AND ("
             "(s.source='claude' AND t.role='user' AND t.is_sidechain=0 AND COALESCE(t.is_meta,0)=0 AND t.origin_kind='human')"
             " OR (s.source='codex' AND s.thread_source='user'))")

_TAG_RE = re.compile(
    r"<(system-reminder|task-notification|agent-message|cross-session-message|command-[\w\-]+|local-command-[\w\-]+)\b[^>]*>.*?</\1>",
    re.S)
_TAG_OPEN_RE = re.compile(r"</?(?:system-reminder|task-notification|agent-message|cross-session-message|command-[\w\-]+|local-command-[\w\-]+)\b[^>]*>")
_MACHINE_PREFIXES = ("Another Claude session sent", "[Subagent hand-back]", "This session is being continued",
                     "Your response above was stopped by a safety classifier", "Caveat: The messages below",
                     "[Request interrupted", "<artifact-content")
_LAUNCH_RX = re.compile(r"^You are (?:now )?the [\w\-\. ]{2,60}?(?:session|worker|WORKER|agent|subagent)\b")
_SUBAGENT_RX = re.compile(r"^You are subagent\b", re.I)


def human_clean(text, codex=False):
    """Text of a user turn typed by the person, or None (tool results, reminders, hand-backs, briefs, injected context)."""
    if not text:
        return None
    t = _TAG_RE.sub("", text)
    t = _TAG_OPEN_RE.sub("", t)
    t = t.replace("[tool_result]", "").strip()
    if not t:
        return None
    t = t.replace("’", "'").replace("‘", "'")
    if any(t.startswith(p) for p in _MACHINE_PREFIXES) or _LAUNCH_RX.match(t) or _SUBAGENT_RX.match(t):
        return None
    if codex and (t.startswith("# AGENTS.md") or t.startswith("<")):
        return None
    return t
