# Changelog

## 0.1.0 (2026-11)
First public release.
- `ingest.py`: Claude Code and Codex CLI transcripts into SQLite with FTS5; incremental, idempotent,
  fork-aware, usage deduplicated per API message, redaction at ingest plus `--rescrub`.
- `detect.py` (detector version detect-1.2): mechanical and heuristic events, including a static parse of
  shell and Python bodies for boundary-crossing commands.
- `agent-ledger` CLI: sessions, session, day, spend, search, timeline, events, boundaries, decisions, stats.
- `coverage_check.py`, `refresh.sh`, `examples/make_demo.py`.
- Transcript roots and the data directory are configurable (CLI options, environment, XDG defaults).
