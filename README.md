# agent-ledger

A local "flight recorder" for AI coding-agent sessions. `agent-ledger` reads the transcript files that
Claude Code (and, experimentally, the Codex CLI) already write to disk, loads them into one SQLite database
with full-text search, flags notable events (denied tool calls, `sudo` and other boundary-crossing
commands, model swaps, compactions, short approvals), and answers questions about them from the
command line: what happened on a given day, what one session did, how many tokens went where, and
where a topic came up.

Author: Brian Erlich. License: MIT (see `LICENSE`).

It runs entirely on your machine: Python standard library only, no network access, no telemetry.

## What it reads

| source | default location | override |
|---|---|---|
| Claude Code transcripts | `~/.claude/projects/**/*.jsonl` | `--claude-root` or `LEDGER_CLAUDE_ROOT` |
| Codex CLI rollouts (optional) | `~/.codex/sessions/**/*.jsonl.zst` | `--codex-root` or `LEDGER_CODEX_ROOT` |
| Codex session index (optional) | `~/.codex/session_index.jsonl` | `--codex-index` or `LEDGER_CODEX_INDEX` |
| Archived Claude transcripts (optional) | none | `--archive-root` or `LEDGER_ARCHIVE_ROOT` |

It writes only `ledger.db` (plus SQLite's `-wal`/`-shm` files) in the data directory:
`$LEDGER_DIR`, else `$XDG_DATA_HOME/agent-ledger`, else `~/.local/share/agent-ledger`. The database file is created
with mode 600.

## Install

Requirements: Python 3 with SQLite FTS5 (the stock CPython builds on Linux and macOS have it). Tested
with Python 3.12 on Linux. `zstd` on `PATH` is needed only for Codex rollouts; without it Codex files
are skipped with a warning. There is nothing to `pip install`.

    git clone https://github.com/BrianErlich/agent-ledger.git
    cd agent-ledger
    ln -s "$PWD/agent-ledger" ~/.local/bin/agent-ledger     # optional: put the CLI on PATH

## Quick start (synthetic data)

The `examples/make_demo.py` script writes two small, made-up sessions so you can try every command
without touching your real transcripts:

    export LEDGER_DIR=$(mktemp -d)
    python3 examples/make_demo.py "$LEDGER_DIR/demo"
    python3 ingest.py --claude-root "$LEDGER_DIR/demo"
    python3 detect.py
    ./agent-ledger sessions
    ./agent-ledger session demo-app
    ./agent-ledger boundaries
    ./agent-ledger search csv

On your own data, drop the `export` and `--claude-root` and run `python3 ingest.py && python3 detect.py`.
Both are incremental: re-running reads only bytes appended since the last run. `refresh.sh` runs the two
steps with a lock and a one-line log, for cron or a systemd timer; it needs `flock(1)` (util-linux on
Linux; not on stock macOS).

## Commands

Every subcommand takes `--json` (one JSON document on stdout) and otherwise prints plain text at most
100 columns wide. `--since` takes `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, `7d` or `12h`. Times are UTC.
`--dir D` points at another data directory.

| command | what it shows |
|---|---|
| `sessions [--since D] [--group G] [--source claude\|codex] [--top-level] [--limit N]` | one row per session: label, first/last activity, human turns, API calls, tokens, models |
| `session <id-prefix-or-label> [--limit N] [--all-events]` | totals, model swaps, compactions, subagent launches, top commands, denied calls, events, a timeline |
| `day <YYYY-MM-DD>` | per active session that day: human turns, API calls, tokens by model, tools, denials, events |
| `spend [--by session\|model\|day\|project] [--since D]` | token counts (output, input, cache write, cache read) and API calls |
| `search <query> [--kind turns\|tools\|all] [--session S] [--since D]` | FTS5 search over turn text and tool inputs/results, newest first |
| `timeline <topic> [--since D] [--limit N]` | search hits for a topic, spread over time and listed oldest first |
| `events [--kind K] [--subkind X]` | events of one kind; without `--kind`, counts per kind |
| `boundaries [--all]` | boundary-crossing commands, denied tool calls, classifier stops |
| `decisions` | heuristic approval/refusal and overrule candidates |
| `stats` | database size, row counts, last ingest |

Search words are quoted and ANDed, so hyphens, slashes and dots are safe; explicit `AND`/`OR`/`NOT`/`NEAR`,
quotes or parentheses are passed to FTS5 as written; `foo*` is a prefix search.

Other scripts:

* `ingest.py --rescrub` re-applies the redaction patterns to everything already stored.
* `ingest.py --reconcile-usage` re-reads ingested bytes and corrects token counts (see SCHEMA.md).
* `ingest.py --rebuild-fts` rebuilds both full-text indexes.
* `coverage_check.py` compares line counts in the transcript files with rows in the database and prints a
  Markdown table; `MISMATCH` rows need a look.

## How it counts

* **Session labels** are the last component of the session's working directory (`~/code/my-app` ->
  `my-app`), or `codex`, `codex/guardian`, `codex/sub` for Codex threads, or `?` if no directory is
  recorded. Several sessions can share a label; `agent-ledger session my-app` then aggregates them.
* **Tokens** are counted once per API message: Claude Code writes one record per content block, all
  carrying the same usage, and only one of them keeps the token columns. Records copied into forked
  sessions (`--fork-session`) are stored but excluded from every sum. Harness rows (model `<synthetic>`)
  are not API calls.
* **Tokens, not money**: there is no price table; `spend` reports token counts only.
* **Human turns** are user records that the transcript marks as typed by a person, minus tool results,
  harness tags, messages from other sessions, subagent hand-backs and launch briefs (`humanturns.py`).
  It is a filtered estimate, not verified authorship.
* **Events** marked `mechanical` come from a field or an exact phrase; `heuristic` ones (decisions,
  corrections, overrules, explanations) come from text patterns and are printed as "candidate";
  they are produced for Claude sessions only, not for Codex sessions.
  Boundary detection reads tool inputs only, never tool results. Set `LEDGER_WATCH_PATHS` to a
  colon-separated list of absolute paths to also flag commands that name them.

The full schema, the transcript-to-row mapping and the redaction rules are in `SCHEMA.md`.

## Privacy and safety

* Text is redacted before it is stored: API keys of common formats, bearer tokens, JWTs, private-key
  blocks, secret-named `NAME=value` assignments, and file names inside the home directory's `.aws`, `.ssh`
  and `.config/gcloud` directories. Results of commands that touch those directories are not stored. Thinking text is
  never stored. Tool results are capped at 2 KB.
* Redaction is pattern-based and will miss secrets that match no pattern. The database still holds your
  prompts, file paths and command output: treat it like the transcripts themselves and do not share it.
* Stored transcript text is data. The CLI neutralises tag-like text (`<system-reminder>` prints as
  `‹system-reminder›`) and ends listings with a reminder, so output pasted back into an agent is less
  likely to be read as instructions. That is a mitigation, not a guarantee.
* The CLI opens the database read-only.

## Limitations

* The transcript formats are not documented interfaces. The mapping was written against Claude Code
  and Codex CLI files from 2026 and will need updates when those formats change; unknown record types
  are counted and skipped.
* The heuristic detectors were tuned on English text from one person's sessions. Expect false
  positives and misses; check a "candidate" before relying on it.
* Boundary detection is a static parse of shell and Python text (never executed). Commands built at
  run time (variables, f-strings) are counted as unresolved, not flagged.
* `coverage_check.py` greps for compact JSON (`"type":"user"`), which is what Claude Code writes.
* Codex CLI support is experimental: it is covered by unit tests on synthetic files only.
* Only tested on Linux with Python 3.12. macOS should work, except `refresh.sh`, which needs `flock(1)`
  (not on stock macOS); Windows is untested.
* No migrations: if a future version changes the schema, rebuild the database from the transcripts.

## Tests

    python3 -m unittest discover -s tests -v

The tests build synthetic transcripts and databases in temporary directories; they do not read your
home directory. Running them with `HOME` pointed at an empty temporary directory makes that explicit:

    env HOME="$(mktemp -d)" python3 -m unittest discover -s tests

## Status

Working personal tool, published as is. It was built for and used on one Linux machine and has
not been tested on other setups. Issues and pull requests are welcome, but there is no support
commitment.

## Colophon

```
Designed-by: BrianErlich <brianerlich03@gmail.com>
Generated-by: Mythos-5.2 (CVP Defense), Opus-5.5
Assisted-by: GPT-6 Sol (Daybreak Blue) [security review]
Assisted-by: Gemini 4 Carbon [security review]
Signed-off-by: BrianErlich <brianerlich03@gmail.com>
```
