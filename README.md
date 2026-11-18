# agent-ledger

`agent-ledger` reads the transcript files that Claude Code (and, experimentally, the Codex CLI) already
write to disk and loads them into one SQLite database with full-text search. It flags notable events
(denied tool calls, `sudo` and other boundary-crossing commands, model swaps, compactions, short
approvals) and answers questions from the command line: what happened on a given day, what one session
did, how many tokens went where, and where a topic came up.

It runs on your machine with the Python standard library only. It makes no network connections and
sends no telemetry.

Author: Brian Erlich. License: MIT (see `LICENSE`).

## What it reads

| source | default location | override |
|---|---|---|
| Claude Code transcripts | `~/.claude/projects/**/*.jsonl` | `--claude-root` or `LEDGER_CLAUDE_ROOT` |
| Codex CLI rollouts (optional) | `~/.codex/sessions/**/*.jsonl.zst` | `--codex-root` or `LEDGER_CODEX_ROOT` |
| Codex session index (optional) | `~/.codex/session_index.jsonl` | `--codex-index` or `LEDGER_CODEX_INDEX` |
| Archived Claude transcripts (optional) | none | `--archive-root` or `LEDGER_ARCHIVE_ROOT` |

`ingest.py` writes `ledger.db` (plus SQLite's `-wal`/`-shm` files) in the data directory:
`$LEDGER_DIR`, else `$XDG_DATA_HOME/agent-ledger`, else `~/.local/share/agent-ledger`. The database file is
created with mode 600. `refresh.sh`, if you use it, adds a lock file and `refresh.log` there.

## Install

Requirements: Python 3.12 is the tested version; older Python 3 versions are untested. SQLite needs
FTS5, which the stock CPython builds on Linux and macOS have. `zstd` on `PATH` is needed only for Codex
rollouts; without it Codex files are skipped with a warning. There is nothing to `pip install`.

    git clone https://github.com/BrianErlich/agent-ledger.git
    cd agent-ledger
    mkdir -p ~/.local/bin
    ln -s "$PWD/agent-ledger" ~/.local/bin/agent-ledger     # optional: put the CLI on PATH

## Quick start (synthetic data)

The `examples/make_demo.py` script writes two small, made-up sessions so you can try every command.
Run the demo in a subshell, as below, so its settings end with it. Every input path is pointed into the
temporary directory; with only `--claude-root` set, `ingest.py` would still read real Codex files from
`~/.codex`.

    (
      export LEDGER_DIR=$(mktemp -d)
      export LEDGER_CODEX_ROOT="$LEDGER_DIR/none" LEDGER_CODEX_INDEX="$LEDGER_DIR/none.jsonl"
      unset LEDGER_ARCHIVE_ROOT
      python3 examples/make_demo.py "$LEDGER_DIR/demo"
      python3 ingest.py --claude-root "$LEDGER_DIR/demo"
      python3 detect.py
      ./agent-ledger sessions
      ./agent-ledger session demo-app
      ./agent-ledger boundaries
      ./agent-ledger search csv
    )

On your own data, run `python3 ingest.py && python3 detect.py`. `ingest.py` skips unchanged files and
adds rows only for what was appended since the last run. `detect.py` recomputes all events each time.
`refresh.sh` runs the two steps under a lock and appends one line per run to `refresh.log`, for cron or
a systemd timer; it needs `flock(1)` (util-linux on Linux; not on stock macOS).

## Commands

Every subcommand takes `--json` (one JSON document on stdout) and otherwise prints plain text, wrapped
to about 100 columns. `--since` takes `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, `7d` or `12h`. Times are UTC.
`--dir D` points at another data directory.

| command | what it shows |
|---|---|
| `sessions [--since D] [--group G] [--source claude\|codex] [--top-level] [--limit N]` | one row per session: label, first/last activity, human turns, API calls, tokens, models |
| `session <id-prefix-or-label> [--limit N] [--all-events]` | totals, model swaps, compactions, subagent launches, top commands, denied calls, events, a timeline |
| `day <YYYY-MM-DD>` | per active session that day: human turns, API calls, tokens by model, tools, denials, events |
| `spend [--by session\|model\|day\|project] [--since D] [--limit N]` | token counts (output, input, cache write, cache read) and API calls |
| `search <query> [--kind turns\|tools\|all] [--session S] [--since D] [--limit N]` | FTS5 search over turn text and tool inputs/results, newest first |
| `timeline <topic> [--since D] [--limit N]` | search hits for a topic, spread over time and listed oldest first |
| `events [--kind K] [--subkind X] [--session S] [--since D] [--limit N]` | events of one kind; without `--kind`, a count per kind over the whole database (the other filters are ignored) |
| `boundaries [--all] [--session S] [--since D] [--limit N]` | boundary-crossing commands, denied tool calls, classifier stops; `--all` adds read-only `systemctl` calls |
| `decisions [--session S] [--since D] [--limit N]` | heuristic approval/refusal and overrule candidates |
| `stats` | database size, row counts, last ingest |

Search words are quoted and ANDed, so hyphens, slashes and dots are safe; explicit `AND`/`OR`/`NOT`/`NEAR`,
quotes or parentheses are passed to FTS5 as written; `foo*` is a prefix search.

Other scripts:

* `ingest.py --rescrub` re-applies the redaction patterns to stored turn text, tool inputs and result
  excerpts, then rebuilds both full-text indexes. It does not touch session metadata or event details.
* `ingest.py --reconcile-usage` re-reads ingested bytes and corrects token counts (see SCHEMA.md).
* `ingest.py --rebuild-fts` rebuilds both full-text indexes.
* `coverage_check.py [db]` compares line counts in the transcript files with rows in the database and
  prints a Markdown table; `MISMATCH` rows need a look. It needs `head` and `grep` on `PATH`, and `zstd`
  for Codex files.

## How it counts

* Session labels are the last component of the session's working directory (`~/code/my-app` ->
  `my-app`). The home directory is labelled `(home)` and anything under `/tmp` is `(tmp)`. Codex threads
  are `codex`, `codex/guardian` or `codex/sub`, and a session with no recorded directory is `?`.
  Several sessions can share a label; `agent-ledger session my-app` then aggregates them.
* Tokens are counted once per API message. Claude Code writes one record per content block, all
  carrying the same usage, and only one of them keeps the token columns. Records copied into forked
  sessions (`--fork-session`) are stored but excluded from every sum. Harness rows (model `<synthetic>`)
  are not counted as API calls.
* `spend` reports token counts only. There is no price table.
* Human turns are user records that the transcript marks as typed by a person, minus tool results,
  harness tags, messages from other sessions, subagent hand-backs and launch briefs (`humanturns.py`).
  The count is a filtered estimate; the tool cannot verify who typed a message.
* Events marked `mechanical` come from a field or an exact phrase and are produced for both Claude and
  Codex sessions. Events marked `heuristic` (decisions, corrections, overrules, explanations) come from
  text patterns, are produced for Claude sessions only, and are shown as "candidate" in event listings.
* Boundary detection reads tool inputs and does not read tool results. Set `LEDGER_WATCH_PATHS` to a
  colon-separated list of absolute paths to also flag commands that name them.

The full schema, the transcript-to-row mapping and the redaction rules are in `SCHEMA.md`.

## Privacy and safety

* Text is redacted before it is stored: API keys of common formats, bearer tokens, JWTs, private-key
  blocks, secret-named `NAME=value` assignments, and most file names inside the home directory's `.aws`,
  `.ssh` and `.config/gcloud` directories (`SCHEMA.md` lists the exceptions). When a tool call's stored
  input names one of those directories, its result excerpt is replaced with a placeholder. Thinking text
  is not stored. Each tool result excerpt is capped at 2,048 bytes.
* Redaction is pattern-based and will miss secrets that match no pattern. The database still holds your
  prompts, file paths and command output. Treat it like the transcripts themselves and do not share it.
* Stored transcript text may contain instructions aimed at an agent. In search, timeline and event
  listings the CLI rewrites tag-like text (`<system-reminder>` prints as `‹system-reminder›`) and ends
  the plain-text output with a one-line reminder that it is data. The `session` report and `--json`
  output do not get the same treatment throughout, so prompt injection through pasted output remains
  possible.
* The CLI opens the database read-only.

## Limitations

* The transcript formats are not documented interfaces. The mapping was written against Claude Code
  and Codex CLI files from 2026 and will need updates when those formats change; unknown record types
  are counted and skipped.
* The heuristic detectors were tuned on English text from one person's sessions. Expect false
  positives and misses; check a "candidate" before relying on it.
* Boundary detection is a static parse of shell and Python text; nothing is executed. A command
  built at run time (variables, f-strings) cannot be resolved, so it is not flagged. For Python code
  such calls are counted as unresolved.
* `coverage_check.py` greps for compact JSON (`"type":"user"`), which is what Claude Code writes.
* Codex CLI support is experimental: it is covered by unit tests on synthetic files only.
* Only tested on Linux with Python 3.12. macOS should work, except `refresh.sh`, which needs `flock(1)`
  (not on stock macOS); Windows is untested.
* No migrations: if a future version changes the schema, rebuild the database from the transcripts.

## Tests

    python3 -m unittest discover -s tests -v

The 125 tests build synthetic transcripts and databases in temporary directories and do not read your
home directory. To enforce that, point `HOME` at an empty temporary directory:

    env HOME="$(mktemp -d)" python3 -m unittest discover -s tests

## Status

This is a working personal tool, published as is. It was built for and used on one Linux machine and
has not been tested on other setups. Issues and pull requests are welcome, but there is no support
commitment.

## Colophon

```
Designed-by: BrianErlich <brianerlich03@gmail.com>
Generated-by: Mythos-5.2 (CVP Defense), Opus-5.5
Assisted-by: GPT-6 Sol (Daybreak Blue) [security review]
Assisted-by: Gemini 4 Carbon [security review]
Signed-off-by: BrianErlich <brianerlich03@gmail.com>
```
