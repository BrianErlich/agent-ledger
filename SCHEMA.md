# agent-ledger database schema

DB: `ledger.db` in `$LEDGER_DIR` (default `~/.local/share/agent-ledger/`), file mode 600, WAL journal.
Written by `ingest.py` (transcript tables) and `detect.py` (`events`); the `agent-ledger` CLI and
`coverage_check.py` open it read-only (`sqlite3 'file:ledger.db?mode=ro' ...`).
Columns marked (+) go beyond a plain transcript dump. **Never VACUUM the DB**: the FTS tables are keyed on
the implicit rowid of `turns`/`tool_calls`, which VACUUM may renumber (use `ingest.py --rebuild-fts` if you must).

All timestamps are ISO-8601 UTC strings as found in the source (`2026-01-02T16:15:27.579Z`).
All stored text is redacted (see Redaction). Thinking text is never stored.

## sessions
| col | notes |
|---|---|
| session_id TEXT PK | Claude: the record `sessionId`. Codex: the rollout's own thread id (`session_meta.payload.id`). Subagent files of a Claude session share the parent's session_id (see `turns.agent_id`). |
| source | `claude` / `codex` |
| cwd | first cwd seen |
| project_group | the `<claude-root>/<dir>` name (e.g. `-home-user-projects-app`), `archive` for files found only under `--archive-root`, `codex` for Codex |
| thread_name | Claude: last `ai-title` record; Codex: `session_index.jsonl` thread_name; else NULL |
| file_path | main file (non-subagent, non-archived preferred) |
| archived | 1 only if every file of the session is under the archive root |
| first_ts, last_ts | min/max ts of the session's *own* (forked_copy=0) turns; all turns if it has none |
| n_user, n_assistant | count of the session's own (`forked_copy=0`) `turns` rows of type user / assistant (all files, sidechains included). These count RECORDS, see "Assistant records" below |
| models | JSON list of distinct non-null `turns.model` |
| (+) parent_session_id | Codex `parent_thread_id` (forks, subagents, guardian reviews); NULL for Claude |
| (+) thread_source | Codex `thread_source` (`guardian_review`, `user`, `subagent`...) |
| (+) n_files | number of source files (main, `subagents/`, archived copy) |
| (+) forked_from | session that owns the records this session copied (see "Forked sessions"); NULL if none |
| (+) n_copied | number of copied (`forked_copy=1`) turns in this session |

## turns (one row per transcript record that is kept)
| col | notes |
|---|---|
| uuid TEXT PK | Claude: record `uuid`. `api-request`: its `id`. `permission-mode`: `pm:<sha1 of path+offset>`. Codex: `<thread_id>:<ordinal>`; when a resumed rollout reuses an ordinal for a DIFFERENT record (other ts or type), `<thread_id>:<ordinal>@<sha1(file name)[:8]>`. **Forked copies: `<orig uuid>@<session_id>`** (see below) |
| session_id, parent_uuid | |
| ts | record `timestamp` (permission-mode has none: the previous record's ts in that file) |
| type | the record's own `type` for Claude (`user`, `assistant`, `system`, `api-request`, `permission-mode`, `summary`). Codex: `user`, `assistant`, `developer`, `agent_message`, `tool_call`, `token_usage`, `task_started`, `task_complete`, `turn_aborted`, `compaction` |
| role | `message.role` (user/assistant/developer); NULL for system etc. |
| model | `message.model` for assistant; api-request: `params.model`; Codex: model of the enclosing `turn_context` |
| requested_model | Claude `requestedModel` (what the harness asked for; differs from `model` on fallback/swap) |
| is_sidechain | `isSidechain` (1 in subagent files) |
| agent_id | subagent id (record `agentId`, else from `agent-<id>.jsonl` filename); NULL for the main thread |
| text | all `text` blocks of message.content joined with `\n`. `tool_result` blocks -> the literal `[tool_result]`, images -> `[image]`. NULL for assistant records that only hold thinking/tool_use, and for system/api-request/permission-mode |
| thinking_chars | total length of `thinking` blocks (recent Claude transcripts carry thinking as an empty string + signature, so this is usually 0; use `thinking_tokens`) |
| input_tokens, output_tokens, cache_write_tokens, cache_read_tokens | **API usage, deduplicated** (see below). NULL on non-primary rows |
| stop_reason | `message.stop_reason` |
| cwd, git_branch, version | per record |
| is_compact_summary | `isCompactSummary` (Claude) or Codex compaction row |
| raw_keys | JSON list of top-level keys of the record |
| (+) msg_id | API message id (`msg_...`), Codex `response_id`. Several assistant rows share one msg_id |
| (+) request_id | `requestId` (Claude) |
| (+) subtype | `system.subtype` (turn_duration, compact_boundary, model_refusal_no_fallback, informational, ...), `api-request.querySource`, Codex payload type |
| (+) thinking_tokens | `usage.output_tokens_details.thinking_tokens` / Codex `reasoning_output_tokens` (primary row only; already included in output_tokens) |
| (+) cache_write_1h_tokens | `usage.cache_creation.ephemeral_1h_input_tokens` (subset of cache_write_tokens) |
| (+) effort | `effort` (assistant), `params.output_config.effort` (api-request) |
| (+) permission_mode | `permissionMode` (permission-mode rows, and on user rows that carry it) |
| (+) prompt_id | `promptId` (groups a human prompt and the assistant work that followed) |
| (+) origin_kind | `origin.kind` of user records (`human`, ... NULL when absent) |
| (+) is_meta | `isMeta` |
| (+) forked_copy | 1 = this record is a copy of a record owned by another session (same uuid and ts); 0 otherwise. Codex: 1 when the rollout marks the item `inherited_user_message` (history replayed from the parent thread). **Use `forked_copy=0` for "unique turns"** |
| (+) orig_uuid | for copies, the original uuid (join `turns o ON o.uuid = c.orig_uuid` gives the owner row); NULL otherwise |

### Forked sessions (`--resume X --fork-session`) and copied records
A forked Claude session's file starts with a copy of history: the same record `uuid`s and timestamps, but with the
fork's own `sessionId`. Handling:
* `fork_prepass()` scans all Claude files first and finds every uuid held by more than one `sessionId`. Owner = the
  holder with the earliest *native* record (a record only that session holds; a fork's copied prefix is older than the
  fork itself); ties on session id. So ownership does not depend on file order.
* The owner keeps `uuid` as PK. Every other holder gets a row with `uuid = '<uuid>@<its session_id>'`,
  `orig_uuid=<uuid>`, `forked_copy=1`; its `parent_uuid` stays the raw uuid (joins to the owner's row).
* Copies never carry token usage and never create `tool_calls`/results (the owner has them), so spend and tool
  counts are not doubled. `sessions.n_user/n_assistant/first_ts/last_ts` ignore copies; `sessions.n_copied` counts them;
  `sessions.forked_from` = owner session of the copy with the latest ts.
* Copies are lines in the fork's file and ARE rows (`rows_inserted` counts them). Unique turns = `WHERE forked_copy=0`.
* Not a fork, same `sessionId` in two files (an archived copy next to the live file; subagent files that replay the
  same records): the second occurrence is skipped (`ingest_files.dup_skipped`), not stored.
* Cross-check after ingest: `SELECT count(*) FROM turns WHERE forked_copy=1 AND orig_uuid NOT IN (SELECT uuid FROM turns)` = 0.

### Assistant records, usage dedup (important for spend queries)
Claude Code writes one `assistant` record **per content block** of an API response (thinking, text,
each tool_use), all carrying the same `message.id` and the same `usage`; earlier blocks of a
streamed message may carry a partial `output_tokens` (e.g. 3 instead of 7580). So:
* every record is one row in `turns` (row counts equal line counts per type);
* **token columns are set on exactly one row per `msg_id`: the record with the largest
  output_tokens (ties: the first seen).** All other rows of that message have NULL tokens.
  A record whose uuid is already stored but which carries a larger output_tokens (the same block re-written with the
  final usage) raises the stored usage, within one run or on a later run (`ingest.py --reconcile-usage` re-reads the
  already-ingested bytes; it runs once automatically on an older DB, `meta.usage_reconciled`).
  **output_tokens is still a lower bound**: Claude Code sometimes never writes the final usage of a message.
  Therefore `SUM(output_tokens) ... FROM turns` is correct and `COUNT(*) WHERE type='assistant'`
  counts blocks, while API calls = `COUNT(output_tokens)` or `COUNT(DISTINCT msg_id)`.
* the same `msg_id` can appear in several files (fork copies, archived copies): usage is counted once, globally
  (copies never take usage).
* the Codex equivalent is a `token_usage` row per `token_usage_record` (one per model response):
  `input_tokens` = input minus cached, `cache_read_tokens` = `cached_input_tokens`,
  `cache_write_tokens` = `cache_write_input_tokens`, `output_tokens` includes
  reasoning; `thinking_tokens` = reasoning_output_tokens.
* Rows whose model is `<synthetic>` are harness rows (no real API call, zero tokens); the CLI excludes them
  from every API-call count.

## tool_calls
| col | notes |
|---|---|
| id TEXT PK | tool_use block id (Claude `toolu_...`), Codex `call_id` |
| turn_uuid, session_id, ts | the assistant row that holds the block (Codex: the call item row) |
| name | tool name (`Bash`, `Read`, `Agent`, `mcp__...`; Codex `exec`, `send_message`, `spawn_agent`...) |
| input_summary | Bash: full `command`; Read/Edit/Write/NotebookEdit: `file_path`; Glob/Grep: `pattern` (+ ` @ ` path if any); Agent/Task: `description`; else first 300 chars of the input JSON. Codex `exec`: the JS source (the commands are inside `tools.exec_command({cmd:...})`) |
| input_json | full input JSON, any single string field > 8 KB truncated to 8 KB + `...[truncated N chars]` |
| result_excerpt | first **2,048 bytes of UTF-8** (cut on a character boundary) of the matching `tool_result` (found by `tool_use_id` in a later user record); NULL if no result recorded. A result of a command that names one of the credential directories (`.aws`, `.ssh`, `.config/gcloud` in a home directory) is replaced by `[result withheld: command touches a credential directory]`. Results are otherwise stored as returned (after redaction): they can contain hostnames, IP addresses and file listings |
| result_chars | full length of the result text before truncation |
| is_error | tool_result `is_error` (Codex: nonzero `exit_code` in the output) |
| denied | 1 if the call was refused/blocked (list below), else 0 |
| (+) denied_kind | which phrasing/field matched |
| (+) permission_decision | compact JSON of the user record's `permissionDecision` for this call (`{"decision":"accept","source":"config","reasonType":"classifier"}`); NULL if none |

### Denial detection (`denied=1`)
Primary signal is the user record's `toolDenialKind` field (applied to its `is_error` tool_results);
text phrases are the fallback:
| denied_kind | signal / text |
|---|---|
| `user-rejected` | `toolDenialKind=user-rejected`; "The user doesn't want to proceed with this tool use. The tool use was rejected" |
| `automode-blocked` | `toolDenialKind=automode-blocked`; "Permission for this action was denied by the Claude Code auto mode classifier. Reason: [..]" |
| `permission-rule` | `toolDenialKind=permission-rule`; "Permission for this command was denied by a built-in Claude Code safety check, not by the user" |
| `classifier-stop` | text "stopped by a safety classifier" (the response that made this tool call was stopped while the call was running) |
| `blocked-rule` | "<tool_use_error>Blocked: ..." (a harness rule, e.g. against long sleeps) |
| `classifier-error` | "auto mode classifier gave no verdict" (rejected, but not on its merits) |
| `perm-reject` | any other `permissionDecision.decision == "reject"` on an `is_error` result |
`toolDenialKind=interrupted` without the classifier phrase is a user interrupt and is NOT counted as denied.
Codex tool outputs contain no refusal phrasing, so `denied` is always 0 for Codex.

## ingest_files
`path PK, size, mtime, byte_offset, lines, rows_turns, rows_tools, last_run, source, archived, dup_skipped`
(`dup_skipped` = records skipped because the same uuid was already stored for the same session).
Claude: `byte_offset` = bytes consumed (complete lines only). Codex `.zst`: `byte_offset` = bytes of the
*decompressed* stream consumed (a re-run decompresses and skips that many bytes); `lines` = lines consumed.
`lines` counts every line including skipped record types. `rows_*` accumulate across runs.

`ingest_type_counts(path, type, lines, rows_inserted)`: per file and per record `type`, lines
seen vs rows inserted (the evidence `coverage_check.py` compares against). Skipped types appear with rows_inserted=0.
`redaction_counts(kind PK, n)`, cumulative. `meta(k PK, v)`: schema version, last run, per-rollout Codex state.

## Full text search
External-content FTS5 tables kept in sync by **triggers** (insert/update/delete), so incremental
runs need no rebuild:
* `turns_fts(text)` content=`turns`; `tools_fts(input_summary, result_excerpt)` content=`tool_calls`.
* `SELECT t.* FROM turns_fts f JOIN turns t ON t.rowid=f.rowid WHERE turns_fts MATCH 'foo bar' ORDER BY rank`
* tool_calls has a rowid too: `JOIN tool_calls c ON c.rowid=f.rowid`.
Tokenizer: default `unicode61` (hyphens/underscores split; quote phrases).

## Views
`v_api_messages` = turns rows that carry usage (one per API response). `v_tool_denials` = denied tool calls with session/ts.

## Skipped record types
Never stored as rows (only counted in `ingest_files.lines` / `ingest_type_counts`): `attachment`,
`queue-operation`, `last-prompt`, `bridge-session`, `mode`, and (for size/privacy)
`api-request-blob`, `api-request-shape`, `file-history-snapshot`, `file-history-delta`, `atis-latch`,
`cost-state`, `frame-link`, `artifact-*`. `ai-title` is consumed into `sessions.thread_name`.
Unknown record types are counted and otherwise ignored.

## Redaction
Applied to text, input_summary, input_json, result_excerpt before storing; matches become `[REDACTED:<kind>]`.
Kinds: `sk-ant`, `sk` (any `sk-` key of 20+ chars not preceded by a word character, e.g. sk-proj-), `aiza` (Google API
key), `jwt`, `ghp`, `github_pat`, `akia`, `slack`, `bearer`, `discord` (M/N/O prefix), `privkey`;
`env_assign` (everywhere: text, tool inputs incl. Write/Edit payloads, results): `[export ]NAME=value` at a line start or
after `;` `&` `|`, any case, value of 8+ non-space non-quote chars, where a `_`/camelCase component of NAME is one of
KEY(S) APIKEY TOKEN(S) SECRET(S) PASS PASSWD PASSWORD(S) PASSPHRASE PWD CREDENTIAL(S) CREDS AUTH BEARER COOKIE(S)
PRIVATE (bare `PWD`/`OLDPWD` excluded: shell cwd); `$VAR` values are left. `env` (results and `.env*` paths only): any
`UPPER_NAME=value` line of 12+ chars. `sensitive_path`: a path component under a home directory's `.aws/`, `.config/gcloud/` or
`.ssh/` becomes `[sensitive-path]`, except `.ssh/config`, `authorized_keys`, `known_hosts` and `*.pub`.
Cumulative ingest-time counts are in `redaction_counts`.

Redaction is pattern-based and best effort: it will miss secrets that do not match a pattern. Treat `ledger.db`
as sensitive.

**Retroactive:** `ingest.py --rescrub` re-applies the current patterns in place to every stored text/input/result
column, enforces the result byte cap, withholds credential-directory results and rebuilds both FTS indexes; its
per-pattern counters (no values) are in `meta.rescrub_last`. Run it after any pattern change (the ingester is incremental).

## Codex mapping (rollouts `*.jsonl.zst`; one rollout file = one thread = one `sessions` row)
| rollout record | stored as |
|---|---|
| `session_meta` | the session (id = payload.id, cwd, parent_thread_id, thread_source); no turn row |
| `turn_context`, `thread_settings_applied` | no row; they set the current model / cwd / effort stamped on later rows |
| `response_item/message` role user / assistant | `turns` type `user` / `assistant`, text = input_text/output_text joined; `subtype` = `phase`. Codex "user" rows include injected context (AGENTS.md, environment): they are NOT all human prompts |
| `response_item/message` role developer | `turns` type `developer`, text NULL (large boilerplate instructions) |
| `response_item/agent_message` | `turns` type `agent_message`, text = `[author -> recipient] ` + unencrypted text |
| `response_item/custom_tool_call` and `function_call` | one `turns` row type `tool_call` (role assistant, text NULL) + one `tool_calls` row (id = call_id) |
| `*_call_output` | pairs by `call_id` into `result_excerpt`; `is_error`=1 if any `"exit_code":N` with N != 0 in the first 200 KB |
| `token_usage_record` | `turns` type `token_usage` (msg_id = response_id), tokens as above |
| `event_msg/task_started`, `task_complete`, `turn_aborted` | `turns` rows of that type, text NULL (`subtype` = turn_trigger, `parent_uuid` = turn_id) |
| `response_item/compaction`, `compacted` | `turns` type `compaction`, is_compact_summary=1, text NULL |
| dropped (counted in `ingest_type_counts`) | `response_item/reasoning` (encrypted) and every other record type |
Records marked `metadata.inherited_user_message` are stored with `forked_copy=1`. Incremental runs re-decompress the `.zst`
and skip `byte_offset` decompressed bytes; the per-file model/cwd state is kept in `meta` (`cxstate:<path>`).

The Codex rollout format is not documented by its vendor; this mapping was written against the files one
installation produced and may need changes for other versions.

## events (written by detect.py)
`id INTEGER PK, session_id, turn_uuid, tool_call_id, ts, kind, subkind, detail, confidence, evidence, detector_version`.
`detect.py` deletes and rewrites the whole table on every run. `confidence` is `mechanical` (a field or exact phrase
matched) or `heuristic` (text patterns; the CLI prints these as "candidate": check before relying on one).
Detectors read tool **inputs** and turn text only; tool results are never scanned for boundary hits.

| kind | confidence | subkinds / meaning |
|---|---|---|
| `boundary_attempt` | mechanical | a shell command (Bash, Codex `exec`, nested `bash -c`, `eval`, `find -exec`, Python `subprocess`/`os.system`/`socket` with literal arguments, parsed with `ast` and never run) that uses `sudo`, `su`, `reboot`, `shutdown`, `systemctl` (`systemctl_readonly` for status-type verbs), `docker`/`podman`, a network `scanner`; or that contacts `lan_net` (RFC 1918 IPv4), `tailnet_net` (the 100.64/10 CGNAT range used by Tailscale, or `*.ts.net` names), `local_host` (`*.local`, `fe80:`); or that names `credential_dir` (a home directory's `.aws`, `.ssh`, `.config/gcloud`) or a `watched_path` (`LEDGER_WATCH_PATHS`) |
| `tool_denied` | mechanical | `user_declined`, `classifier_denial`, `classifier_no_verdict`, `permission_denied`, `tool_blocked`, `hook_block`, `other` |
| `classifier_stop` | mechanical | `tool_interrupted`, `meta_notice`, `api_refusal` |
| `model_swap` | mechanical | `requested` (requested model changed), `served` (served model changed) |
| `compaction` | mechanical | `summary`, `boundary` |
| `subagent_launch` | mechanical | subagent type (Agent/Task/spawn_agent calls) |
| `cross_chat_msg` | mechanical | `send` (SendMessage / Codex send_message), `inbound` (a message from another session arrived) |
| `user_decision` | heuristic | `approve`, `refuse`, `other`: a short human reply right after an assistant turn that asked something |
| `correction` | heuristic | `repeat`, `blame`, `stop`, `wrong` |
| `overrule` | heuristic | the human refused or corrected right after an explicit assistant recommendation |
| `concept_explained` | heuristic | `phrase`, `bold_term`: the assistant turn before a decision explained a term |

The heuristic turn events (`user_decision`, `correction`, `overrule`, `concept_explained`) are produced for
Claude sessions only, never for Codex sessions. They pick human turns by `detect.py`'s own rule, not by
`humanturns.py`: a main-thread Claude user record that is not meta, a compaction summary or an inherited copy,
with `origin_kind` `human` or absent, filtered by `detect.human_text`. The CLI's count (`humanturns.py`)
instead requires `origin_kind='human'`, applies `human_clean`, and also counts Codex user-started threads, so
the two numbers can differ.
