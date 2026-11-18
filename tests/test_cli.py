"""Tests for the `agent-ledger` CLI on a tiny synthetic ledger.db (no real data)."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(os.path.dirname(HERE), "agent-ledger")

TURNS = """CREATE TABLE turns(
  uuid TEXT PRIMARY KEY, session_id TEXT, parent_uuid TEXT, ts TEXT, type TEXT, role TEXT,
  model TEXT, requested_model TEXT, is_sidechain INT, agent_id TEXT, text TEXT, thinking_chars INT,
  input_tokens INT, output_tokens INT, cache_write_tokens INT, cache_read_tokens INT,
  stop_reason TEXT, cwd TEXT, git_branch TEXT, version TEXT, is_compact_summary INT, raw_keys TEXT,
  msg_id TEXT, request_id TEXT, subtype TEXT, thinking_tokens INT, cache_write_1h_tokens INT,
  effort TEXT, permission_mode TEXT, prompt_id TEXT, origin_kind TEXT, is_meta INT, forked_copy INT, orig_uuid TEXT)"""
SESSIONS = """CREATE TABLE sessions(
  session_id TEXT PRIMARY KEY, source TEXT, cwd TEXT, project_group TEXT, thread_name TEXT,
  file_path TEXT, archived INT, first_ts TEXT, last_ts TEXT, n_user INT, n_assistant INT, models TEXT,
  parent_session_id TEXT, thread_source TEXT, n_files INT, forked_from TEXT, n_copied INT)"""
TOOLS = """CREATE TABLE tool_calls(
  id TEXT PRIMARY KEY, turn_uuid TEXT, session_id TEXT, ts TEXT, name TEXT, input_summary TEXT,
  input_json TEXT, result_excerpt TEXT, result_chars INT, is_error INT, denied INT,
  denied_kind TEXT, permission_decision TEXT)"""
EVENTS = """CREATE TABLE events(
  id INTEGER PRIMARY KEY, session_id TEXT, turn_uuid TEXT, tool_call_id TEXT, ts TEXT,
  kind TEXT, subkind TEXT, detail TEXT, confidence TEXT, evidence TEXT, detector_version TEXT)"""

S1 = "aaaaaaaa-0000-0000-0000-000000000001"  # cwd /home/user/projects/zoo -> label 'zoo'
S2 = "bbbbbbbb-0000-0000-0000-000000000002"  # fork of S1, no cwd recorded -> '?'
S3 = "cccccccc-0000-0000-0000-000000000003"  # cwd /home/user/projects/garden -> 'garden'
DAY = "2026-10-20"


def turn(uuid, sid, ts, typ="assistant", model="claude-opus-5-5", text=None, msg=None, out=None, inp=None,
         cw=None, cr=None, fork=0, origin=None, role=None):
    return (uuid, sid, ts, typ, role or typ, model, 0, text, inp, out, cw, cr, msg, fork, origin)


def make_dbs(d, with_events=False):
    c = sqlite3.connect(os.path.join(d, "ledger.db"))
    for ddl in (TURNS, SESSIONS, TOOLS):
        c.execute(ddl)
    c.execute("CREATE VIRTUAL TABLE turns_fts USING fts5(text, content='turns', content_rowid='rowid')")
    c.execute("CREATE VIRTUAL TABLE tools_fts USING fts5(input_summary, result_excerpt, content='tool_calls', content_rowid='rowid')")
    c.execute("CREATE TABLE ingest_files(path TEXT PRIMARY KEY, size INT, mtime REAL, byte_offset INT, lines INT, rows_turns INT, "
              "rows_tools INT, last_run TEXT, source TEXT, archived INT, dup_skipped INT)")
    c.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT)")
    c.execute("INSERT INTO meta VALUES('last_run','2026-10-20T23:00:00Z')")
    c.execute("INSERT INTO ingest_files VALUES('/x/a.jsonl',1,1,1,10,5,2,'2026-10-20T23:00:00Z','claude',0,0)")
    cols = "(uuid,session_id,ts,type,role,model,is_sidechain,text,input_tokens,output_tokens,cache_write_tokens,cache_read_tokens,msg_id,forked_copy,origin_kind)"
    rows = [
        turn("u1", S1, DAY + "T10:00:00Z", "user", None, text="please fix the zebra parser", origin="human"),
        # one API message (m1) written as 3 block rows; usage sits on one row only (ingest rule)
        turn("a1", S1, DAY + "T10:00:05Z", text="thinking about zebra", msg="m1"),
        turn("a2", S1, DAY + "T10:00:06Z", text="here is the plan for the zebra", msg="m1", out=100, inp=10, cw=50, cr=1000),
        turn("a3", S1, DAY + "T10:00:07Z", text=None, msg="m1"),
        turn("a4", S1, DAY + "T11:00:00Z", model="claude-sonnet-5-5", text="second call", msg="m2", out=30, inp=3, cw=0, cr=500),
        turn("a5", S1, DAY + "T12:00:00Z", model="<synthetic>", text="harness note", msg="m3", out=0, inp=0, cw=0, cr=0),
        # a forked copy of a1/a2 in S2 (carries no usage by ingest rules, but even if it did it must be excluded)
        turn("a2@" + S2, S2, DAY + "T10:00:06Z", text="here is the plan for the zebra", msg="m1", out=100, inp=10, cw=50, cr=1000, fork=1),
        turn("u2", S2, DAY + "T13:00:00Z", "user", None, text="a different question", origin="human"),
        turn("a6", S2, DAY + "T13:00:05Z", text="answer two", msg="m4", out=7, inp=1, cw=0, cr=20),
        turn("tr1", S2, DAY + "T13:00:06Z", "user", None, text="[tool_result]"),
        turn("u3", S3, "2026-10-21T09:00:00Z", "user", None, text="garden kickoff", origin="human"),
        turn("a7", S3, "2026-10-21T09:00:05Z", text="garden answer", msg="m5", out=11, inp=2, cw=5, cr=9),
    ]
    c.executemany("INSERT INTO turns " + cols + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    c.execute("UPDATE turns SET orig_uuid='a2' WHERE forked_copy=1")
    c.executemany("INSERT INTO sessions(session_id,source,cwd,project_group,thread_name,first_ts,last_ts,forked_from) VALUES (?,?,?,?,?,?,?,?)", [
        (S1, "claude", "/home/user/projects/zoo", "-home-user-projects-zoo", "Fix zebra parser", DAY + "T10:00:00Z", DAY + "T12:00:00Z", None),
        (S2, "claude", None, "-home-user-projects-zoo", "Follow-up question", DAY + "T13:00:00Z", DAY + "T13:00:06Z", S1),
        (S3, "claude", "/home/user/projects/garden", "-home-user-projects-garden", "garden", "2026-10-21T09:00:00Z", "2026-10-21T09:00:05Z", None)])
    c.executemany("INSERT INTO tool_calls(id,turn_uuid,session_id,ts,name,input_summary,result_excerpt,denied,denied_kind) VALUES (?,?,?,?,?,?,?,?,?)", [
        ("t1", "a2", S1, DAY + "T10:00:06Z", "Bash", "cd ~/projects/zoo && make test && make lint", "ok 3 passed", 0, None),
        ("t2", "a2", S1, DAY + "T10:30:00Z", "Bash", "git status && grep quokka notes.txt", "quokka appears here", 0, None),
        ("t3", "a2", S1, DAY + "T10:31:00Z", "Bash", "sudo reboot", "denied by classifier", 1, "automode-blocked"),
        ("t4", "a4", S1, DAY + "T11:00:00Z", "Read", "/home/user/projects/zoo/x.py", None, 0, None)])
    c.execute("INSERT INTO turns_fts(turns_fts) VALUES('rebuild')")
    c.execute("INSERT INTO tools_fts(tools_fts) VALUES('rebuild')")
    if with_events:
        c.execute(EVENTS)
        c.execute("INSERT INTO events(session_id,turn_uuid,tool_call_id,ts,kind,subkind,detail,confidence,detector_version) VALUES "
                  "(?,?,?,?,?,?,?,?,?)", (S1, "a2", "t3", DAY + "T10:31:00Z", "boundary_attempt", "sudo", "sudo reboot", "mechanical", "detect-1.0"))
        c.execute("INSERT INTO events(session_id,ts,kind,subkind,detail,confidence,detector_version) VALUES (?,?,?,?,?,?,?)",
                  (S1, DAY + "T10:05:00Z", "user_decision", "approve", "[start] yes", "heuristic", "detect-1.0"))
    c.commit()
    c.close()


def run(d, *args, ok=True):
    env = dict(os.environ, HOME=d)   # never look at a real home directory
    p = subprocess.run([sys.executable, LEDGER, "--dir", d] + list(args), capture_output=True, text=True, env=env)
    if ok and p.returncode != 0:
        raise AssertionError("agent-ledger %s failed (%d): %s" % (" ".join(args), p.returncode, p.stderr))
    return p


def js(d, *args):
    return json.loads(run(d, *args, "--json").stdout)


class WithEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = cls.tmp.name
        make_dbs(cls.d, with_events=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_spend_dedup_by_model(self):
        r = js(self.d, "spend", "--by", "model")
        tot = r["total"]
        # m1 (3 block rows) counted once: 100; m2 30; m3 0; m4 7; m5 11. The forked copy of m1 is excluded.
        self.assertEqual(tot["output"], 100 + 30 + 0 + 7 + 11)
        self.assertEqual(tot["api_calls"], 4)   # the <synthetic> harness row m3 is not an API call
        self.assertEqual(tot["input"], 10 + 3 + 0 + 1 + 2)
        self.assertEqual(tot["cache_write"], 50 + 0 + 0 + 0 + 5)
        self.assertEqual(tot["cache_read"], 1000 + 500 + 0 + 20 + 9)
        keys = {x["key"] for x in r["rows"]}
        self.assertNotIn("synthetic(harness)", keys)
        self.assertEqual(r["unit"], "tokens")

    def test_spend_dedup_when_several_rows_of_a_message_carry_usage(self):
        # defensive: even if ingest ever left usage on two block rows of one msg_id, it is counted once
        with tempfile.TemporaryDirectory() as d:
            make_dbs(d)
            c = sqlite3.connect(os.path.join(d, "ledger.db"))
            c.execute("UPDATE turns SET output_tokens=100, input_tokens=10, cache_write_tokens=50, cache_read_tokens=1000 WHERE uuid='a1'")
            c.commit()
            c.close()
            self.assertEqual(js(d, "spend", "--by", "model")["total"]["output"], 100 + 30 + 0 + 7 + 11)

    def test_spend_by_session_day_project(self):
        by_s = js(self.d, "spend", "--by", "session")
        self.assertEqual(sum(x["output"] for x in by_s["rows"]), 148)
        self.assertTrue(any(x["key"].startswith("zoo ") and x["output"] == 130 for x in by_s["rows"]))
        by_d = {x["key"]: x["output"] for x in js(self.d, "spend", "--by", "day")["rows"]}
        self.assertEqual(by_d, {DAY: 137, "2026-10-21": 11})
        by_p = {x["key"]: x["output"] for x in js(self.d, "spend", "--by", "project")["rows"]}
        self.assertEqual(by_p["zoo"], 130)
        self.assertEqual(by_p["(none)"], 7)
        self.assertEqual(by_p["garden"], 11)
        since = js(self.d, "spend", "--by", "day", "--since", "2026-10-21")
        self.assertEqual(since["total"]["output"], 11)

    def test_no_dollars_in_output(self):
        out = run(self.d, "spend", "--by", "model").stdout
        self.assertNotIn("$", out)
        self.assertIn("tokens only", out)

    def test_search_turns_and_tools(self):
        r = js(self.d, "search", "zebra", "--limit", "20")
        kinds = {x["kind"].split(":")[0] for x in r}
        self.assertEqual(kinds, {"turn"})
        ts = [x["ts"] for x in r]
        self.assertEqual(ts, sorted(ts, reverse=True))   # newest first
        # forked copy is not returned twice: 'plan for the zebra' exists in a2 and its copy
        plan = [x for x in r if "plan" in x["snippet"]]
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["label"], "zoo")
        self.assertTrue(all(len(x["snippet"]) <= 200 for x in r))
        tools = js(self.d, "search", "quokka", "--kind", "tools")
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["kind"], "tool:Bash")
        self.assertEqual(len(js(self.d, "search", "quokka", "--kind", "turns")), 0)

    def test_search_filters_and_odd_queries(self):
        self.assertEqual(js(self.d, "search", "zebra", "--since", "2026-10-21"), [])
        sess = js(self.d, "search", "zebra", "--session", "zoo", "--kind", "all")
        self.assertTrue(sess and all(x["label"] == "zoo" for x in sess))
        self.assertEqual(js(self.d, "search", "3/3"), js(self.d, "search", '"3 3"'))  # slash is safe
        self.assertEqual(len(js(self.d, "search", "zoo-2", "--kind", "turns")), 0)  # hyphen does not break FTS
        self.assertEqual(len(js(self.d, "search", "zeb*", "--kind", "turns")), 3)  # prefix
        self.assertEqual(len(js(self.d, "search", "zebra OR quokka")), 4)  # raw operator

    def test_day_aggregation(self):
        r = js(self.d, "day", DAY)
        by = {s["label"]: s for s in r["sessions"]}
        s1 = by["zoo"]
        self.assertEqual(s1["user_turns"], 1)
        self.assertEqual(s1["api_calls"], 2)  # m1, m2 (m3 is a <synthetic> harness row: excluded)
        self.assertEqual(s1["tokens_by_model"]["opus-5-5"]["output"], 100)
        self.assertEqual(s1["tokens_by_model"]["sonnet-5-5"]["output"], 30)
        self.assertEqual(s1["tools"], {"Bash": 3, "Read": 1})
        self.assertEqual(s1["denied"], 1)
        self.assertEqual(s1["events"], {"boundary_attempt": 1, "user_decision": 1})
        s2 = by["?"]  # fork without a recorded cwd
        self.assertEqual((s2["user_turns"], s2["api_calls"], s2["tool_calls"]), (1, 1, 0))
        self.assertNotIn("garden", [s["label"] for s in r["sessions"]])
        text = run(self.d, "day", DAY).stdout
        self.assertIn("zoo (aaaaaaaa)", text)
        self.assertTrue(all(len(line) <= 100 for line in text.splitlines()), "line over 100 cols")

    def test_labels(self):
        rows = {x["id"]: x for x in js(self.d, "sessions")}
        self.assertEqual(rows["aaaaaaaa"]["label"], "zoo")
        self.assertEqual(rows["aaaaaaaa"]["label_basis"], "cwd")
        self.assertEqual(rows["bbbbbbbb"]["label"], "?")
        self.assertEqual(rows["bbbbbbbb"]["label_basis"], "none; fork of aaaaaaaa")
        self.assertEqual(rows["cccccccc"]["label"], "garden")
        # user turns count only human typed rows; api calls and tokens are deduplicated
        self.assertEqual(rows["aaaaaaaa"]["user_turns"], 1)
        self.assertEqual(rows["aaaaaaaa"]["api_calls"], 2)  # synthetic m3 excluded
        self.assertEqual(rows["aaaaaaaa"]["output_tokens"], 130)
        self.assertEqual(rows["bbbbbbbb"]["output_tokens"], 7)

    def test_session_summary(self):
        r = js(self.d, "session", "zoo")
        self.assertEqual(r["usage"]["output"], 130)
        self.assertEqual(r["model_swaps"][0]["from"], "opus-5-5")
        self.assertEqual(len(r["denied"]), 1)
        self.assertEqual(dict(r["top_commands"])["git"], 1)  # `git status && ...`
        self.assertEqual(dict(r["top_commands"])["make"], 1)  # `cd ~/projects/zoo && make ...` skips the cd
        self.assertEqual(dict(r["top_commands"])["sudo"], 1)
        self.assertEqual(r["events_by_kind"]["boundary_attempt"], 1)
        self.assertEqual(js(self.d, "session", "aaaaaaaa")["usage"]["output"], 130)  # id prefix works
        self.assertNotEqual(run(self.d, "session", "nonexistent", ok=False).returncode, 0)

    def test_events_commands(self):
        b = js(self.d, "boundaries")
        self.assertEqual(b["total"], 1)
        self.assertEqual(b["rows"][0]["subkind"], "sudo")
        d = js(self.d, "decisions")
        self.assertEqual(d["rows"][0]["confidence"], "candidate")
        self.assertEqual(js(self.d, "events", "--kind", "user_decision")["total"], 1)
        self.assertEqual(js(self.d, "events", "--kind", "overrule")["total"], 0)

    def test_timeline(self):
        t = js(self.d, "timeline", "zebra")
        self.assertEqual({x["kind"].split(":")[0] for x in t}, {"turn"})
        ts = [x["ts"] for x in t]
        self.assertEqual(ts, sorted(ts))   # chronological
        self.assertTrue(all(len(x["snippet"]) <= 300 for x in t))
        t2 = js(self.d, "timeline", "quokka")
        self.assertEqual([x["kind"] for x in t2], ["tool:Bash"])

    def test_stats_and_readonly(self):
        r = js(self.d, "stats")
        self.assertEqual(r["row_counts"]["ledger.turns"], 12)
        self.assertEqual(r["last_ingest"], "2026-10-20T23:00:00Z")
        before = os.path.getmtime(os.path.join(self.d, "ledger.db"))
        run(self.d, "spend")
        self.assertEqual(before, os.path.getmtime(os.path.join(self.d, "ledger.db")))


class SharedLabel(unittest.TestCase):
    """`session <label>` over several sessions counts model swaps within each session, never across them."""

    def test_model_swaps_are_per_session(self):
        s4 = "dddddddd-0000-0000-0000-000000000004"   # a second 'zoo' session
        with tempfile.TemporaryDirectory() as d:
            make_dbs(d)
            c = sqlite3.connect(os.path.join(d, "ledger.db"))
            c.execute("INSERT INTO sessions(session_id,source,cwd,project_group,first_ts,last_ts) VALUES (?,?,?,?,?,?)",
                      (s4, "claude", "/home/user/projects/zoo", "-home-user-projects-zoo", DAY + "T14:00:00Z", DAY + "T15:00:00Z"))
            cols = "(uuid,session_id,ts,type,role,model,is_sidechain,text,input_tokens,output_tokens,cache_write_tokens,cache_read_tokens,msg_id,forked_copy,origin_kind)"
            # S1 ends on sonnet; s4 starts on opus (not a swap), then moves to sonnet (a swap)
            c.executemany("INSERT INTO turns " + cols + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                turn("d1", s4, DAY + "T14:00:00Z", text="d one", msg="m41", out=1, inp=1, cw=0, cr=0),
                turn("d2", s4, DAY + "T15:00:00Z", model="claude-sonnet-5-5", text="d two", msg="m42", out=1, inp=1, cw=0, cr=0)])
            c.commit()
            c.close()
            r = js(d, "session", "zoo")
            self.assertEqual(sorted(x["session_id"] for x in r["sessions"]), [S1, s4])
            self.assertEqual([(s["from"], s["to"]) for s in r["model_swaps"]],
                             [("opus-5-5", "sonnet-5-5"), ("opus-5-5", "sonnet-5-5")])


class NoEvents(unittest.TestCase):
    def test_graceful_without_events_table(self):
        with tempfile.TemporaryDirectory() as d:
            make_dbs(d, with_events=False)
            for cmd in (["decisions"], ["boundaries"], ["events", "--kind", "sudo"], ["events"]):
                p = run(d, *cmd)
                self.assertIn("no events yet; run detect.py", p.stdout)
                self.assertFalse(js(d, *cmd)["events_available"])
            day = run(d, "day", DAY).stdout
            self.assertIn("events: none yet", day)
            ses = js(d, "session", "aaaaaaaa")
            self.assertFalse(ses["events_available"])
            self.assertTrue(js(d, "search", "zebra"))
            self.assertEqual(js(d, "spend")["total"]["output"], 148)
            self.assertEqual(len(js(d, "sessions")), 3)

    def test_missing_db_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = run(d, "stats", ok=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("run ingest.py first", p.stderr)

    def test_empty_events_table(self):
        with tempfile.TemporaryDirectory() as d:
            make_dbs(d)
            c = sqlite3.connect(os.path.join(d, "ledger.db"))
            c.execute(EVENTS)
            c.commit()
            c.close()
            self.assertIn("no events yet", run(d, "boundaries").stdout)


class Helpers(unittest.TestCase):
    def test_cmd_word_and_fts_query(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("ledger_cli", LEDGER)
        spec = importlib.util.spec_from_loader("ledger_cli", loader)
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        self.assertEqual(m.cmd_word("cd ~/work && FOO=1 python3 x.py"), "python3")
        self.assertEqual(m.cmd_word("/usr/bin/git log"), "git")
        self.assertEqual(m.cmd_word("timeout 30 curl http://x"), "curl")
        self.assertEqual(m.cmd_word("cat > f <<'EOF'\nsudo not me\nEOF"), "cat")
        self.assertEqual(m.fts_query('zoo-2 "x" foo*'), '"zoo-2" "x" "foo"*')
        self.assertEqual(m.parse_since("2026-10-20"), "2026-10-20")


if __name__ == "__main__":
    unittest.main()
