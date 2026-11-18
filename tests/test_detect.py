"""Unit tests for detect.py.  Run from the repository root: python3 -m unittest discover -s tests -v"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402
from fixtures import AWS, GCLOUD, PEM_BEGIN, PEM_END, ROOT_SSH, SSH, ip  # noqa: E402,F401

SCHEMA = """
CREATE TABLE sessions(session_id TEXT PRIMARY KEY, source TEXT, cwd TEXT, project_group TEXT, first_ts TEXT, last_ts TEXT);
CREATE TABLE turns(uuid TEXT PRIMARY KEY, session_id TEXT, parent_uuid TEXT, ts TEXT, type TEXT, role TEXT, model TEXT,
  requested_model TEXT, is_sidechain INT DEFAULT 0, agent_id TEXT, text TEXT, stop_reason TEXT,
  is_compact_summary INT DEFAULT 0, subtype TEXT, is_meta INT, origin_kind TEXT, inherited INT DEFAULT 0);
CREATE TABLE tool_calls(id TEXT PRIMARY KEY, turn_uuid TEXT, session_id TEXT, ts TEXT, name TEXT, input_summary TEXT,
  input_json TEXT, result_excerpt TEXT, is_error INT DEFAULT 0, denied INT DEFAULT 0, denied_kind TEXT);
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.con = sqlite3.connect(self.tmp.name)
        self.con.executescript(SCHEMA)
        self.n = 0
        self.session("s1", "/home/user/projects")

    def tearDown(self):
        self.con.close()
        os.unlink(self.tmp.name)

    # ---- fixture helpers
    def ts(self):
        self.n += 1
        return f"2026-10-20T10:{self.n // 60:02d}:{self.n % 60:02d}.000Z"

    def session(self, sid, cwd, source="claude"):
        self.con.execute("INSERT INTO sessions(session_id, source, cwd, first_ts) VALUES (?,?,?,?)", (sid, source, cwd, "2026-10-20T09:00:00Z"))

    def turn(self, typ, text="", sid="s1", model=None, rmodel=None, side=0, **kw):
        u = f"u{self.n + 1}"
        role = kw.pop("role", typ if typ in ("user", "assistant") else None)
        cols = dict(uuid=u, session_id=sid, ts=self.ts(), type=typ, role=role, model=model, requested_model=rmodel,
                    is_sidechain=side, text=text)
        cols.update(kw)
        self.con.execute(f"INSERT INTO turns({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", list(cols.values()))
        return u

    def user(self, text, **kw):
        return self.turn("user", text, **kw)

    def asst(self, text, model="claude-opus-4-8", **kw):
        return self.turn("assistant", text, model=model, rmodel=kw.pop("rmodel", model), **kw)

    def tool(self, name, summary="", result="", sid="s1", is_error=0, denied=0, dkind=None, input_json=None):
        turn = self.turn("assistant", "", sid=sid, model="claude-opus-4-8", rmodel="claude-opus-4-8")
        tid = f"t{self.n}"
        self.con.execute("INSERT INTO tool_calls VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (tid, turn, sid, self.ts(), name, summary, input_json, result, is_error, denied, dkind))
        return tid

    def bash(self, cmd, **kw):
        return self.tool("Bash", cmd, **kw)

    def run_detect(self):
        self.con.commit()
        detect.run(self.tmp.name)
        c = sqlite3.connect(self.tmp.name)
        rows = c.execute("SELECT kind, subkind, tool_call_id, turn_uuid, confidence, detail, evidence, session_id FROM events").fetchall()
        c.close()
        return rows

    def kinds(self, rows, kind):
        return [r for r in rows if r[0] == kind]

    def boundary(self, cmd):
        tid = self.bash(cmd)
        rows = self.run_detect()
        return sorted(r[1] for r in rows if r[0] == "boundary_attempt" and r[2] == tid)


class TestBoundary(Base):
    def test_sudo_and_variants(self):
        self.assertEqual(self.boundary("sudo apt update"), ["sudo"])

    def test_sudo_in_pipeline_and_subshell(self):
        self.assertEqual(self.boundary("echo x | sudo tee /etc/f"), ["sudo"])
        self.assertEqual(self.boundary("x=$(sudo id)"), ["sudo"])
        self.assertEqual(self.boundary("bash -c 'sudo id'"), ["sudo"])

    def test_sudo_in_quotes_echo_comment_heredoc_negative(self):
        for cmd in ["echo 'sudo rm -rf /'", 'echo "run sudo later"', "git commit -m 'no sudo here'",
                    "ls  # sudo is not allowed", "grep -r sudo notes.md", "cat <<EOF\nsudo apt install x\nEOF",
                    "printf '%s' docker", "which docker", "command -v sudo",
                    "python3 -c \"print('sudo')\""]:
            self.assertEqual(self.boundary(cmd), [], cmd)

    def test_systemctl_user_allowed_system_flagged(self):
        self.assertEqual(self.boundary("systemctl --user restart foo.service"), [])
        self.assertEqual(self.boundary("systemctl restart foo.service"), ["systemctl"])
        self.assertEqual(self.boundary("systemctl status nginx.service"), ["systemctl_readonly"])
        self.assertEqual(self.boundary("systemctl reboot"), ["shutdown"])

    def test_power_docker_scanners(self):
        self.assertEqual(self.boundary("reboot"), ["reboot"])
        self.assertEqual(self.boundary("shutdown -h now"), ["shutdown"])
        self.assertEqual(self.boundary("docker ps"), ["docker"])
        self.assertEqual(self.boundary(f"for i in 1; do nmap -sn {ip(10, 0, 0, 0)}/24; done"), ["scanner"])
        self.assertEqual(self.boundary("masscan 1.2.3.4"), ["scanner"])

    def test_lan_tailnet_local(self):
        self.assertEqual(self.boundary(f"curl http://{ip(192, 168, 1, 10)}/api"), ["lan_net"])
        self.assertEqual(self.boundary(f"ssh pi@{ip(10, 1, 2, 3)} uptime"), ["lan_net"])
        self.assertEqual(self.boundary(f"ping -c1 {ip(172, 20, 0, 5)}"), ["lan_net"])
        self.assertEqual(self.boundary(f"ping {ip(100, 100, 1, 1)}"), ["tailnet_net"])
        self.assertEqual(self.boundary("ssh nas.local ls"), ["local_host"])
        self.assertEqual(self.boundary("curl http://[fe80::1]/"), ["local_host"])

    def test_public_and_loopback_not_flagged(self):
        for cmd in ["curl https://example.com", "ping 8.8.8.8", "curl http://127.0.0.1:8080/", "curl localhost:3000",
                    "ping 172.32.0.1", "curl http://100.63.0.1", "wget https://github.com/x/y",
                    f"echo {ip(192, 168, 1, 1)} > hosts.txt", f"pip install foo=={ip(10, 2, 3, 4)}"]:
            self.assertEqual(self.boundary(cmd), [], cmd)

    def test_paths_credential_dirs(self):
        self.assertEqual(self.boundary(f"ls -la {SSH}/"), ["credential_dir"])
        self.assertEqual(self.boundary("cat /home/user/" + ".aws/credentials"), ["credential_dir"])
        self.assertEqual(self.boundary(f"ls {GCLOUD}"), ["credential_dir"])
        self.assertEqual(self.boundary(f"ls -la {ROOT_SSH}"), ["credential_dir"])
        self.assertEqual(self.boundary("ls /srv" + ROOT_SSH), [])

    def test_watched_paths_from_env(self):
        old = os.environ.get("LEDGER_WATCH_PATHS")
        os.environ["LEDGER_WATCH_PATHS"] = "/srv/private:/mnt/backup"
        try:
            self.assertEqual(self.boundary("ls /srv/private"), ["watched_path"])
            self.assertEqual(self.boundary("cat '/mnt/backup/x.tar'"), ["watched_path"])
            self.assertEqual(self.boundary("tar tf data.tar > /mnt/backup/out.txt"), ["watched_path"])
            for cmd in ["ls /home/user/projects/mnt/backup", "echo /mnt/backup is read-only",
                        "git commit -m 'mention /mnt/backup'", "ls /srv/private2", "# cat /srv/private/x\nls"]:
                self.assertEqual(self.boundary(cmd), [], cmd)
        finally:
            if old is None:
                os.environ.pop("LEDGER_WATCH_PATHS", None)
            else:
                os.environ["LEDGER_WATCH_PATHS"] = old
        self.assertEqual(self.boundary("ls /srv/private"), [])

    def test_paths_negative(self):
        for cmd in ["ls ~/.config/nvim", "ls /home/user/ssh", "echo .ssh"]:
            self.assertEqual(self.boundary(cmd), [], cmd)

    def test_result_text_never_read(self):
        # a web page in the RESULT quoting 'sudo rm -rf' must not fire
        tid = self.bash("fetch-page https://example.com/status/1", result=f"post: just ran sudo rm -rf / and nmap {ip(192, 168, 1, 1)} on {SSH}")
        rows = self.run_detect()
        self.assertEqual([r for r in rows if r[2] == tid and r[0] == "boundary_attempt"], [])

    def test_secret_in_evidence_is_redacted(self):
        self.bash("sudo curl -H 'Authorization: Bearer abcdefghijklmnop12345' http://x")
        rows = self.run_detect()
        ev = self.kinds(rows, "boundary_attempt")[0][6]
        self.assertNotIn("abcdefghijklmnop12345", ev)


class TestToolDenied(Base):
    def test_classifier_denial_with_reason(self):
        tid = self.bash("curl https://x", is_error=1, denied=1, dkind="automode-blocked",
                        result="Permission for this action was denied by the Claude Code auto mode classifier. Reason: [Third-Party Attack].")
        rows = self.run_detect()
        r = [x for x in rows if x[0] == "tool_denied" and x[2] == tid]
        self.assertEqual(r[0][1], "classifier_denial")
        self.assertIn("Third-Party Attack", r[0][5])

    def test_user_declined_and_blocked(self):
        a = self.tool("Edit", "f.py", result="The user doesn't want to proceed with this tool use. The tool use was rejected", is_error=1, denied=1, dkind="user-rejected")
        b = self.bash("sleep 45; echo", result="<tool_use_error>Blocked: sleep 45 followed by", is_error=1, denied=1, dkind="blocked-rule")
        rows = self.run_detect()
        got = {r[2]: r[1] for r in rows if r[0] == "tool_denied"}
        self.assertEqual(got[a], "user_declined")
        self.assertEqual(got[b], "tool_blocked")

    def test_no_verdict_without_denied_flag(self):
        tid = self.bash("ls", is_error=1, result="The server-side auto mode classifier gave no verdict (error), so auto mode cannot determine")
        rows = self.run_detect()
        self.assertEqual([r[1] for r in rows if r[0] == "tool_denied" and r[2] == tid], ["classifier_no_verdict"])

    def test_ordinary_error_and_ok_not_denied(self):
        self.bash("false", is_error=1, result="Exit code 1\nboom")
        self.bash("ls", result="denied by nobody; the word denied appears in a file listing")
        rows = self.run_detect()
        self.assertEqual(self.kinds(rows, "tool_denied"), [])


class TestClassifierStop(Base):
    def test_meta_notice(self):
        self.user("Your response above was stopped by a safety classifier — this is not a tool or API error. The rest was withheld", is_meta=1)
        rows = self.run_detect()
        self.assertEqual([r[1] for r in self.kinds(rows, "classifier_stop")], ["meta_notice"])

    def test_tool_interrupted(self):
        tid = self.bash("ls", is_error=1, denied=1, dkind="classifier-stop",
                        result="Interrupted: the response that made this tool call was stopped by a safety classifier while the call was running")
        rows = self.run_detect()
        self.assertEqual([(r[1], r[2]) for r in self.kinds(rows, "classifier_stop")], [("tool_interrupted", tid)])
        self.assertEqual(self.kinds(rows, "tool_denied"), [])

    def test_api_refusal_synthetic(self):
        self.turn("assistant", "API Error: Example 1.0's safeguards flagged this message.", model="<synthetic>")
        self.turn("assistant", "", model="<synthetic>", stop_reason="refusal")
        self.turn("assistant", "Here is a summary of safeguards in general.")
        rows = self.run_detect()
        self.assertEqual([r[1] for r in self.kinds(rows, "classifier_stop")], ["api_refusal", "api_refusal"])


class TestModelSwap(Base):
    def test_requested_swap(self):
        self.asst("a", model="claude-opus-4-8")
        u = self.asst("b", model="claude-example-1-0")
        rows = self.run_detect()
        r = self.kinds(rows, "model_swap")
        self.assertEqual([(x[1], x[3]) for x in r], [("requested", u)])

    def test_served_only_swap(self):
        self.asst("a", model="m1", rmodel="req")
        self.asst("b", model="m2", rmodel="req")
        self.assertEqual([r[1] for r in self.kinds(self.run_detect(), "model_swap")], ["served"])

    def test_no_swap_sidechain_synthetic_and_other_session(self):
        self.asst("a", model="m1")
        self.asst("b", model="m9", side=1)                    # sidechain ignored
        self.turn("assistant", "No response requested.", model="<synthetic>")
        self.asst("c", model="m1")
        self.session("s2", "/home/user/projects")
        self.asst("d", model="m9", sid="s2")                  # different session: first turn, no swap
        self.assertEqual(self.kinds(self.run_detect(), "model_swap"), [])


class TestCompactionSubagentCrossChat(Base):
    def test_compaction(self):
        self.user("This session is being continued from a previous conversation...", is_compact_summary=1)
        self.turn("summary", "old style summary")
        self.user("hello, an ordinary message mentioning compaction")
        self.assertEqual(len(self.kinds(self.run_detect(), "compaction")), 2)

    def test_compact_boundary_deduped_against_summary(self):
        self.turn("system", "Conversation compacted", subtype="compact_boundary")
        self.user("This session is being continued", is_compact_summary=1)
        self.assertEqual([r[1] for r in self.kinds(self.run_detect(), "compaction")], ["summary"])

    def test_subagent_launch(self):
        tid = self.tool("Agent", "Write detectors", input_json=json.dumps({"description": "Write detectors", "subagent_type": "general-purpose", "prompt": "x"}))
        self.tool("Read", "/x")
        self.tool("Bash", "echo Agent")
        rows = self.run_detect()
        r = self.kinds(rows, "subagent_launch")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][2], tid)
        self.assertIn("Write detectors", r[0][5])
        self.assertIn("general-purpose", r[0][5])

    def test_cross_chat(self):
        a = self.bash("cat > note.md <<'MSG'\nhello sudo\nMSG")
        d = self.tool("SendMessage", "to peer", input_json=json.dumps({"to": "peer-session", "message": "hi"}))
        self.bash("echo SendMessage")                         # negative
        self.user("Another Claude session sent a message: <agent-message from=\"abc\"> hi", is_meta=1)
        rows = self.run_detect()
        got = {r[2] or r[3]: r[1] for r in self.kinds(rows, "cross_chat_msg")}
        self.assertNotIn(a, got)
        self.assertEqual(got[d], "send")
        self.assertEqual(sorted(got.values()), ["inbound", "send"])
        self.assertEqual([r for r in rows if r[0] == "boundary_attempt"], [])  # sudo in heredoc body: no

    def test_codex_agent_tools(self):
        self.session("cx", "/home/user/projects", source="codex")
        a = self.tool("spawn_agent", "x", sid="cx", input_json=json.dumps({"description": "review", "subagent_type": "reviewer"}))
        b = self.tool("send_message", "x", sid="cx", input_json=json.dumps({"to": "peer"}))
        self.tool("wait", "x", sid="cx")
        rows = self.run_detect()
        self.assertEqual([r[2] for r in self.kinds(rows, "subagent_launch")], [a])
        self.assertEqual([r[2] for r in self.kinds(rows, "cross_chat_msg")], [b])

    def test_codex_exec_js_command(self):
        self.session("cx", "/home/user/projects", source="codex")
        js = 'text(await tools.exec_command({cmd:"sudo -n true","max_output_tokens"' + ':10}));\ntext(await tools.exec_command({cmd:"echo \'sudo x\'"}));'
        tid = self.tool("exec", js, sid="cx")
        rows = self.run_detect()
        self.assertEqual([(r[1], r[2]) for r in self.kinds(rows, "boundary_attempt")], [("sudo", tid)])


class TestHeuristics(Base):
    def test_decision_approve_after_ask(self):
        self.asst("I can push the branch now. Shall I go ahead?")
        u = self.user("yes go ahead")
        rows = self.run_detect()
        d = self.kinds(rows, "user_decision")
        self.assertEqual([(r[1], r[3]) for r in d], [("approve", u)])
        self.assertEqual(d[0][4], "heuristic")

    def test_decision_refuse_after_question_mark(self):
        self.asst("Should I delete the old DB?")
        self.user("No, hold on. Keep it.")
        self.assertEqual([r[1] for r in self.kinds(self.run_detect(), "user_decision")], ["refuse"])

    def test_decision_other_reply_and_mixed(self):
        self.asst("Option A or B? Your call.")
        self.user("use B instead, thanks")
        self.asst("Ok to proceed with merge?")
        self.user("yes but don't push")
        self.assertEqual([r[1] for r in self.kinds(self.run_detect(), "user_decision")], ["other", "other"])

    def test_decision_negatives(self):
        self.asst("Done. The tests pass.")                   # no ask
        self.user("yes")
        self.asst("Want me to continue?")
        self.user("<system-reminder>yes go ahead</system-reminder>")   # reminder only
        self.asst("Want me to continue?")
        self.con.execute("UPDATE sessions SET source='claude' WHERE 1")
        self.user("This session is being continued from a previous conversation. yes", is_compact_summary=1)
        self.asst("Want me to continue?")
        self.user("[tool_result]")
        self.asst("Want me to continue?")
        self.user("Another Claude session sent a message: <agent-message> yes go ahead", is_meta=1)
        self.asst("Want me to continue?")
        self.user("ok " + "pasted log line " * 150)           # > PASTE_LIMIT
        self.asst("Want me to continue?")
        self.user("yes", side=1)                              # sidechain
        self.assertEqual(self.kinds(self.run_detect(), "user_decision"), [])

    def test_decision_ignores_tool_result_between(self):
        self.asst("Shall I deploy it?")
        self.bash("ls")                                       # assistant tool-only rows have empty text
        self.user("[tool_result]")
        self.user("ship it")
        self.assertEqual([r[1] for r in self.kinds(self.run_detect(), "user_decision")], ["approve"])

    def test_correction_positive(self):
        self.asst("I rewrote the file.")
        a = self.user("No, that's not what I asked for.")
        b = self.user("why did you delete the tests?")
        c = self.user("I said use the other path")
        d = self.user("please stop")
        rows = self.run_detect()
        got = {r[3]: r[1] for r in self.kinds(rows, "correction")}
        self.assertEqual(got[a], "wrong")
        self.assertEqual(got[b], "blame")
        self.assertEqual(got[c], "repeat")
        self.assertEqual(got[d], "stop")

    def test_correction_negative(self):
        self.asst("Done.")
        self.user("great, thanks. now do the next one")
        self.user("The stop hook summary shows 3 entries")      # 'stop' not sentence-initial verb
        self.user("<system-reminder>that's wrong, stop</system-reminder>")
        self.user("Another Claude session sent a message: wrong, stop", is_meta=1)
        self.turn("assistant", "that's wrong, stop")             # assistant text is never a correction
        self.assertEqual(self.kinds(self.run_detect(), "correction"), [])

    def test_overrule(self):
        self.asst("I recommend option A: ship it behind a flag. Ok?")
        u = self.user("no, don't ship it. do B")
        self.asst("My recommendation is to merge now.")
        v = self.user("That's wrong, the tests fail")
        self.asst("Option A or B?")                             # no recommendation
        self.user("no, B")
        rows = self.run_detect()
        o = sorted((r[3], r[1]) for r in self.kinds(rows, "overrule"))
        self.assertEqual(o, sorted([(u, "refuse"), (v, "correction")]))

    def test_overrule_negative_approve(self):
        self.asst("I suggest we merge it. OK?")
        self.user("yes do it")
        self.assertEqual(self.kinds(self.run_detect(), "overrule"), [])

    def test_concept_explained(self):
        a = self.asst("A **tripwire file**: a dummy file that alerts you when touched. In other words, a tripwire. Shall I add one?")
        self.user("yes")
        b = self.asst("**Tripwire**: a file that is never opened by normal work, so any touch is a signal worth an alert. Shall I add one?")
        self.user("yes")
        self.asst("**Option A**: do it now and see what happens in the logs for a while. Ok?")   # skipped lead
        self.user("yes")
        self.asst("Which do you want? Shall I proceed?")
        self.user("yes")
        rows = self.run_detect()
        c = self.kinds(rows, "concept_explained")
        self.assertEqual([r[3] for r in c], [a, b])
        self.assertEqual(sorted(r[1] for r in c), ["bold_term", "phrase"])

    def test_concept_requires_following_decision(self):
        self.asst("In other words, it means that the cache is stale.")
        self.user("thanks, now something else entirely")
        self.assertEqual(self.kinds(self.run_detect(), "concept_explained"), [])

    def test_codex_user_turns_not_human(self):
        self.session("cx", "/home/user/projects", source="codex")
        self.turn("assistant", "Shall I?", sid="cx", model="gpt")
        self.turn("user", "yes", sid="cx")
        self.assertEqual(self.kinds(self.run_detect(), "user_decision"), [])


class TestIdempotent(Base):
    def test_rerun_same_counts_and_ids(self):
        self.bash("sudo id")
        self.asst("Shall I?")
        self.user("yes")
        r1 = self.run_detect()
        c = sqlite3.connect(self.tmp.name)
        ids1 = [r[0] for r in c.execute("SELECT id FROM events ORDER BY id")]
        c.close()
        r2 = self.run_detect()
        c = sqlite3.connect(self.tmp.name)
        ids2 = [r[0] for r in c.execute("SELECT id FROM events ORDER BY id")]
        c.close()
        self.assertEqual(r1, r2)
        self.assertEqual(len(ids1), len(ids2))
        self.assertGreater(len(ids1), 0)

    def test_other_version_replaced(self):
        # detect-1.1: the events table holds one detector's output, so readers that do not
        # filter on detector_version can never double count across versions
        self.run_detect()
        c = sqlite3.connect(self.tmp.name)
        c.execute("INSERT INTO events(session_id, kind, detector_version) VALUES ('s1','x','old-0.1')")
        c.commit()
        c.close()
        self.run_detect()
        c = sqlite3.connect(self.tmp.name)
        n = c.execute("SELECT COUNT(*) FROM events WHERE detector_version='old-0.1'").fetchone()[0]
        c.close()
        self.assertEqual(n, 0)

    def test_detail_evidence_length_cap(self):
        self.bash("sudo " + "x" * 2000)
        rows = self.run_detect()
        self.assertLessEqual(len(rows[0][5]), 300)
        self.assertLessEqual(len(rows[0][6]), 300)


if __name__ == "__main__":
    unittest.main()
