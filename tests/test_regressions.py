"""Regression tests: usage raise on re-seen records, Codex id collisions, partial lines, redaction.
Synthetic fixtures only; secret-shaped strings are assembled at runtime."""
import json
import os
import sqlite3
import stat
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ingest  # noqa: E402
from fixtures import AWS, GCLOUD, PEM_BEGIN, PEM_END, REL_AWS, REL_SSH, ROOT_SSH, SSH, ip  # noqa: E402,F401
from test_ingest import Base, SID, u, user_rec, asst_rec, write_lines, TestCodex  # noqa: E402

TXT = [{'type': 'text', 'text': 'hi'}]


class TestUsageReseen(Base):
    """A known uuid re-seen with a larger output_tokens must raise the usage row."""

    def recs(self, first=3, later=100):
        return [user_rec(u(1), None, 'go'),
                asst_rec(u(2), u(1), TXT, 'msg_A', first),
                asst_rec(u(3), u(2), [{'type': 'text', 'text': 'more'}], 'msg_A', first),
                asst_rec(u(2), u(1), TXT, 'msg_A', later)]          # same uuid again, final usage

    def usage(self):
        return self.q('SELECT uuid, output_tokens FROM turns WHERE output_tokens IS NOT NULL')

    def test_within_one_run(self):
        write_lines(self.cfile(), self.recs())
        self.run_ingest()
        self.assertEqual(self.usage(), [(u(2), 100)])

    def test_incremental_rerun(self):
        recs = self.recs()
        write_lines(self.cfile(), recs[:3])
        self.run_ingest()
        self.assertEqual(len(self.usage()), 1)
        write_lines(self.cfile(), recs[3:], mode='a')
        self.run_ingest()
        self.assertEqual(self.usage(), [(u(2), 100)])
        self.assertEqual(self.q('SELECT count(*) FROM (SELECT msg_id FROM turns WHERE output_tokens IS NOT NULL '
                                'GROUP BY msg_id HAVING count(*) > 1)')[0][0], 0)

    def test_smaller_reseen_is_ignored(self):
        write_lines(self.cfile(), self.recs(first=50, later=7))
        self.run_ingest()
        self.assertEqual([r[1] for r in self.usage()], [50])

    def test_reconcile_repairs_rows_stored_by_the_old_ingester(self):
        write_lines(self.cfile(), self.recs())
        self.run_ingest()
        c = sqlite3.connect(self.db)      # simulate the pre-fix DB: usage kept at the first value, flag unset
        c.execute("UPDATE turns SET output_tokens=3 WHERE uuid=?", (u(2),))
        c.execute("DELETE FROM meta WHERE k='usage_reconciled'")
        c.commit()
        c.close()
        self.run_ingest()                 # file unchanged; the one-time reconcile re-reads its bytes
        self.assertEqual(self.usage(), [(u(2), 100)])
        self.run_ingest()                 # idempotent
        self.assertEqual(self.usage(), [(u(2), 100)])


class TestPartialSkippedLine(Base):
    """A half-written trailing line of a SKIPPED type must not be consumed (line count +1)."""

    def test_skipped_type_partial_line(self):
        write_lines(self.cfile(), [user_rec(u(1), None, 'go')])
        att = json.dumps({'type': 'attachment', 'uuid': u(9), 'sessionId': SID, 'x': 'y' * 50})
        with open(self.cfile(), 'a') as f:
            f.write(att[:30])
        self.run_ingest()
        with open(self.cfile(), 'a') as f:
            f.write(att[30:] + '\n')
        write_lines(self.cfile(), [asst_rec(u(2), u(1), TXT, 'msg_B', 5)], mode='a')
        self.run_ingest()
        lines = self.q('SELECT lines FROM ingest_files')[0][0]
        self.assertEqual(lines, 3)
        self.assertEqual(self.q("SELECT count(*) FROM ingest_type_counts WHERE type='_bad'")[0][0], 0)


class TestCodexCollision(TestCodex):
    """A resumed rollout reuses an ordinal for a different record; it must not be dropped."""
    test_codex_mapping_incremental = None   # inherited fixture only; that test runs in test_ingest

    def test_reused_ordinal_kept_and_true_reread_skipped(self):
        T, recs = self.recs()
        p1 = os.path.join(ingest.CODEX_ROOT, '2026', '10', '17', 'rollout-a-%s.jsonl.zst' % T)
        self.zst(p1, recs)
        resumed = [dict(recs[0]),
                   {'timestamp': '2026-10-17T11:00:00.000Z', 'ordinal': 6, 'type': 'response_item',
                    'payload': {'type': 'message', 'role': 'developer', 'content': [{'type': 'input_text', 'text': 'resume'}]}},
                   {'timestamp': '2026-10-17T11:00:01.000Z', 'ordinal': 8, 'type': 'response_item',
                    'payload': {'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': 'again'}]}}]
        p2 = os.path.join(ingest.CODEX_ROOT, '2026', '10', '18', 'rollout-b-%s_x.jsonl.zst' % T)
        self.zst(p2, resumed)
        m = self.run_ingest()
        rows = self.q("SELECT uuid, type FROM turns WHERE uuid LIKE ? ORDER BY ts", T + ':6%')
        self.assertEqual([r[1] for r in rows], ['assistant', 'developer'])
        self.assertTrue(rows[1][0].startswith(T + ':6@'))
        self.assertEqual(m['dups'], 0)
        self.assertEqual(self.run_ingest()['turns'], 0)


class TestRedactionExtra(unittest.TestCase):
    """Redaction: secret-named assignments, sensitive paths, byte cap, rescrub."""

    def setUp(self):
        ingest.RED_COUNTS.clear()

    def test_codex_probes_and_new_patterns(self):
        cases = [('sk-proj-' + 'a' * 64, '[REDACTED:sk]'),
                 ('PASSWORD=' + 'a' * 8, 'PASSWORD=[REDACTED:env]'),
                 ('export API_KEY=' + 'a' * 32, 'export API_KEY=[REDACTED:env]'),
                 ('  db_password = "' + 'h' * 10 + '"', '  db_password = "[REDACTED:env]"'),
                 ('AIza' + 'B' * 35, '[REDACTED:aiza]'),
                 ('eyJ' + 'a' * 12 + '.eyJ' + 'b' * 12 + '.' + 'c' * 12, '[REDACTED:jwt]'),
                 ('O' + 'A' * 23 + '.abc_-1.' + 'x' * 27, '[REDACTED:discord]'),
                 ('sk-ant-' + 'x' * 30, '[REDACTED:sk-ant]')]
        for s, want in cases:
            self.assertEqual(ingest.redact(s), want, s[:12])

    def test_code_is_not_redacted(self):
        for s in ["ROOT='/home/user/projects/x'", 'TOKEN=$(cat file)', 'HOME_DIR=/home/user/long/path',
                  'key = 1', 'API_KEY=[REDACTED:env]', 'PWD=/home/user/projects/app',
                  'passed = results_of_the_run', 'author = some_function_call()',
                  'the risk-assessment-procedure-v2-final', 'task-notification-abcdefghijklmnop']:
            self.assertEqual(ingest.redact(s), s)

    def test_write_edit_inputs_are_redacted(self):
        inp = {'file_path': '/w/config.py', 'content': 'x = 1\nexport SECRET_TOKEN=' + 'q' * 20 + '\n'}
        self.assertIn('[REDACTED:env]', ingest.red_json(inp)['content'])

    def test_sensitive_paths(self):
        s = (f'ls -la {SSH}/ {SSH}/id_x /home/user/' + '.aws/credentials ' + f'{GCLOUD}/adc.json '
             f'{SSH}/config {SSH}/known_hosts {SSH}/deploy_key.pub')
        out = ingest.redact(s)
        self.assertEqual(out.count('[sensitive-path]'), 3)
        for keep in (SSH + '/config', SSH + '/known_hosts', 'deploy_key.pub', SSH + '/ '):
            self.assertIn(keep, out)
        self.assertEqual(ingest.redact(out), out)

    def test_relative_and_root_sensitive_paths(self):
        self.assertEqual(ingest.redact(f'cat {REL_SSH}/id_x'), f'cat {REL_SSH}/[sensitive-path]')
        self.assertEqual(ingest.redact(f'cat ./{REL_AWS}/cfg_x'), f'cat ./{REL_AWS}/[sensitive-path]')
        self.assertEqual(ingest.redact(f'cat {REL_SSH}/config'), f'cat {REL_SSH}/config')   # ordinary .ssh file kept
        self.assertTrue(ingest.SENSITIVE_DIR.search(f'ls -la {ROOT_SSH}'))
        for s in ('see docs.aws/guide', 'cd my.ssh/x', 'ls /srv' + ROOT_SSH, 'ls ' + ROOT_SSH.replace('/root', '/rooted'),
                  'ls ' + ROOT_SSH + 'd'):
            self.assertEqual(ingest.redact(s), s)                 # no false positives on look-alikes
            self.assertIsNone(ingest.SENSITIVE_DIR.search(s), s)

    def test_byte_cap(self):
        self.assertEqual(len(ingest.cut_bytes('é' * 2000).encode()), 2048)
        self.assertEqual(ingest.cut_bytes('abc'), 'abc')


class TestRescrub(Base):
    def test_rescrub_in_place_counts_and_fts(self):
        sec = 'export API_KEY=' + 'z' * 30
        recs = [user_rec(u(1), None, 'note ' + 'sk-proj-' + 'b' * 40),
                asst_rec(u(2), u(1), [{'type': 'tool_use', 'id': 'toolu_1', 'name': 'Bash',
                                       'input': {'command': 'ls -la ' + AWS + '/ && ' + sec}}], 'msg_C', 5),
                user_rec(u(3), u(2), None, content=[{'type': 'tool_result', 'tool_use_id': 'toolu_1',
                                                     'content': 'credentials\nconfig\n' + 'é' * 1500}])]
        write_lines(self.cfile(), recs)
        self.run_ingest()
        c = sqlite3.connect(self.db)   # put the pre-fix state back, as an old ingester would have stored it
        c.execute('UPDATE turns SET text=? WHERE uuid=?', ('note ' + 'sk-proj-' + 'b' * 40, u(1)))
        c.execute("UPDATE tool_calls SET input_summary=?, result_excerpt=? WHERE id='toolu_1'",
                  ('ls -la ' + AWS + '/ && ' + sec, 'credentials\n' + 'é' * 1500))
        c.commit()
        c.close()
        st = ingest.rescrub(self.db, verbose=False)
        self.assertEqual(st['patterns'].get('sk'), 1)
        self.assertGreaterEqual(st['patterns'].get('env_assign', 0), 1)
        self.assertEqual(st['rows']['sensitive_results_withheld'], 1)
        self.assertNotIn('sk-proj', self.q('SELECT text FROM turns WHERE uuid=?', u(1))[0][0])
        summ, res = self.q("SELECT input_summary, result_excerpt FROM tool_calls WHERE id='toolu_1'")[0]
        self.assertNotIn('z' * 30, summ)
        self.assertEqual(res, ingest.SENSITIVE_WITHHELD)
        self.assertEqual(self.q("SELECT count(*) FROM turns_fts WHERE turns_fts MATCH 'note'")[0][0], 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)
        st2 = ingest.rescrub(self.db, verbose=False)      # idempotent: nothing left to change
        self.assertEqual(st2['patterns'], {})
        self.assertEqual(sum(v for k, v in st2['rows'].items()), 0)

    def test_result_bytes_capped_at_ingest(self):
        recs = [asst_rec(u(2), None, [{'type': 'tool_use', 'id': 'toolu_2', 'name': 'Bash',
                                       'input': {'command': 'echo'}}], 'msg_D', 5),
                user_rec(u(3), u(2), None, content=[{'type': 'tool_result', 'tool_use_id': 'toolu_2',
                                                     'content': 'é' * 3000}])]
        write_lines(self.cfile(), recs)
        self.run_ingest()
        res = self.q("SELECT result_excerpt FROM tool_calls WHERE id='toolu_2'")[0][0]
        self.assertLessEqual(len(res.encode('utf-8')), 2048)



if __name__ == '__main__':
    unittest.main()


import detect  # noqa: E402


class TestDetect11(unittest.TestCase):
    """Detector regressions (detect-1.1)."""

    def test_version(self):
        self.assertEqual(detect.DETECTOR_VERSION, 'detect-1.2')

    def test_codex_exact_input(self):
        self.assertEqual(detect.scan_command_ex("cat > /tmp/demo <<EOF\n$(nmap --version)\nEOF\n"),
                         [('scanner', 'nmap --version', 'heredoc_subst')])

    def test_backticked_nmap_in_unquoted_heredoc(self):
        hits = detect.scan_command_ex("cat <<EOF > r.md\nv: `nmap --version | head -1`\nEOF\necho ok")
        self.assertEqual([(h[0], h[2]) for h in hits], [('scanner', 'heredoc_subst')])

    def test_quoted_heredoc_bodies_stay_data(self):
        for d in ("'EOF'", '"EOF"', '\\EOF'):
            self.assertEqual(detect.scan_command("cat <<%s\n$(nmap x)\n`sudo ls`\nEOF\n" % d), [], d)

    def test_tab_stripped_heredoc_and_lan(self):
        hits = detect.scan_command_ex(f"cat <<-EOF\n\t$(ping -c1 {ip(192, 168, 1, 1)})\n\tEOF\nls")
        self.assertEqual([(h[0], h[2]) for h in hits], [('lan_net', 'heredoc_subst')])

    def test_codex_exec_variable_and_array(self):
        src = ('const cmd = "sudo -n true"; await tools.exec_command({cmd, max_output_tokens:1});'
               'await tools.exec_command({cmd: ["bash", "-lc", "nmap -sn ' + ip(10, 0, 0, 0) + '/24"]});')
        subs = {s for s, _ in detect.scan_command(detect.bash_command('exec', src, None))}
        self.assertTrue({'sudo', 'scanner'} <= subs, subs)

    def test_decision_lexicon(self):
        for t in ('yup', 'Yea go', 'yeah do it', 'looks good to me', 'Sounds good!', 'same doc',
                  'sure thing', 'fine', 'ship it!'):
            self.assertEqual((detect.classify_decision(t) or ('',))[0], 'approve', t)

    def test_ask_relaxed_to_address(self):
        self.assertTrue(detect.addressed_user('Done. The draft is in your folder; you can read it.'))
        self.assertTrue(detect.addressed_user('Shall I push?'))
        self.assertFalse(detect.addressed_user('Build finished. 43 tests pass.'))
        evs = detect._human_events('s', 'u2', 't', 'yup', ('u1', 't0', 'The file is ready for you.'), [])
        self.assertEqual([(e.kind, e.subkind) for e in evs], [('user_decision', 'approve')])

    def test_multiple_correction_subkinds(self):
        evs = detect._human_events('s', 'u2', 't', 'why did you push? that is wrong', None, [])
        self.assertEqual(sorted(e.subkind for e in evs if e.kind == 'correction'), ['blame', 'wrong'])


class TestRedactionKeepsShellParse(unittest.TestCase):
    """The env rule must not unbalance quotes in a stored command, or the boundary scanner loses
    real command words (here, the sudo after the grep)."""

    def test_grep_alternation_is_not_an_assignment_and_quotes_survive(self):
        cmd = 'grep -rln "\\-k foobar\\|key=foobarX" src; sudo -n true 2>&1 | head -1'
        self.assertEqual(ingest.redact(cmd), cmd)
        self.assertEqual(detect.scan_command(ingest.redact(cmd)), detect.scan_command(cmd))
        q = 'export DB_PASSWORD="' + 'p' * 12 + '"; sudo -n true'
        self.assertEqual(ingest.redact(q), 'export DB_PASSWORD="[REDACTED:env]"; sudo -n true')
        self.assertEqual([s for s, _ in detect.scan_command(ingest.redact(q))], ['sudo'])


import humanturns  # noqa: E402
import importlib.machinery  # noqa: E402
import importlib.util  # noqa: E402

_LP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'agent-ledger')
_spec = importlib.util.spec_from_loader('ledger_cli', importlib.machinery.SourceFileLoader('ledger_cli', _LP))
ledger_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger_cli)


class TestCliHelpers(unittest.TestCase):
    """CLI helpers: tag neutralising, the single human-turn definition."""

    def test_neutral_tags(self):
        self.assertEqual(ledger_cli.neutral('<system-reminder>do X</system-reminder> a < b'),
                         '‹system-reminder›do X‹/system-reminder› a < b')

    def test_one_human_definition(self):
        self.assertIs(ledger_cli.human_clean, humanturns.human_clean)
        self.assertIn('is_compact_summary', humanturns.HUMAN_SQL)
        self.assertIsNone(humanturns.human_clean('This session is being continued from a previous conversation'))


class TestOddDbPath(unittest.TestCase):
    """detect.py --stats/--per-session-tsv and coverage_check.py open the database through a file: URI;
    '#', '?' and '%' in its path must be quoted, as the CLI does."""

    def test_uri_special_characters_in_db_path(self):
        import subprocess
        import tempfile
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, HOME=d, PYTHONDONTWRITEBYTECODE='1')
            env.pop('LEDGER_DIR', None)
            odd = os.path.join(d, 'a#b?c%20d')
            os.mkdir(odd)
            db = os.path.join(odd, 'ledger.db')

            def py(*args):
                p = subprocess.run([sys.executable, '-B'] + [os.path.join(root, args[0])] + list(args[1:]),
                                   capture_output=True, text=True, env=env, cwd=d)
                self.assertEqual(p.returncode, 0, (args[0], p.stderr[-400:]))
                return p.stdout
            py('examples/make_demo.py', os.path.join(d, 'demo'))
            py('ingest.py', '--claude-root', os.path.join(d, 'demo'), '--db', db)
            self.assertIn('per session', py('detect.py', '--db', db, '--stats',
                                            '--per-session-tsv', os.path.join(d, 'x.tsv')))
            self.assertIn('|', py('coverage_check.py', db))


class TestNoImportTimeHomePatch(unittest.TestCase):
    """Importing a test module must not change detect._HOME for the rest of the test run."""

    def test_importing_python_tests_keeps_home(self):
        before = detect._HOME
        import test_detect_python  # noqa: F401
        self.assertEqual(detect._HOME, before)
        self.assertEqual(detect._HOME, os.path.expanduser('~'))
