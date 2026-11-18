"""Unit tests for ingest.py. Fixtures are synthesized here; no real transcript lines are used.
Run from the repository root: python3 -m unittest discover -s tests -v"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ingest  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import AWS, GCLOUD, PEM_BEGIN, PEM_END, SSH, ip  # noqa: E402,F401

SID = '11111111-1111-4111-8111-111111111111'
SID2 = '22222222-2222-4222-8222-222222222222'


def u(n):
    return '00000000-0000-4000-8000-%012d' % n


def user_rec(uuid, parent, text, sid=SID, ts='2026-10-20T10:00:00.000Z', content=None, **extra):
    r = {'parentUuid': parent, 'isSidechain': False, 'type': 'user', 'uuid': uuid, 'timestamp': ts,
         'cwd': '/w', 'sessionId': sid, 'version': '1.0', 'gitBranch': 'main',
         'message': {'role': 'user', 'content': content if content is not None else text}}
    r.update(extra)
    return r


def asst_rec(uuid, parent, blocks, msg_id, out, sid=SID, ts='2026-10-20T10:00:01.000Z', model='claude-x'):
    return {'parentUuid': parent, 'isSidechain': False, 'type': 'assistant', 'uuid': uuid, 'timestamp': ts,
            'cwd': '/w', 'sessionId': sid, 'version': '1.0', 'gitBranch': 'main', 'requestedModel': model,
            'message': {'id': msg_id, 'role': 'assistant', 'model': model, 'content': blocks, 'stop_reason': 'tool_use',
                        'usage': {'input_tokens': 2, 'output_tokens': out, 'cache_creation_input_tokens': 100,
                                  'cache_read_input_tokens': 1000,
                                  'output_tokens_details': {'thinking_tokens': 5}}}}


def write_lines(path, recs, mode='w', newline_end=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as f:
        for i, r in enumerate(recs):
            s = r if isinstance(r, str) else json.dumps(r)
            f.write(s + ('\n' if (newline_end or i < len(recs) - 1) else ''))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.old = (ingest.CLAUDE_ROOT, ingest.ARCHIVE_ROOT, ingest.CODEX_ROOT, ingest.CODEX_INDEX)
        ingest.CLAUDE_ROOT = os.path.join(t, 'claude')
        ingest.ARCHIVE_ROOT = os.path.join(t, 'archive')
        ingest.CODEX_ROOT = os.path.join(t, 'codex')
        ingest.CODEX_INDEX = os.path.join(t, 'index.jsonl')
        os.makedirs(ingest.ARCHIVE_ROOT)
        os.makedirs(ingest.CODEX_ROOT)
        self.db = os.path.join(t, 'test.db')
        ingest.RED_COUNTS.clear()

    def tearDown(self):
        ingest.CLAUDE_ROOT, ingest.ARCHIVE_ROOT, ingest.CODEX_ROOT, ingest.CODEX_INDEX = self.old
        self.tmp.cleanup()

    def cfile(self, name='proj-a/%s.jsonl' % SID):
        return os.path.join(ingest.CLAUDE_ROOT, name)

    def run_ingest(self):
        return ingest.run(self.db, ingest.discover(), verbose=False)

    def q(self, sql, *a):
        c = sqlite3.connect(self.db)
        try:
            return c.execute(sql, a).fetchall()
        finally:
            c.close()


class TestRedaction(unittest.TestCase):
    def setUp(self):
        ingest.RED_COUNTS.clear()

    def test_each_pattern(self):
        # synthetic, assembled at runtime so no secret-shaped literal sits in this file
        cases = {
            'sk-ant': 'key sk-ant-' + 'a1B2_' * 6,
            'ghp': 'tok ghp_' + 'A1' * 20,
            'github_pat': 'pat github_pat_' + 'Zz9_' * 10,
            'akia': 'aws AKIA' + 'ABCDEFGH12345678',
            'slack': 'xoxb-' + '1234567890-abcdef',
            'bearer': 'Authorization: Bearer ' + 'abcDEF0123456789.-_~+/xyz',
            'discord': 'M' + 'A' * 23 + '.' + 'abc_-1' + '.' + 'x' * 27,
            'privkey': PEM_BEGIN % 'RSA ' + '\nMIIBOgIBAAJB\nabc\n' + PEM_END % 'RSA ',
        }
        for kind, s in cases.items():
            out = ingest.redact('before ' + s + ' after')
            self.assertIn('[REDACTED:%s]' % kind, out, kind)
            self.assertTrue(out.startswith('before ') and out.endswith(' after'), kind)
        self.assertEqual(sorted(ingest.RED_COUNTS), sorted(cases))
        self.assertTrue(all(v == 1 for v in ingest.RED_COUNTS.values()))

    def test_private_key_without_end_is_cut(self):
        out = ingest.redact('x ' + PEM_BEGIN % '' + '\nAAAA\nBBBB')
        self.assertEqual(out, 'x [REDACTED:privkey]')

    def test_env_lines_only_when_requested(self):
        kv = 'API_' + 'TOKEN=' + 'abcdefghijklmnop'
        text = 'PATH_X=short\n' + kv + '\nlower=abcdefghijklmnop\nHOME_DIR=/home/user/long/path'
        # a secret-NAMED assignment is redacted everywhere now; other lines only with env=True
        self.assertEqual(ingest.redact(text), text.replace(kv, 'API_' + 'TOKEN=[REDACTED:env]'))
        out = ingest.redact(text, env=True)
        self.assertIn('API_TOKEN=[REDACTED:env]', out)
        self.assertIn('HOME_DIR=[REDACTED:env]', out)
        self.assertIn('PATH_X=short', out)           # value < 12 chars
        self.assertIn('lower=abcdefghijklmnop', out)  # key not upper-case
        self.assertEqual(ingest.RED_COUNTS['env'], 1)
        self.assertEqual(ingest.RED_COUNTS['env_assign'], 2)

    def test_no_false_positive(self):
        s = 'bearer token handling in sk-ant style docs, ghp_ short, AKIA short'
        self.assertEqual(ingest.redact(s), s)

    def test_cut_never_splits_a_secret(self):
        s = 'x' * 95 + 'ghp_' + 'A' * 36 + ' tail'
        out = ingest.red_cut(s, 100, marker=False)
        self.assertNotIn('ghp_A', out)
        self.assertNotIn('AAAA', out)
        self.assertIn('[REDA', out)

    def test_red_json_truncates_long_strings(self):
        o = ingest.red_json({'a': 'y' * 9000, 'b': [1, 'ok'], 'c': {'d': 'ghp_' + 'Q' * 36}})
        self.assertLess(len(o['a']), 8300)
        self.assertIn('truncated', o['a'])
        self.assertEqual(o['b'], [1, 'ok'])
        self.assertEqual(o['c']['d'], '[REDACTED:ghp]')


class TestClaude(Base):
    def basic(self):
        secret = 'ghp_' + 'B2' * 20
        return [
            {'type': 'permission-mode', 'permissionMode': 'auto', 'sessionId': SID},
            {'type': 'ai-title', 'aiTitle': 'My title', 'sessionId': SID},
            {'type': 'queue-operation', 'operation': 'enqueue', 'sessionId': SID},
            {'type': 'mode', 'mode': 'normal', 'sessionId': SID},
            {'parentUuid': None, 'isSidechain': False, 'attachment': {'type': 'x', 'content': 'big'}, 'type': 'attachment',
             'uuid': u(99), 'timestamp': '2026-10-20T09:59:00.000Z', 'sessionId': SID},
            user_rec(u(1), None, 'hello world find-me-in-fts'),
            asst_rec(u(2), u(1), [{'type': 'thinking', 'thinking': '', 'signature': 'abc'}], 'msg_A', 3),
            asst_rec(u(3), u(1), [{'type': 'text', 'text': 'running it'}], 'msg_A', 3),
            asst_rec(u(4), u(1), [{'type': 'tool_use', 'id': 'toolu_1', 'name': 'Bash',
                                   'input': {'command': 'echo ' + secret, 'description': 'd'}}], 'msg_A', 50),
            user_rec(u(5), u(4), None, content=[{'type': 'tool_result', 'tool_use_id': 'toolu_1',
                                                 'content': 'out\nAPI_' + 'TOKEN=' + 'abcdefghijklmnopqrst\nok', 'is_error': False}],
                     toolUseResult={'x': 1}),
            asst_rec(u(6), u(5), [{'type': 'tool_use', 'id': 'toolu_2', 'name': 'Read', 'input': {'file_path': '/a/b.txt'}}],
                     'msg_B', 10),
            user_rec(u(7), u(6), None, content=[{'type': 'tool_result', 'tool_use_id': 'toolu_2',
                                                 'content': [{'type': 'text', 'text': 'denied!'}], 'is_error': True}],
                     toolDenialKind='user-rejected'),
            {'type': 'system', 'subtype': 'turn_duration', 'uuid': u(8), 'parentUuid': u(7), 'timestamp': '2026-10-20T10:00:05.000Z',
             'sessionId': SID, 'isSidechain': False, 'cwd': '/w', 'durationMs': 5},
        ]

    def test_ingest_basics(self):
        write_lines(self.cfile(), self.basic())
        self.run_ingest()
        types = dict(self.q('SELECT type, count(*) FROM turns GROUP BY 1'))
        self.assertEqual(types, {'user': 3, 'assistant': 4, 'system': 1, 'permission-mode': 1})
        # skipped types are only counted in ingest_files.lines
        self.assertEqual(self.q('SELECT lines FROM ingest_files')[0][0], 13)
        tl = dict(self.q('SELECT type, lines FROM ingest_type_counts'))
        self.assertEqual((tl['attachment'], tl['queue-operation'], tl['mode']), (1, 1, 1))
        # system / permission-mode rows have NULL text
        self.assertEqual(self.q("SELECT count(*) FROM turns WHERE type IN ('system','permission-mode') AND text IS NOT NULL")[0][0], 0)
        # tool_result placeholder
        self.assertEqual(self.q('SELECT text FROM turns WHERE uuid=?', u(5))[0][0], '[tool_result]')
        # title
        self.assertEqual(self.q('SELECT thread_name, n_user, n_assistant, archived FROM sessions')[0], ('My title', 3, 4, 0))

    def test_tool_result_pairing_redaction_and_denial(self):
        write_lines(self.cfile(), self.basic())
        self.run_ingest()
        rows = {r[0]: r for r in self.q('SELECT id, name, input_summary, result_excerpt, result_chars, is_error, denied, denied_kind FROM tool_calls')}
        t1, t2 = rows['toolu_1'], rows['toolu_2']
        self.assertIn('[REDACTED:ghp]', t1[2])
        self.assertNotIn('ghp_', t1[2])
        self.assertIn('API_TOKEN=[REDACTED:env]', t1[3])
        self.assertEqual((t1[5], t1[6]), (0, 0))
        self.assertEqual(t2[2], '/a/b.txt')
        self.assertEqual((t2[3], t2[5], t2[6], t2[7]), ('denied!', 1, 1, 'user-rejected'))
        self.assertEqual(self.q("SELECT count(*) FROM tool_calls WHERE instr(input_json, 'ghp_')>0")[0][0], 0)

    def test_usage_counted_once_per_message_using_max_output(self):
        write_lines(self.cfile(), self.basic())
        self.run_ingest()
        # msg_A: blocks with output 3,3,50 -> exactly one row holds the usage, with 50
        rows = self.q("SELECT uuid, output_tokens, cache_write_tokens, thinking_tokens FROM turns WHERE msg_id='msg_A'")
        self.assertEqual(sorted(r[1] for r in rows if r[1] is not None), [50])
        self.assertEqual(self.q("SELECT sum(output_tokens), count(output_tokens) FROM turns")[0], (60, 2))
        self.assertEqual(self.q("SELECT sum(cache_write_tokens) FROM turns")[0][0], 200)

    def test_idempotent_rerun_and_growth(self):
        recs = self.basic()
        write_lines(self.cfile(), recs[:10])           # up to the assistant tool_use for toolu_2 not yet present
        self.run_ingest()
        n1 = self.q('SELECT count(*) FROM turns')[0][0]
        m1 = self.run_ingest()                          # unchanged file
        self.assertEqual((m1['turns'], m1['tools'], m1['lines']), (0, 0, 0))
        self.assertEqual(self.q('SELECT count(*) FROM turns')[0][0], n1)
        # file grows: the tool_use for toolu_2 is in a later chunk than its result
        write_lines(self.cfile(), recs[10:], mode='a')
        m2 = self.run_ingest()
        self.assertEqual(m2['dups'], 0)
        self.assertEqual(m2['lines'], 3)
        self.assertEqual(self.q("SELECT denied FROM tool_calls WHERE id='toolu_2'")[0][0], 1)
        # whole-file totals equal a fresh ingest of the final file
        a = self.q('SELECT count(*), count(output_tokens), sum(output_tokens) FROM turns')[0]
        os.remove(self.db)
        for e in ('-wal', '-shm'):
            if os.path.exists(self.db + e):
                os.remove(self.db + e)
        self.run_ingest()
        self.assertEqual(self.q('SELECT count(*), count(output_tokens), sum(output_tokens) FROM turns')[0], a)
        m3 = self.run_ingest()
        self.assertEqual((m3['turns'], m3['tools']), (0, 0))

    def test_result_in_later_run_pairs_with_earlier_tool_call(self):
        recs = self.basic()
        write_lines(self.cfile(), recs[:9])             # ... assistant tool_use toolu_1 (idx 8) ; result at idx 9
        self.run_ingest()
        self.assertIsNone(self.q("SELECT result_chars FROM tool_calls WHERE id='toolu_1'")[0][0])
        write_lines(self.cfile(), recs[9:], mode='a')
        self.run_ingest()
        self.assertIsNotNone(self.q("SELECT result_chars FROM tool_calls WHERE id='toolu_1'")[0][0])
        # FTS follows the UPDATE
        self.assertEqual(self.q("SELECT count(*) FROM tools_fts WHERE tools_fts MATCH 'ok'")[0][0] >= 1, True)

    def test_partial_trailing_line_is_left_for_next_run(self):
        recs = self.basic()
        write_lines(self.cfile(), recs[:6])
        with open(self.cfile(), 'a') as f:
            f.write(json.dumps(recs[6])[:40])           # half a record, no newline
        self.run_ingest()
        self.assertEqual(self.q('SELECT count(*) FROM turns WHERE type=?', 'assistant')[0][0], 0)
        with open(self.cfile(), 'a') as f:
            f.write(json.dumps(recs[6])[40:] + '\n')
        self.run_ingest()
        self.assertEqual(self.q('SELECT count(*) FROM turns WHERE type=?', 'assistant')[0][0], 1)

    def test_fts_and_db_mode(self):
        write_lines(self.cfile(), self.basic())
        self.run_ingest()
        self.assertEqual(self.q("SELECT count(*) FROM turns_fts WHERE turns_fts MATCH 'find'")[0][0], 1)
        self.assertEqual(oct(os.stat(self.db).st_mode & 0o777), '0o600')

    def test_fork_copy_and_archive_duplicate(self):
        parent = [user_rec(u(1), None, 'p1', ts='2026-10-20T10:00:00.000Z'),
                  asst_rec(u(2), u(1), [{'type': 'text', 'text': 'p2'}], 'msg_P', 7, ts='2026-10-20T10:00:01.000Z'),
                  user_rec(u(3), u(2), 'p3', ts='2026-10-20T10:05:00.000Z')]
        fork = [user_rec(u(1), None, 'p1', sid=SID2, ts='2026-10-20T10:00:00.000Z'),
                asst_rec(u(2), u(1), [{'type': 'text', 'text': 'p2'}], 'msg_P', 7, sid=SID2, ts='2026-10-20T10:00:01.000Z'),
                user_rec(u(10), u(2), 'native', sid=SID2, ts='2026-10-20T11:00:00.000Z')]
        # file order puts the fork first alphabetically: ownership must still go to the parent session
        write_lines(self.cfile('proj-a/%s.jsonl' % SID2), fork)
        write_lines(self.cfile('proj-a/%s.jsonl' % SID), parent)
        # archived copy of the parent session (same session id) must not add rows
        write_lines(os.path.join(ingest.ARCHIVE_ROOT, 'x-%s.jsonl' % SID), parent)
        self.run_ingest()
        rows = self.q('SELECT uuid, session_id, forked_copy, orig_uuid, output_tokens FROM turns ORDER BY ts, session_id')
        self.assertEqual(len(rows), 3 + 3)               # 3 parent + 2 copies + 1 native fork
        copies = [r for r in rows if r[2] == 1]
        self.assertEqual(len(copies), 2)
        self.assertTrue(all(r[1] == SID2 and r[0] == r[3] + '@' + SID2 for r in copies))
        self.assertEqual(self.q('SELECT sum(output_tokens) FROM turns')[0][0], 7)   # usage counted once
        s = dict((r[0], r[1:]) for r in self.q('SELECT session_id, n_user, n_assistant, n_copied, forked_from FROM sessions'))
        self.assertEqual(s[SID], (2, 1, 0, None))
        self.assertEqual(s[SID2], (1, 0, 2, SID))        # native only
        # archived duplicate was skipped, archived flag stays 0 (a live copy exists)
        self.assertEqual(self.q('SELECT sum(dup_skipped) FROM ingest_files')[0][0], 3)
        self.assertEqual(self.q('SELECT archived FROM sessions WHERE session_id=?', SID)[0][0], 0)
        m = self.run_ingest()
        self.assertEqual((m['turns'], m['tools']), (0, 0))

    def test_subagent_file_gets_agent_id(self):
        sub = os.path.join(ingest.CLAUDE_ROOT, 'proj-a', SID, 'subagents', 'agent-abc123.jsonl')
        r = user_rec(u(1), None, 'sub task')
        r['isSidechain'] = True
        write_lines(sub, [r])
        self.run_ingest()
        self.assertEqual(self.q('SELECT is_sidechain, agent_id, session_id FROM turns')[0], (1, 'abc123', SID))


class TestCodex(Base):
    def zst(self, path, recs):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        raw = ''.join(json.dumps(r) + '\n' for r in recs).encode()
        out = subprocess.run([ingest.ZSTD, '-q', '-c'], input=raw, stdout=subprocess.PIPE, check=True).stdout
        with open(path, 'wb') as f:
            f.write(out)

    def recs(self):
        T = '019aaaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee'
        return T, [
            {'timestamp': '2026-10-17T10:00:00.000Z', 'ordinal': 0, 'type': 'session_meta',
             'payload': {'id': T, 'cwd': '/w', 'parent_thread_id': None, 'thread_source': 'user'}},
            {'timestamp': '2026-10-17T10:00:01.000Z', 'ordinal': 1, 'type': 'turn_context', 'payload': {'model': 'gpt-x', 'cwd': '/w'}},
            {'timestamp': '2026-10-17T10:00:02.000Z', 'ordinal': 2, 'type': 'response_item',
             'payload': {'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': 'please list files'}]}},
            {'timestamp': '2026-10-17T10:00:03.000Z', 'ordinal': 3, 'type': 'response_item',
             'payload': {'type': 'custom_tool_call', 'call_id': 'call_1', 'name': 'exec', 'input': 'tools.exec_command({cmd:"ls"})'}},
            {'timestamp': '2026-10-17T10:00:04.000Z', 'ordinal': 4, 'type': 'response_item',
             'payload': {'type': 'custom_tool_call_output', 'call_id': 'call_1',
                         'output': [{'type': 'input_text', 'text': '{"exit_code":2,"output":"boom ghp_' + 'C3' * 20 + '"}'}]}},
            {'timestamp': '2026-10-17T10:00:05.000Z', 'ordinal': 5, 'type': 'token_usage_record',
             'payload': {'response_id': 'resp_1', 'usage': {'input_tokens': 100, 'cached_input_tokens': 60, 'output_tokens': 20,
                                                           'reasoning_output_tokens': 8, 'cache_write_input_tokens': 0}}},
            {'timestamp': '2026-10-17T10:00:06.000Z', 'ordinal': 6, 'type': 'response_item',
             'payload': {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'done'}]}},
            {'timestamp': '2026-10-17T10:00:07.000Z', 'ordinal': 7, 'type': 'event_msg', 'payload': {'type': 'token_count', 'info': {}}},
        ]

    def test_codex_mapping_incremental(self):
        T, recs = self.recs()
        path = os.path.join(ingest.CODEX_ROOT, '2026', '10', '17', 'rollout-x-%s.jsonl.zst' % T)
        self.zst(path, recs[:5])
        with open(ingest.CODEX_INDEX, 'w') as f:
            f.write(json.dumps({'id': T, 'thread_name': 'A thread', 'updated_at': '2026-10-17T10:00:00Z'}) + '\n')
        self.run_ingest()
        self.zst(path, recs)                              # file "grew": recompressed with more records
        m = self.run_ingest()
        self.assertEqual(m['dups'], 0)
        self.assertEqual(dict(self.q('SELECT type, count(*) FROM turns GROUP BY 1')),
                         {'user': 1, 'tool_call': 1, 'token_usage': 1, 'assistant': 1})
        tool = self.q('SELECT name, is_error, result_chars, result_excerpt FROM tool_calls')[0]
        self.assertEqual((tool[0], tool[1]), ('exec', 1))
        self.assertIn('[REDACTED:ghp]', tool[3])
        tok = self.q("SELECT input_tokens, cache_read_tokens, output_tokens, thinking_tokens, model FROM turns WHERE type='token_usage'")[0]
        self.assertEqual(tok, (40, 60, 20, 8, 'gpt-x'))
        self.assertEqual(self.q('SELECT session_id, source, thread_name, n_user, n_assistant FROM sessions')[0],
                         (T, 'codex', 'A thread', 1, 1))
        m2 = self.run_ingest()
        self.assertEqual((m2['turns'], m2['tools']), (0, 0))


if __name__ == '__main__':
    unittest.main()
