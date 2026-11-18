#!/usr/bin/env python3
"""Coverage check: grep-counted user/assistant lines per Claude file vs rows inserted by ingest.py,
and message records per Codex thread vs rows. Prints a Markdown table; MISMATCH rows need a look.
Usage: coverage_check.py [db]   (read-only; counts the first byte_offset bytes of each file, so growing
files compare fairly; needs `head`, `grep` and, for Codex, `zstd` on PATH)"""
import os, shutil, sqlite3, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402
from urllib.parse import quote  # noqa: E402
db = sys.argv[1] if len(sys.argv) > 1 else paths.default_db()
c = sqlite3.connect('file:%s?mode=ro' % quote(db), uri=True)

def gcount(path, off, pat):
    p1 = subprocess.Popen(['head', '-c', str(off), path], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['grep', '-c', pat, '-'], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    out = p2.communicate()[0].decode().strip()
    return int(out or 0)

rows = c.execute("SELECT path, byte_offset, dup_skipped FROM ingest_files WHERE source='claude' ORDER BY path").fetchall()
tot = dict(gu=0, ga=0, ru=0, ra=0, dup=0)
import json, re
AG = re.compile(r'/subagents/agent-([^/]+)\.jsonl$')


def turns_rows(path, typ):
    """rows in `turns` attributable to this file (session from the name, agent_id from subagents/agent-<id>)
    -- compare with the turns table itself, not only the ingester's own counters."""
    m = AG.search(path)
    sid = os.path.basename(os.path.dirname(os.path.dirname(path))) if m else os.path.basename(path)[:-6]
    if m:
        return c.execute("SELECT count(*) FROM turns WHERE session_id=? AND agent_id=? AND type=?", (sid, m.group(1), typ)).fetchone()[0]
    return c.execute("SELECT count(*) FROM turns WHERE session_id=? AND agent_id IS NULL AND type=?", (sid, typ)).fetchone()[0]


print('| file | grep user | rows user | turns user | grep asst | rows asst | turns asst | dup-skipped | verdict |')
print('|---|---|---|---|---|---|---|---|---|')
bad = 0
for path, off, dup in rows:
    gu = gcount(path, off, '"type":"user"')
    ga = gcount(path, off, '"type":"assistant"')
    r = dict(c.execute("SELECT type, rows_inserted FROM ingest_type_counts WHERE path=? AND type IN ('user','assistant')", (path,)).fetchall())
    lines_ = dict(c.execute("SELECT type, lines FROM ingest_type_counts WHERE path=? AND type IN ('user','assistant')", (path,)).fetchall())
    ru, ra = r.get('user', 0), r.get('assistant', 0)
    lu, la = lines_.get('user', 0), lines_.get('assistant', 0)
    ok = (gu == lu and ga == la)                    # grep == parsed records per type
    exact = (gu == ru and ga == ra)
    verdict = 'OK' if exact else ('OK (parsed==grep; rows short by same-session dup records)' if ok and dup else 'MISMATCH')
    if not ok:
        bad += 1
    tu_, ta_ = turns_rows(path, 'user'), turns_rows(path, 'assistant')
    print('| %s | %d | %d | %d | %d | %d | %d | %d | %s |' % (os.path.relpath(path, os.path.expanduser('~')), gu, ru, tu_, ga, ra, ta_, dup, verdict))
    tot['gu'] += gu; tot['ga'] += ga; tot['ru'] += ru; tot['ra'] += ra; tot['dup'] += dup
print('| TOTAL | %(gu)d | %(ru)d | | %(ga)d | %(ra)d | | %(dup)d | |' % tot)
print('\n(turns user/asst = rows in the turns table for that file\'s session+agent_id, forked copies included; an archived'
      ' copy of a live file shows the live file\'s rows.)')
tu = c.execute("SELECT count(*) FROM turns WHERE type='user' AND session_id IN (SELECT session_id FROM sessions WHERE source='claude')").fetchone()[0]
ta = c.execute("SELECT count(*) FROM turns WHERE type='assistant' AND session_id IN (SELECT session_id FROM sessions WHERE source='claude')").fetchone()[0]
uu = c.execute("SELECT count(*) FROM turns WHERE type='user' AND forked_copy=0 AND session_id IN (SELECT session_id FROM sessions WHERE source='claude')").fetchone()[0]
ua = c.execute("SELECT count(*) FROM turns WHERE type='assistant' AND forked_copy=0 AND session_id IN (SELECT session_id FROM sessions WHERE source='claude')").fetchone()[0]
print('\nturns table (claude): user=%d assistant=%d | unique (forked_copy=0): user=%d assistant=%d | files with grep!=parsed: %d' % (tu, ta, uu, ua, bad))


# ---- Codex: per thread, user/assistant message records in the rollouts vs rows in turns
print('\n## Codex rollouts: response_item/message user+assistant records vs turns rows, per thread\n')
print('| thread | files | records user | turns user | records asst | turns asst | dup-skipped | verdict |')
print('|---|---|---|---|---|---|---|---|')
by = {}
ZSTD = shutil.which('zstd')
for path, off, dup in (c.execute("SELECT path, byte_offset, dup_skipped FROM ingest_files WHERE source='codex' ORDER BY path")
                       if ZSTD else []):
    p1 = subprocess.Popen([ZSTD, '-dc', '-q', path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = p1.stdout.read(off)
    p1.stdout.close(); p1.wait()
    tid, cu, ca = None, 0, 0
    for line in data.splitlines():
        if b'"session_meta"' in line[:80] and tid is None:
            try:
                tid = json.loads(line)['payload']['id']
            except Exception:
                pass
        if b'"response_item"' not in line or b'"message"' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        pl = r.get('payload') or {}
        if r.get('type') == 'response_item' and pl.get('type') == 'message':
            if pl.get('role') == 'user':
                cu += 1
            elif pl.get('role') == 'assistant':
                ca += 1
    b = by.setdefault(tid, [0, 0, 0, 0])
    b[0] += 1; b[1] += cu; b[2] += ca; b[3] += dup
cbad = 0
for tid, (nf, cu, ca, dup) in sorted(by.items(), key=lambda kv: str(kv[0])):
    tu_ = c.execute("SELECT count(*) FROM turns WHERE session_id=? AND type='user'", (tid,)).fetchone()[0]
    ta_ = c.execute("SELECT count(*) FROM turns WHERE session_id=? AND type='assistant'", (tid,)).fetchone()[0]
    v = 'OK' if (tu_, ta_) == (cu, ca) else 'MISMATCH'
    cbad += v != 'OK'
    print('| %s | %d | %d | %d | %d | %d | %d | %s |' % (tid, nf, cu, tu_, ca, ta_, dup, v))
print('\nCodex threads: %d, mismatches: %d' % (len(by), cbad))
