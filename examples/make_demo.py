#!/usr/bin/env python3
"""Write a small, obviously synthetic Claude Code transcript tree for trying agent-ledger out.

    python3 examples/make_demo.py DEST_DIR

Creates DEST_DIR/-home-demo-projects-demo-app/<session>.jsonl with two sessions: one with a few
turns, tool calls, a denied command and a short approval; and a fork of it. Nothing here comes
from a real session.
"""
import json
import os
import sys

S1 = "de000001-0000-4000-8000-000000000001"
S2 = "de000002-0000-4000-8000-000000000002"
CWD = "/home/demo/projects/demo-app"


def rec(kind, uuid, parent, ts, sid=S1, **kw):
    r = {"parentUuid": parent, "isSidechain": False, "type": kind, "uuid": uuid, "timestamp": ts,
         "cwd": CWD, "sessionId": sid, "version": "0.0-demo", "gitBranch": "main"}
    r.update(kw)
    return r


def user(uuid, parent, ts, content, sid=S1, human=True, **kw):
    extra = {"origin": {"kind": "human"}} if human else {}
    extra.update(kw)
    return rec("user", uuid, parent, ts, sid, message={"role": "user", "content": content}, **extra)


def asst(uuid, parent, ts, blocks, msg_id, out, sid=S1, model="claude-demo-model"):
    return rec("assistant", uuid, parent, ts, sid, requestedModel=model,
               message={"id": msg_id, "role": "assistant", "model": model, "content": blocks,
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 12, "output_tokens": out, "cache_creation_input_tokens": 200,
                                  "cache_read_input_tokens": 3000}})


def u(n):
    return "00000000-0000-4000-8000-%012d" % n


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    dest = os.path.join(sys.argv[1], "-home-demo-projects-demo-app")
    os.makedirs(dest, exist_ok=True)
    day = "2026-01-15T"
    s1 = [
        {"type": "ai-title", "sessionId": S1, "aiTitle": "Add a CSV export to the demo app"},
        user(u(1), None, day + "09:00:00.000Z", "Please add a CSV export to the demo app and run the tests."),
        asst(u(2), u(1), day + "09:00:05.000Z", [{"type": "text", "text": "Reading the exporter first."},
                                                 {"type": "tool_use", "id": "toolu_demo_1", "name": "Read",
                                                  "input": {"file_path": CWD + "/export.py"}}], "msg_demo_1", 40),
        user(u(3), u(2), day + "09:00:06.000Z", [{"type": "tool_result", "tool_use_id": "toolu_demo_1",
                                                  "content": "def export(rows):\n    pass\n"}], human=False),
        asst(u(4), u(3), day + "09:01:00.000Z", [{"type": "tool_use", "id": "toolu_demo_2", "name": "Bash",
                                                  "input": {"command": "sudo apt-get install -y csvkit"}}],
             "msg_demo_2", 25),
        user(u(5), u(4), day + "09:01:02.000Z",
             [{"type": "tool_result", "tool_use_id": "toolu_demo_2", "is_error": True,
               "content": "The user doesn't want to proceed with this tool use. The tool use was rejected."}],
             human=False, toolDenialKind="user-rejected"),
        asst(u(6), u(5), day + "09:02:00.000Z", [{"type": "text", "text": (
            "I will use the standard csv module instead. I recommend writing the header row first. "
            "Shall I go ahead and run the test suite?")}], "msg_demo_3", 60),
        user(u(7), u(6), day + "09:03:00.000Z", "yes go ahead"),
        asst(u(8), u(7), day + "09:03:10.000Z", [{"type": "tool_use", "id": "toolu_demo_3", "name": "Bash",
                                                  "input": {"command": "cd " + CWD + " && python3 -m pytest -q"}}],
             "msg_demo_4", 30, model="claude-demo-model-2"),
        user(u(9), u(8), day + "09:03:20.000Z", [{"type": "tool_result", "tool_use_id": "toolu_demo_3",
                                                  "content": "3 passed in 0.12s"}], human=False),
    ]
    # S2: a fork of S1 (same history copied under a new sessionId), then one new exchange
    s2 = []
    for r in s1[1:4]:
        c = json.loads(json.dumps(r))
        c["sessionId"] = S2
        s2.append(c)
    s2 += [user(u(20), u(3), day + "11:00:00.000Z", "What does the export do with empty rows?", sid=S2),
           asst(u(21), u(20), day + "11:00:04.000Z", [{"type": "text", "text": "It skips them."}],
                "msg_demo_5", 8, sid=S2)]
    for sid, recs in ((S1, s1), (S2, s2)):
        with open(os.path.join(dest, sid + ".jsonl"), "w") as f:
            for r in recs:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")   # compact, as Claude Code writes
    print("wrote 2 synthetic sessions under %s" % dest)


if __name__ == "__main__":
    main()
