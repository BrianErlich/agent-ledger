"""detect-1.2: Python bodies that shell out are parsed with `ast` (never run) and their
literal commands fed to the boundary scanner. Synthetic fixtures only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detect  # noqa: E402
from test_detect import Base  # noqa: E402
from fixtures import AWS, GCLOUD, PEM_BEGIN, PEM_END, SSH, ip  # noqa: E402,F401

_SAVED_HOME = None


def setUpModule():
    """A fixed fake home so `~` paths resolve the same on every machine; restored after this module."""
    global _SAVED_HOME
    _SAVED_HOME = detect._HOME
    detect._HOME = "/home/user"


def tearDownModule():
    detect._HOME = _SAVED_HOME


def subs(cmd, **kw):
    return sorted((s, v) for s, _, v in detect.scan_command_ex(cmd, **kw))


class TestPythonPositives(unittest.TestCase):
    def test_subprocess_list_argv_sudo(self):
        cmd = "python3 -c 'import subprocess; subprocess.run([\"sudo\", \"-n\", \"true\"])'"
        self.assertEqual(detect.scan_command_ex(cmd), [("sudo", "sudo -n true", "python_subprocess")])

    def test_shell_true_string_nmap(self):
        cmd = f"python3 - <<'EOF'\nimport subprocess as sp\nsp.check_output('nmap -sn {ip(192, 168, 1, 0)}/24', shell=True)\nEOF"
        self.assertEqual(subs(cmd), [("scanner", "python_subprocess")])

    def test_os_system_reboot(self):
        self.assertEqual(subs("python3 -c 'import os; os.system(\"sleep 1; reboot\")'"),
                         [("reboot", "python_subprocess")])

    def test_nested_quotes_in_c(self):
        # double-quoted -c body with escaped inner double quotes and single quotes
        cmd = 'python3 -c "import subprocess; subprocess.call([\\"bash\\", \\"-c\\", \\"ls ' + AWS + '\\"]); print(\'x\')"'
        self.assertEqual(subs(cmd), [("credential_dir", "python_subprocess")])

    def test_heredoc_without_dash_and_from_import(self):
        cmd = ("cd /tmp && python3 <<EOF\nfrom subprocess import Popen as P\n"
               "P(['systemctl', 'restart', 'nginx'])\nEOF\n")
        self.assertEqual(subs(cmd), [("systemctl", "python_subprocess")])

    def test_exec_spawn_pty_asyncio_shlex(self):
        cases = {
            "import os\nos.execvp('sudo', ['sudo', 'id'])": "sudo",
            "import os\nos.execl('/sbin/shutdown', 'shutdown', '-h', 'now')": "shutdown",
            "import os\nos.spawnlp(os.P_WAIT, 'nmap', 'nmap', 'x')": "scanner",
            "import pty\npty.spawn(['su', '-'])": "su",
            "import asyncio\nasyncio.create_subprocess_exec('docker', 'ps')": "docker",
            f"import subprocess, shlex\nsubprocess.run(shlex.split('ssh {ip(10, 0, 0, 5)} uptime'))": "lan_net",
            "import subprocess\nC = ['sudo', 'ls']\nsubprocess.run(C)": "sudo",          # assigned once: literal
            f"import subprocess\nsubprocess.getoutput('cat {AWS}/x')": "credential_dir",
        }
        for code, want in cases.items():
            found, unres, status = detect.python_shellouts(code)
            self.assertEqual(status, "ok", code)
            got = {s for _, c, v in found if v == "python_subprocess" for s, _ in detect.scan_command(c)}
            self.assertEqual(got, {want}, code)

    def test_socket_literal_lan(self):
        cmd = "python3 -c 'import socket; s=socket.socket(); s.connect((\"" + ip(192, 168, 0, 10) + "\", 22))'"
        self.assertEqual(subs(cmd), [("lan_net", "python_socket")])
        cmd = "python3 -c 'import socket; socket.create_connection((\"box.tail1234" + ".ts.net\", 80))'"
        self.assertEqual(subs(cmd), [("tailnet_net", "python_socket")])

    def test_python_inside_subprocess_inside_python(self):
        inner = "import os; os.system('sudo true')"
        code = "import subprocess\nsubprocess.run(['python3', '-c', %r])" % inner
        self.assertEqual(subs("python3 - <<'EOF'\n%s\nEOF" % code), [("sudo", "python_subprocess")])

    def test_written_file_then_run(self):
        files = {"/home/user/projects/x/run.py": ("import os\nos.system('sudo -n true')\n", "toolu_w")}
        self.assertEqual(subs("python3 run.py", files=files, cwd="/home/user/projects/x"),
                         [("sudo", "python_file:/home/user/projects/x/run.py")])
        self.assertEqual(subs("python3 ~/projects/x/run.py --flag", files=files),
                         [("sudo", "python_file:/home/user/projects/x/run.py")])
        # a literal cd before the run moves the directory; a non-literal one makes it unknown (no link)
        self.assertEqual(subs("cd /elsewhere && python3 run.py", files=files, cwd="/home/user/projects/x"), [])
        self.assertEqual(subs("cd ~/projects/x && python3 run.py", files=files, cwd="/tmp"),
                         [("sudo", "python_file:/home/user/projects/x/run.py")])
        detect.PY_STATS.clear()
        self.assertEqual(subs('cd "$D" && python3 run.py', files=files, cwd="/home/user/projects/x"), [])
        self.assertEqual(detect.PY_STATS["script_path_unresolved"], 1)

    def test_shell_heredoc_write_is_tracked(self):
        self.assertEqual(detect.shell_file_writes("cat > /tmp/a.py <<'EOF'\nprint(1)\nEOF", None),
                         [("/tmp/a.py", "print(1)")])
        self.assertEqual(detect.shell_file_writes("tee b.py >/dev/null <<EOF\nx=1\nEOF", "/w"), [("/w/b.py", "x=1")])


class TestPythonNegatives(unittest.TestCase):
    def test_sudo_in_print_comment_docstring(self):
        code = ('"""Run sudo reboot to fix it; os.system(\'nmap\')."""\n# subprocess.run(["sudo", "ls"])\n'
                'print("sudo reboot")\nx = "nmap ' + ip(10, 0, 0, 1) + '"\n')
        self.assertEqual(subs("python3 - <<'EOF'\n%s\nEOF" % code), [])
        self.assertEqual(subs("python3 -c 'print(\"sudo\")'"), [])

    def test_variable_arg_is_unresolved_not_hit(self):
        code = ("import subprocess, os, sys\ncmd = sys.argv[1]\nsubprocess.run(cmd, shell=True)\n"
                "os.system(f'sudo {cmd}')\nfor c in ['a', 'b']:\n    subprocess.run(c)\n")
        found, unres, status = detect.python_shellouts(code)
        self.assertEqual(found, [])
        self.assertEqual(status, "ok")
        self.assertEqual(len(unres), 3, unres)
        detect.PY_STATS.clear()
        self.assertEqual(subs("python3 - <<'EOF'\n%s\nEOF" % code), [])
        self.assertEqual(detect.PY_STATS["unresolved"], 3)

    def test_reassigned_name_is_not_resolved(self):
        code = "import subprocess\nc = ['ls']\nc = ['sudo', 'ls']\nsubprocess.run(c)\n"
        found, unres, _ = detect.python_shellouts(code)
        self.assertEqual(found, [])
        self.assertEqual(unres, [("subprocess.run", "argv not literal")])

    def test_partial_argv_keeps_known_program(self):
        found, unres, _ = detect.python_shellouts("import subprocess, sys\nsubprocess.run(['git', 'log', sys.argv[1]])")
        self.assertEqual(len(found), 1)
        self.assertEqual(detect.scan_command(found[0][1]), [])
        self.assertEqual(len(unres), 1)

    def test_harmless_commands(self):
        code = ("import subprocess, os, socket, sqlite3\nsubprocess.run(['git', 'status'])\nos.system('ls -la')\n"
                "sqlite3.connect('x.db')\nsocket.create_connection(('127.0.0.1', 8080))\n"
                "subprocess.run(['systemctl', '--user', 'status', 'x'])\n")
        self.assertEqual(subs("python3 - <<'EOF'\n%s\nEOF" % code), [])

    def test_module_and_unknown_script_not_parsed(self):
        detect.PY_STATS.clear()
        self.assertEqual(subs("python3 -m pytest -q; python3 tool.py", cwd="/w", files={}), [])
        self.assertEqual(detect.PY_STATS["python_bodies"], 0)
        self.assertEqual(detect.PY_STATS["script_not_in_record"], 1)


class TestPythonParseFailure(unittest.TestCase):
    def test_truncated_body_partial_then_failed(self):
        code = "import os\nos.system('sudo id')\ndef f(:\n    pass\n[REDACTED:sk"
        found, _, status = detect.python_shellouts(code)
        self.assertEqual(status, "partial")
        self.assertEqual([c for _, c, _ in found], ["sudo id"])
        found, unres, status = detect.python_shellouts("def (:\n  ...[truncated 900 chars]")
        self.assertEqual((found, unres, status), ([], [], "failed"))

    def test_failure_does_not_crash_and_is_counted(self):
        detect.PY_STATS.clear()
        for bad in ("python3 -c 'if True print(1'", "python3 - <<'EOF'\n\x00bad\nEOF", "python3 -c"):
            self.assertEqual(subs(bad), [])
        self.assertEqual(detect.PY_STATS["parse_failed"], 2)
        self.assertEqual(detect.PY_STATS["python_bodies"], 2)
        deep = "python3 -c '" + "(" * 300 + "1" + ")" * 300 + "'"     # deep nesting: no crash
        self.assertEqual(subs(deep), [])


class TestPythonEndToEnd(Base):
    def test_write_edit_then_run_and_detail(self):
        p = "/home/user/projects/s/probe.py"
        self.tool("Write", p, input_json=json.dumps({"file_path": p, "content": "import os\nos.system('ls')\n"}))
        self.tool("Edit", p, input_json=json.dumps({"file_path": p, "old_string": "'ls'", "new_string": "'sudo ls'"}))
        self.bash("python3 /home/user/projects/s/probe.py")
        self.bash("python3 -c 'import subprocess; subprocess.run([\"nmap\", \"x\"])'")
        rows = self.run_detect()
        ba = [(r[1], r[5]) for r in rows if r[0] == "boundary_attempt"]
        self.assertEqual(sorted(s for s, _ in ba), ["scanner", "sudo"])
        self.assertTrue(any(d.startswith("via=python_file:" + p + "; ") for s, d in ba if s == "sudo"), ba)
        self.assertTrue(any(d.startswith("via=python_subprocess; ") for s, d in ba if s == "scanner"), ba)

    def test_unapplicable_edit_unlinks(self):
        p = "/home/user/projects/s/probe.py"
        self.tool("Write", p, input_json=json.dumps({"file_path": p, "content": "import os\nos.system('sudo ls')\n"}))
        self.tool("Edit", p, input_json=json.dumps({"file_path": p, "old_string": "not there", "new_string": "x"}))
        self.bash("python3 " + p)
        self.assertEqual([r for r in self.run_detect() if r[0] == "boundary_attempt"], [])


if __name__ == "__main__":
    unittest.main()
