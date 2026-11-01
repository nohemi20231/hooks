"""D1: the same scan as a git pre-push hook, for pushes typed in a terminal. Everything found blocks."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.dirname(HERE)
GIT_HOOKS = os.path.join(FOLDER, "git-hooks")
INSTALL = os.path.join(FOLDER, "install.sh")

sys.path.insert(0, HERE)
from fixtures import ANTHROPIC_KEY, US_PHONE  # noqa: E402
from test_hook import commit, git, make_repo  # noqa: E402


class PrePushCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pushscan-prepush-")
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.state)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def terminal_push(self, repo, *args):
        """`git push` as typed in a terminal, with core.hooksPath pointing at this folder's git-hooks/."""
        env = dict(os.environ, PUSHSCAN_STATE_DIR=self.state)
        return subprocess.run(["git", "-c", f"core.hooksPath={GIT_HOOKS}", "push", *args],
                              cwd=repo, capture_output=True, text=True, env=env)


class TerminalPush(PrePushCase):
    def test_secret_blocks_a_terminal_push(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{ANTHROPIC_KEY}"\n'})
        run = self.terminal_push(repo)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("PUSH BLOCKED", run.stderr)
        self.assertIn("anthropic-key", run.stderr)
        self.assertNotIn(ANTHROPIC_KEY, run.stdout + run.stderr)
        self.assertEqual(git(repo, "rev-parse", "origin/main").strip(), git(repo, "rev-parse", "HEAD~1").strip())

    def test_clean_push_passes(self):
        repo = make_repo(self.root)
        commit(repo, {"a.py": "x = 1\n"})
        run = self.terminal_push(repo)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(git(repo, "rev-parse", "origin/main").strip(), git(repo, "rev-parse", "HEAD").strip())

    def test_ask_tier_personal_data_blocks_in_a_terminal(self):
        repo = make_repo(self.root)
        commit(repo, {"contact.md": f"office {US_PHONE}\n"})
        run = self.terminal_push(repo)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("phone-us", run.stderr)
        self.assertIn("fingerprint", run.stderr)          # the terminal has no ask step: keep via the allowlist
        self.assertNotIn(US_PHONE, run.stderr)

    def test_deleting_a_remote_branch_sends_nothing(self):
        repo = make_repo(self.root, files={"k.txt": ANTHROPIC_KEY + "\n"})
        git(repo, "checkout", "-qb", "old")
        git(repo, "push", "-q", "origin", "old")          # no hooksPath: plain git
        git(repo, "checkout", "-q", "main")
        run = self.terminal_push(repo, "origin", ":old")
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_new_branch_uses_what_the_remote_holds_as_base(self):
        repo = make_repo(self.root, files={"CONTACT.md": f"office {US_PHONE}\n"})
        git(repo, "checkout", "-qb", "feature")
        commit(repo, {"a.py": "x = 1\n"})
        run = self.terminal_push(repo, "-u", "origin", "feature")
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_scan_failure_blocks_with_a_reason(self):
        repo = make_repo(self.root)
        commit(repo, {"a.py": "x = 1\n"})
        with open(os.path.join(self.state, "pii-own-names"), "w") as f:
            f.write("(unclosed\n")
        run = self.terminal_push(repo)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("pii-own-names", run.stderr)
        self.assertNotIn("Traceback", run.stderr)
