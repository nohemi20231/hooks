"""End to end: a Bash command and a real repository go in, a hook decision comes out."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HOOKS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(HOOKS_DIR, "scan-push-pii.py")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import ANTHROPIC_KEY as FAKE_ANTHROPIC_KEY, AWS_KEY as FAKE_AWS_KEY, GMAIL, US_PHONE  # noqa: E402


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def git(repo, *args, **kw):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, text=True, check=True, **kw).stdout


def make_repo(root, name="r1", files=None, remote=True):
    """A repo with one commit of `files`; optionally an `origin` bare remote that already has it."""
    repo = os.path.join(root, name)
    os.makedirs(repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    write(repo, files or {"README.md": "hello\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    if remote:
        bare = os.path.join(root, name + "-origin.git")
        git(root, "init", "-q", "--bare", "-b", "main", bare)
        git(repo, "remote", "add", "origin", bare)
        git(repo, "push", "-q", "-u", "origin", "main")
    return repo


def write(repo, files):
    for path, content in files.items():
        full = os.path.join(repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as f:
            f.write(content)


def commit(repo, files, message="change"):
    write(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", message)


class HookRun:
    def __init__(self, state_dir, command, cwd, tool_input=None):
        payload = {"tool_name": "Bash", "tool_input": tool_input if tool_input is not None else {"command": command}, "cwd": cwd}
        env = dict(os.environ, PUSHSCAN_STATE_DIR=state_dir)
        started = time.time()
        proc = subprocess.run([sys.executable, "-I", HOOK], input=json.dumps(payload), capture_output=True, text=True, env=env)
        self.seconds = time.time() - started
        self.exit_code = proc.returncode
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        self.decision = json.loads(proc.stdout) if proc.stdout.strip() else None

    @property
    def allowed(self):
        return self.decision is None and self.exit_code == 0

    @property
    def reason(self):
        return self.decision["hookSpecificOutput"]["permissionDecisionReason"]

    @property
    def denied(self):
        return self.decision is not None and self.decision["hookSpecificOutput"]["permissionDecision"] == "deny"


class HookCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pushscan-")
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.state)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_hook(self, command, cwd, **kw):
        return HookRun(self.state, command, cwd, **kw)


class CleanAndNonPush(HookCase):
    def test_clean_repo_is_allowed(self):
        repo = make_repo(self.root)
        commit(repo, {"a.py": 'key = os.environ["API_KEY"]\n'})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.allowed, run.stdout + run.stderr)

    def test_non_repo_cwd_is_allowed(self):
        self.assertTrue(self.run_hook("git push", self.root).allowed)


class SecretsInTheTree(HookCase):
    def test_secret_at_head_blocks(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("anthropic-key", run.reason)
        self.assertIn("config.py:1", run.reason)

    def test_raw_value_never_appears_in_output(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        run = self.run_hook("git push", repo)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout + run.stderr)
        self.assertNotIn(FAKE_ANTHROPIC_KEY[5:25], run.stdout + run.stderr)

    def test_secret_found_when_cwd_is_a_subdirectory(self):
        repo = make_repo(self.root)
        commit(repo, {"sub/.env": f"KEY={FAKE_ANTHROPIC_KEY}\n"})
        run = self.run_hook("git push", os.path.join(repo, "sub"))
        self.assertTrue(run.denied)
        self.assertIn("sub/.env", run.reason)

    def test_secret_found_after_cd_into_subdirectory(self):
        repo = make_repo(self.root)
        commit(repo, {"sub/.env": f"KEY={FAKE_ANTHROPIC_KEY}\n"})
        self.assertTrue(self.run_hook("cd sub && git push", repo).denied)


class PersonalData(HookCase):
    def test_allowlist_hides_an_ask_tier_item(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"office {US_PHONE}\n"})
        first = self.run_hook("git push", repo)
        fp = first.reason.split("fingerprint=")[1].split()[0]
        with open(os.path.join(self.state, "pii-allowlist"), "w") as f:
            f.write("﻿# comment\r\n" + fp + "\r\n")
        self.assertTrue(self.run_hook("git push", repo).allowed)

    def test_pii_already_on_the_remote_is_not_reported_again(self):
        repo = make_repo(self.root, files={"notes.md": f"contact {GMAIL}\n"})
        commit(repo, {"other.md": "plain\n"})
        self.assertTrue(self.run_hook("git push", repo).allowed)


class StateFiles(HookCase):
    def test_every_decision_is_logged_locally_masked(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        self.run_hook("git push", repo)
        log = read_bytes(os.path.join(self.state, "scan-push.log")).decode()
        self.assertIn("deny", log)
        self.assertIn("config.py:1", log)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, log)
