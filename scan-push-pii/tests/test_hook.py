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

    def test_not_a_push_is_allowed_without_scanning(self):
        repo = make_repo(self.root, files={"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        self.assertTrue(self.run_hook("git commit -m 'note: run git push later'", repo).allowed)
        self.assertTrue(self.run_hook("git stash push", repo).allowed)
        self.assertTrue(self.run_hook("echo 'git push'", repo).allowed)

    def test_non_repo_cwd_is_allowed(self):
        self.assertTrue(self.run_hook("git push", self.root).allowed)

    def test_malformed_input_is_denied_readably(self):
        run = self.run_hook("", self.root, tool_input="str")
        self.assertTrue(run.denied)
        self.assertNotIn("Traceback", run.stdout + run.stderr)
        self.assertIn("payload", run.reason)


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

    def test_secret_in_minified_bundle_and_svg_is_found(self):
        repo = make_repo(self.root)
        commit(repo, {"dist/bundle.min.js": f'var k="{FAKE_AWS_KEY}";', "logo.svg": f"<svg><!-- {FAKE_AWS_KEY} --></svg>"})
        run = self.run_hook("git push", repo)
        self.assertIn("dist/bundle.min.js", run.reason)
        self.assertIn("logo.svg", run.reason)

    def test_secret_in_a_filename_is_found(self):
        repo = make_repo(self.root)
        commit(repo, {f"keys/{FAKE_ANTHROPIC_KEY}.txt": "x\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("anthropic-key", run.reason)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout)

    def test_secret_in_utf16_file_is_found(self):
        repo = make_repo(self.root)
        commit(repo, {"utf16.env": f"KEY={FAKE_ANTHROPIC_KEY}\n".encode("utf-16")})
        self.assertIn("utf16.env", self.run_hook("git push", repo).reason)

    def test_secret_after_a_very_long_line_prefix_is_found(self):
        repo = make_repo(self.root)
        commit(repo, {"padded.txt": "x" * 5000 + " " + FAKE_AWS_KEY + "\n"})
        self.assertIn("padded.txt", self.run_hook("git push", repo).reason)

    def test_django_model_is_not_a_secret(self):
        repo = make_repo(self.root)
        commit(repo, {"models.py": "password = models.CharField(max_length=128)\napi_key: Optional[str] = None\n"})
        self.assertTrue(self.run_hook("git push", repo).allowed)

    def test_secret_removed_before_head_but_in_an_outgoing_commit_blocks(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'}, "add key")
        commit(repo, {"config.py": 'KEY = os.environ["KEY"]\n'}, "remove key")
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("anthropic-key", run.reason)

    def test_large_tree_scans_within_the_hook_timeout(self):
        repo = make_repo(self.root)
        files = {f"pkg/m{i:04d}/file{i}.py": f"value_{i} = {i}\n" for i in range(3000)}
        files["pkg/last.py"] = f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'
        commit(repo, files)
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertLess(run.seconds, 15, f"took {run.seconds:.1f}s")


class WhichRefsArePushed(HookCase):
    def test_new_branch_is_compared_with_the_remote_it_forked_from(self):
        repo = make_repo(self.root, files={"CONTACT.md": f"mail {GMAIL}\n"})   # origin/main already has the address
        git(repo, "checkout", "-qb", "feature")
        commit(repo, {"a.py": "x = 1\n"})
        run = self.run_hook("git push -u origin feature", repo)
        self.assertTrue(run.allowed, run.stdout)

    def test_named_branch_other_than_head_is_scanned(self):
        repo = make_repo(self.root)
        git(repo, "checkout", "-qb", "leak")
        commit(repo, {"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        git(repo, "checkout", "-q", "main")
        self.assertTrue(self.run_hook("git push origin leak", repo).denied)
        self.assertTrue(self.run_hook("git push --all", repo).denied)
        self.assertTrue(self.run_hook("git push origin leak:refs/heads/x", repo).denied)
        self.assertTrue(self.run_hook("git push", repo).allowed)

    def test_push_to_a_second_remote_scans_against_that_remote(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"contact {GMAIL}\n"})
        git(repo, "push", "-q", "origin", "main")        # already on origin
        other = os.path.join(self.root, "other.git")
        git(self.root, "init", "-q", "--bare", "-b", "main", other)
        git(repo, "remote", "add", "other", other)
        run = self.run_hook("git push other main", repo)
        self.assertTrue(run.denied)
        self.assertIn("email", run.reason)

    def test_dash_C_absolute_path_is_scanned(self):
        repo = make_repo(self.root)
        commit(repo, {"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        self.assertTrue(self.run_hook(f"git -C {repo} push", self.root).denied)

    def test_subshell_cd_is_scanned(self):
        repo = make_repo(self.root)
        commit(repo, {"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        self.assertTrue(self.run_hook("(cd r1 && git push)", self.root).denied)

    def test_push_alias_is_resolved_from_git_config(self):
        repo = make_repo(self.root)
        git(repo, "config", "alias.p", "push")
        commit(repo, {"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        self.assertTrue(self.run_hook("git p origin main", repo).denied)

    def test_non_push_alias_is_allowed(self):
        repo = make_repo(self.root, files={"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        git(repo, "config", "alias.st", "status")
        self.assertTrue(self.run_hook("git st", repo).allowed)


class FailClosedWithAReadableReason(HookCase):
    def test_cd_to_missing_directory_denies_without_traceback(self):
        run = self.run_hook('cd "$HOME/does-not-exist-pushscan" && git push', self.root)
        self.assertTrue(run.denied)
        self.assertNotIn("Traceback", run.stdout + run.stderr)
        self.assertIn("does-not-exist-pushscan", run.reason)

    def test_cd_to_a_file_denies_readably(self):
        repo = make_repo(self.root)
        run = self.run_hook("cd README.md && git push", repo)
        self.assertTrue(run.denied)
        self.assertNotIn("Traceback", run.stdout + run.stderr)


class PersonalData(HookCase):
    def test_personal_email_in_outgoing_commit_is_auto_tier_without_fingerprint(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"contact {GMAIL}\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        auto_block = run.reason.split("redact WITHOUT asking")[1].split("\n\n")[0]
        self.assertIn("email", auto_block)
        self.assertNotIn("fingerprint=", auto_block)

    def test_us_phone_is_ask_tier_with_fingerprint(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"office {US_PHONE}\n"})
        run = self.run_hook("git push", repo)
        ask_block = run.reason.split("ASK THE USER")[1]
        self.assertIn("phone-us", ask_block)
        self.assertIn("fingerprint=", ask_block)

    def test_allowlist_hides_an_ask_tier_item(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"office {US_PHONE}\n"})
        first = self.run_hook("git push", repo)
        fp = first.reason.split("fingerprint=")[1].split()[0]
        with open(os.path.join(self.state, "pii-allowlist"), "w") as f:
            f.write("﻿# comment\r\n" + fp + "\r\n")
        self.assertTrue(self.run_hook("git push", repo).allowed)

    def test_allowlist_cannot_hide_an_auto_tier_item(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"contact {GMAIL}\n"})
        from pushscan.findings import fingerprint   # computed with the real salt the hook will use
        salt = read_bytes(os.path.join(self.state, ".pii-salt")) if os.path.exists(os.path.join(self.state, ".pii-salt")) else None
        self.run_hook("git push", repo)
        salt = read_bytes(os.path.join(self.state, ".pii-salt"))
        with open(os.path.join(self.state, "pii-allowlist"), "w") as f:
            f.write(fingerprint(salt, "notes.md", "email", GMAIL) + "\n")
        self.assertTrue(self.run_hook("git push", repo).denied)

    def test_pii_found_with_diff_noprefix_and_non_ascii_path(self):
        repo = make_repo(self.root)
        git(repo, "config", "diff.noprefix", "true")
        commit(repo, {"café.md": f"contact {GMAIL}\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("café.md", run.reason)

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


class NothingRawLeavesTheScan(HookCase):
    """Reviewer items 9, 10, 11: paths, commands and error text can carry the value too."""
    def test_command_text_is_not_logged(self):
        repo = make_repo(self.root)
        run = self.run_hook(f"git commit -qm 'rotate {FAKE_ANTHROPIC_KEY}' --allow-empty && git push", repo)
        log = read_bytes(os.path.join(self.state, "scan-push.log")).decode()
        self.assertNotIn(FAKE_ANTHROPIC_KEY, log)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout)

    def test_secret_file_name_is_masked_in_line_findings_too(self):
        repo = make_repo(self.root)
        commit(repo, {f"keys/{FAKE_ANTHROPIC_KEY}.txt": f"contact {GMAIL}\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, read_bytes(os.path.join(self.state, "scan-push.log")).decode())

    def test_error_text_is_masked(self):
        run = self.run_hook(f"cd /tmp/{FAKE_ANTHROPIC_KEY} && git push", self.root)
        self.assertTrue(run.denied)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, read_bytes(os.path.join(self.state, "scan-push.log")).decode())


class MoreRefsAndRemotes(HookCase):
    """Reviewer items 13, 14, 17, 18: tags, pushDefault, commit messages, merge commits."""
    def _tagged_secret_repo(self):
        repo = make_repo(self.root)
        git(repo, "checkout", "-qb", "leak")
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        git(repo, "tag", "v1")
        git(repo, "checkout", "-q", "main")
        git(repo, "branch", "-qD", "leak")
        return repo

    def test_push_tags_is_scanned(self):
        repo = self._tagged_secret_repo()
        self.assertTrue(self.run_hook("git push --tags", repo).denied)
        self.assertTrue(self.run_hook("git push --follow-tags origin main", repo).denied)
        self.assertTrue(self.run_hook("git push --mirror origin", repo).denied)

    def test_wildcard_tag_refspec_is_scanned(self):
        repo = self._tagged_secret_repo()
        self.assertTrue(self.run_hook("git push origin 'refs/tags/*:refs/tags/*'", repo).denied)

    def test_push_default_remote_is_used_for_the_base(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": f"mail {GMAIL}\n"})
        git(repo, "push", "-q", "origin", "main")                    # origin already has the address
        fork = os.path.join(self.root, "fork.git")
        git(self.root, "init", "-q", "--bare", "-b", "main", fork)
        git(repo, "remote", "add", "fork", fork)
        git(repo, "config", "remote.pushDefault", "fork")
        run = self.run_hook("git push", repo)                        # goes to fork, which has nothing
        self.assertTrue(run.denied, run.stdout)
        self.assertIn("email", run.reason)

    def test_secret_in_a_commit_message_blocks(self):
        repo = make_repo(self.root)
        git(repo, "commit", "-q", "--allow-empty", "-m", f"hotfix: key was {FAKE_ANTHROPIC_KEY}")
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("commit message", run.reason)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, run.stdout)

    def test_secret_only_in_a_merge_commit_blocks(self):
        repo = make_repo(self.root)
        git(repo, "checkout", "-qb", "feature")
        commit(repo, {"f.txt": "feature\n"})
        git(repo, "checkout", "-q", "main")
        commit(repo, {"m.txt": "main\n"})
        git(repo, "merge", "-q", "--no-ff", "--no-commit", "feature")
        write(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "merge")
        git(repo, "rm", "-q", "config.py")
        git(repo, "commit", "-qm", "remove")
        self.assertTrue(self.run_hook("git push", repo).denied)


class AwkwardContent(HookCase):
    """Reviewer items 15, 16, 22, 23: quoted paths, binaries, non-UTF-8 lines, $(...) in cd."""
    def test_quoted_path_in_diff_is_scanned(self):
        repo = make_repo(self.root)
        commit(repo, {'we"ird.md': f"mail {GMAIL}\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied, run.stdout)

    def test_secret_inside_a_binary_blob_is_found(self):
        repo = make_repo(self.root)
        commit(repo, {"app.db": b"SQLite\x00format\n" + FAKE_ANTHROPIC_KEY.encode() + b"\n"})
        self.assertTrue(self.run_hook("git push", repo).denied)

    def test_non_utf8_added_line_does_not_fail_closed(self):
        repo = make_repo(self.root)
        commit(repo, {"menu.txt": b"caf\xe9 au lait\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.allowed, run.stdout)

    def test_cd_to_command_substitution_keeps_the_current_directory(self):
        repo = make_repo(self.root, files={"k.txt": FAKE_ANTHROPIC_KEY + "\n"})
        run = self.run_hook('cd "$(git rev-parse --show-toplevel)" && git push', repo)
        self.assertTrue(run.denied)
        self.assertIn("anthropic-key", run.reason)


class LoggingNeverChangesTheDecision(HookCase):
    """Reviewer item 24."""
    def test_unwritable_state_dir_still_denies_with_json(self):
        repo = make_repo(self.root)
        commit(repo, {"config.py": f'KEY = "{FAKE_ANTHROPIC_KEY}"\n'})
        os.chmod(self.state, 0o500)
        try:
            run = self.run_hook("git push", repo)
        finally:
            os.chmod(self.state, 0o700)
        self.assertTrue(run.denied, run.stdout + run.stderr)
        self.assertEqual(run.exit_code, 0)
        self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main()


class OwnNamesEndToEnd(HookCase):
    """D7: names in pii-own-names (private, in the state dir); made-up names here."""
    def _names(self, text):
        with open(os.path.join(self.state, "pii-own-names"), "w") as f:
            f.write(text)

    def test_own_name_is_auto_tier(self):
        self._names("zandrika(vell)?\nvellanquist 0.70\n")
        repo = make_repo(self.root)
        commit(repo, {"README.md": "Maintained by Zandrika Vellanquist\n"})
        run = self.run_hook("git push", repo)
        self.assertIn("own-name", run.reason.split("redact WITHOUT asking")[1])

    def test_surname_alone_is_ask_tier(self):
        self._names("zandrika(vell)?\nvellanquist 0.70\n")
        repo = make_repo(self.root)
        commit(repo, {"README.md": "reviewed by Vellanquist\n"})
        run = self.run_hook("git push", repo)
        self.assertIn("own-name", run.reason.split("ASK THE USER")[1])

    def test_own_name_in_a_path_is_masked_in_line_findings(self):
        self._names("zandrika\n")
        repo = make_repo(self.root)
        commit(repo, {"notes-zandrika.md": f"office {US_PHONE}\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertNotIn("zandrika", run.reason.lower())

    def test_bad_names_file_fails_closed_with_a_reason(self):
        self._names("(unclosed\n")
        repo = make_repo(self.root)
        commit(repo, {"a.py": "x = 1\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("pii-own-names", run.reason)
        self.assertNotIn("Traceback", run.stdout + run.stderr)

    def test_without_a_names_file_names_are_not_scanned(self):
        repo = make_repo(self.root)
        commit(repo, {"README.md": "Maintained by Zandrika Vellanquist\n"})
        self.assertTrue(self.run_hook("git push", repo).allowed)


class ProtectedFiles(HookCase):
    """D8: protected paths and transcript content block like secrets; first-person prose asks."""
    def test_transcript_file_is_blocked_like_a_secret(self):
        repo = make_repo(self.root)
        commit(repo, {"data/transcripts/2026-10-31.txt": "plain text\n"})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("protected-path", run.reason.split("SECRETS")[1].split("PERSONAL DATA")[0])

    def test_transcript_content_in_a_json_file_is_blocked(self):
        repo = make_repo(self.root)
        commit(repo, {"data/export.json": '{"role": "user", "content": "hi"}\n{"role": "assistant", "content": "hello"}\n'})
        run = self.run_hook("git push", repo)
        self.assertTrue(run.denied)
        self.assertIn("transcript-content", run.reason.split("SECRETS")[1].split("PERSONAL DATA")[0])

    def test_first_person_inside_journal_is_blocked(self):
        repo = make_repo(self.root)
        commit(repo, {"journal/day.md": "I am not sure I can do this again today.\n"})
        run = self.run_hook("git push", repo)
        secrets_block = run.reason.split("SECRETS")[1].split("PERSONAL DATA")[0]
        self.assertIn("first-person", secrets_block)

    def test_first_person_prose_is_ask_tier(self):
        repo = make_repo(self.root)
        commit(repo, {"notes.md": "Today I felt that my session went badly and I am tired.\n"})
        run = self.run_hook("git push", repo)
        self.assertIn("first-person", run.reason.split("ASK THE USER")[1])
