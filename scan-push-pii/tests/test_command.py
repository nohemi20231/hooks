"""How the hook finds a push inside a Bash command string, and where that push runs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pushscan.command import find_pushes  # noqa: E402

CWD = "/repo"


def one(command, cwd=CWD):
    pushes = find_pushes(command, cwd)
    assert len(pushes) == 1, pushes
    return pushes[0]


class PlainPush(unittest.TestCase):
    def test_git_push_is_found(self):
        push = one("git push")
        self.assertEqual(push.cwd, "/repo")
        self.assertEqual(push.args, [])

    def test_push_args_are_kept(self):
        push = one("git push -u origin main")
        self.assertEqual(push.args, ["-u", "origin", "main"])

    def test_double_spaces_and_tabs(self):
        self.assertEqual(one("git \t push   origin").args, ["origin"])

    def test_absolute_git_path(self):
        self.assertEqual(one("/usr/bin/git push").args, [])

    def test_quoted_program_name(self):
        self.assertEqual(one('"git" push').args, [])

    def test_force_push(self):
        self.assertEqual(one("git push --force origin main").args, ["--force", "origin", "main"])


class GlobalOptions(unittest.TestCase):
    def test_dash_C_absolute(self):
        push = one("git -C /abs/path/r1 push")
        self.assertEqual(push.cwd, "/abs/path/r1")

    def test_dash_C_relative_to_cwd(self):
        self.assertEqual(one("git -C r1 push").cwd, "/repo/r1")

    def test_dash_C_dot(self):
        self.assertEqual(one("git -C . push").cwd, "/repo")

    def test_work_tree_option(self):
        push = one("git --git-dir=/x/.git --work-tree=/x push")
        self.assertEqual(push.cwd, "/x")

    def test_git_dir_without_work_tree_uses_its_parent(self):
        self.assertEqual(one("git --git-dir=/x/.git push").cwd, "/x")

    def test_dash_c_config_is_skipped(self):
        push = one("git -c core.quotePath=off push origin main")
        self.assertEqual(push.args, ["origin", "main"])

    def test_GIT_DIR_env_prefix(self):
        self.assertEqual(one("GIT_DIR=/x/.git git push").cwd, "/x")

    def test_env_command_prefix(self):
        self.assertEqual(one("env FOO=1 git push").cwd, "/repo")


class GhCli(unittest.TestCase):
    def test_gh_repo_sync_is_a_push(self):
        push = one("gh repo sync")
        self.assertEqual(push.cwd, "/repo")
        self.assertEqual(push.args, [])

    def test_gh_pr_create_is_a_push(self):
        self.assertEqual(one("gh pr create --fill").cwd, "/repo")

    def test_gh_pr_view_is_not(self):
        self.assertEqual(find_pushes("gh pr view", CWD), [])


class Aliases(unittest.TestCase):
    def test_unknown_subcommand_is_reported_as_candidate(self):
        """`git p` may be an alias for push; the hook asks git later. Here it is kept as a candidate."""
        push = one("git p origin main")
        self.assertEqual(push.subcommand, "p")
        self.assertEqual(push.args, ["origin", "main"])
        self.assertFalse(push.certain)

    def test_known_push_is_certain(self):
        self.assertTrue(one("git push").certain)

    def test_known_non_push_is_not_a_candidate(self):
        self.assertEqual(find_pushes("git status", CWD), [])
