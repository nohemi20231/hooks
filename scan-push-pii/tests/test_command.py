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

    def test_force_push(self):
        self.assertEqual(one("git push --force origin main").args, ["--force", "origin", "main"])
