"""This repository is pushed through the hook it contains, so it must pass its own scan.

Fixtures therefore never spell a secret or a personal value on one source line: tests assemble
them from parts at run time (see tests/fixtures.py). A new fixture that breaks this rule fails here
before it can block a push.
"""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from pushscan.detectors import scan_path, scan_text  # noqa: E402
from pushscan.gitio import decode_text  # noqa: E402


def repo_root():
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=HERE, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


class RepositoryPassesItsOwnScan(unittest.TestCase):
    def test_no_tracked_file_holds_a_secret_or_personal_value(self):
        root = repo_root()
        if root is None:
            self.skipTest("not inside a git repository")
        tracked = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, capture_output=True).stdout.split(b"\0")
        offenders = []
        for raw_path in filter(None, tracked):
            path = raw_path.decode()
            offenders += [f"{path}: {h.detector} in the file name" for h in scan_path(path)]
            with open(os.path.join(root, path), "rb") as f:
                text, _ = decode_text(f.read())
            for number, line in enumerate(text.split("\n"), 1):
                offenders += [f"{path}:{number}: {h.detector}" for h in scan_text(line, path)]
        self.assertEqual(offenders, [], "\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
