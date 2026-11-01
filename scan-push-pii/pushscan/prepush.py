"""git pre-push hook: the same scan for pushes typed in a terminal (D1). Everything found blocks.

git runs the hook from the repository with `<remote name> <url>` as arguments and one line per
ref on stdin: `<local ref> <local sha> <remote ref> <remote sha>`. A non-zero exit aborts the push.
There is no ask step in a terminal: ASK-tier items are listed with their fingerprint, and the
allowlist is the way to keep one.
"""
from __future__ import annotations

import os
import sys
from typing import Iterable, TextIO

from . import policy
from .detectors import set_own_names
from .gitio import PushRange, Repo
from .hook import Collector, describe_error
from .scan import masked_text

ZERO_SHA = "0" * 40
BANNER = "scan-push-pii (git pre-push hook)"


def main(argv: list[str], stdin: TextIO) -> int:
    try:
        return _main(argv, stdin)
    except Exception as error:                       # fail closed, readably
        _refuse(policy.FAILURE_REASON.format(error=masked_text(describe_error(error))))
        return 1


def _main(argv: list[str], stdin: TextIO) -> int:
    remote = argv[1] if len(argv) > 1 else "origin"
    repo = Repo.open(os.getcwd())
    if repo is None:
        _refuse(policy.FAILURE_REASON.format(error="the hook did not run inside a repository"))
        return 1
    ranges = list(_ranges(repo, remote, stdin))
    if not ranges:
        return 0                                     # deletions only: nothing is sent
    set_own_names(policy.load_own_names())
    collector = Collector()
    collector.scan(repo, ranges)
    report = collector.report()
    if report.empty:
        return 0
    _refuse(report.render())
    return 1


def _ranges(repo: Repo, remote: str, lines: Iterable[str]) -> Iterable[PushRange]:
    """One range per ref git is about to send; the remote sha is the base when we have it."""
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        local_ref, local_sha, _remote_ref, remote_sha = parts
        if local_sha == ZERO_SHA:
            continue                                 # deleting a remote ref sends no content
        if remote_sha != ZERO_SHA and repo.try_git("cat-file", "-e", remote_sha) is not None:
            yield PushRange(local_ref, remote_sha)
        else:
            yield PushRange(local_ref, repo.base_for(local_ref, remote))


def _refuse(text: str) -> None:
    print(f"{BANNER}: push refused.\n{text}", file=sys.stderr)
