"""Every call to git, in one place. Errors are raised, never swallowed.

Reading the tree uses one `ls-tree` and one `cat-file --batch` process, so a repository
with tens of thousands of files is read in a few seconds instead of one process per file.
"""
from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from typing import Iterator

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT_TIMEOUT_SECONDS = 60
MAX_BLOB_BYTES = 2 * 1024 * 1024       # larger files are scanned only up to this size
BINARY_PROBE_BYTES = 8000
PUSH_OPTS_WITH_VALUE = {"--repo", "--receive-pack", "--exec", "-o", "--push-option", "--force-with-lease", "--signed"}


class GitError(RuntimeError):
    pass


@dataclass(frozen=True)
class PushRange:
    """Commits that would reach the remote: everything in `ref` that `base` does not have."""
    ref: str
    base: str

    @property
    def spec(self) -> str:
        return f"{self.base}..{self.ref}"


@dataclass(frozen=True)
class Blob:
    path: str
    text: str
    binary: bool = False      # decoded as Latin-1 so secret patterns still run; personal data is not scored


@dataclass(frozen=True)
class CommitMessage:
    sha: str
    text: str


class Repo:
    def __init__(self, toplevel: str):
        self.toplevel = toplevel

    # ---------------------------------------------------------------- opening

    @classmethod
    def open(cls, directory: str) -> "Repo | None":
        """The repository that `directory` belongs to (work tree, .git folder or bare), or None."""
        if not os.path.isdir(directory):
            raise GitError(f"directory does not exist: {directory}")
        probe = _plain_git(directory, "rev-parse", "--is-inside-work-tree", "--is-bare-repository", "--absolute-git-dir")
        if probe.returncode != 0:
            return None
        in_work_tree, bare, git_dir = (line.strip() for line in probe.stdout.split("\n")[:3])
        if in_work_tree == "true":
            return cls(_plain_git(directory, "rev-parse", "--show-toplevel").stdout.strip())
        if bare == "true":
            return cls(git_dir)                       # a bare repo can push its refs too
        return cls(os.path.dirname(git_dir) if os.path.basename(git_dir) == ".git" else git_dir)

    def git(self, *args: str) -> str:
        proc = self._run(*args)
        if proc.returncode != 0:
            raise GitError(f"git {' '.join(args[:3])} failed: {proc.stderr.strip()[:300]}")
        return proc.stdout

    def try_git(self, *args: str) -> str | None:
        """stdout of a git command, or None if it fails (for 'does X exist' questions)."""
        proc = self._run(*args)
        return proc.stdout.strip() if proc.returncode == 0 else None

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return _plain_git(self.toplevel, "-c", "core.quotePath=off", *args)

    # ---------------------------------------------------------------- refs and ranges

    def alias(self, name: str) -> str | None:
        return self.try_git("config", "--get", f"alias.{name}")

    def current_branch(self) -> str | None:
        return self.try_git("symbolic-ref", "--short", "-q", "HEAD") or None

    def refs(self, pattern: str) -> list[str]:
        """Full ref names under `pattern`, e.g. refs/heads/ or refs/tags/v."""
        out = self.try_git("for-each-ref", "--format=%(refname)", pattern) or ""
        return [r for r in out.split("\n") if r]

    def push_remote_for(self, branch: str) -> str:
        """Where `git push` with no remote sends `branch`: pushRemote, pushDefault, then the upstream remote."""
        for key in (f"branch.{branch}.pushRemote", "remote.pushDefault", f"branch.{branch}.remote"):
            remote = self.try_git("config", "--get", key)
            if remote:
                return remote
        return "origin"

    def has_commits(self) -> bool:
        return self.try_git("rev-parse", "--verify", "-q", "HEAD") is not None

    def push_ranges(self, push_args: list[str]) -> list[PushRange]:
        """Which local refs a `git push <args>` would send, each with the base the remote already has."""
        if not self.has_commits():
            return []
        remote, refspecs, flags = self._parse_push_args(push_args)
        if "--delete" in flags or "-d" in flags:
            return []                                 # deleting remote refs sends no content
        refs: list[str] = []
        if flags & {"--all", "--branches", "--mirror"}:
            refs += self.refs("refs/heads/")
        if flags & {"--tags", "--follow-tags", "--mirror"}:
            refs += self.refs("refs/tags/")
        for spec in refspecs:
            refs += self._sources_of(spec)
        if not refs and not flags & {"--all", "--branches", "--mirror", "--tags"}:
            current = self.current_branch()
            refs = [f"refs/heads/{current}"] if current else ["HEAD"]
        # a branch created earlier in the same command does not exist yet when the hook runs: scan HEAD
        refs = [r if self.try_git("rev-parse", "--verify", "-q", f"{r}^{{commit}}") is not None else "HEAD" for r in refs if r]
        refs = list(dict.fromkeys(refs))
        if remote is None:
            first = refs[0].replace("refs/heads/", "", 1) if refs else "HEAD"
            remote = self.push_remote_for(first)
        return [PushRange(ref, self.base_for(ref, remote)) for ref in refs]

    @staticmethod
    def _parse_push_args(args: list[str]) -> tuple[str | None, list[str], set[str]]:
        """Return (remote, refspecs, flags) from the arguments after `git push`."""
        positional: list[str] = []
        flags: set[str] = set()
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in PUSH_OPTS_WITH_VALUE:
                i += 1
            elif arg.startswith("-"):
                flags.add(arg.split("=", 1)[0])
            else:
                positional.append(arg)
            i += 1
        if not positional:
            return None, [], flags
        return positional[0], positional[1:], flags

    def _sources_of(self, refspec: str) -> list[str]:
        """The local side of a refspec; `refs/tags/*:refs/tags/*` expands to every matching ref."""
        src = refspec.lstrip("+").split(":", 1)[0]
        if not src:
            return [] if ":" in refspec else ["HEAD"]       # `:branch` deletes; nothing is sent
        if "*" in src:
            return self.refs(src.split("*", 1)[0])
        return [src]

    def base_for(self, ref: str, remote: str) -> str:
        """The newest commit of `ref` that `remote` already has, or the empty tree if none.

        Same-named remote branch first. A new branch or a tag is compared with whatever the
        remote holds under any name, so files already on the remote are not reported again.
        """
        short = ref.split("/", 2)[-1] if ref.startswith("refs/heads/") else ref
        tracking = f"refs/remotes/{remote}/{short}"
        if self.try_git("rev-parse", "--verify", "-q", tracking) is not None:
            base = self.try_git("merge-base", ref, tracking)
            if base:
                return base
        outgoing = self.try_git("rev-list", "--boundary", ref, "--not", f"--remotes={remote}")
        if outgoing is None:
            return EMPTY_TREE
        boundaries = [line[1:] for line in outgoing.split("\n") if line.startswith("-")]
        if boundaries:
            return min(boundaries, key=lambda sha: int(self.try_git("rev-list", "--count", f"{sha}..{ref}") or 0))
        return ref if not outgoing else EMPTY_TREE        # all of it is on the remote already / none of it is

    # ---------------------------------------------------------------- reading content

    def tree_blobs(self, ref: str) -> Iterator[Blob]:
        """Every file in the tree of `ref`, read through one cat-file process."""
        listing = self.git("ls-tree", "-r", "-z", "--full-tree", ref)
        entries = []
        for item in listing.split("\0"):
            if not item:
                continue
            meta, path = item.split("\t", 1)
            mode, kind, sha = meta.split()
            if kind == "blob" and not mode.startswith("120"):      # skip symlinks
                entries.append((sha, path))
        if not entries:
            return
        proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=self.toplevel, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdin and proc.stdout
        requests = "".join(sha + "\n" for sha, _ in entries).encode()
        writer = threading.Thread(target=lambda: (proc.stdin.write(requests), proc.stdin.close()))
        writer.start()
        for sha, path in entries:
            header = proc.stdout.readline()
            if not header:
                break
            parts = header.split()
            if len(parts) != 3:                                      # "<sha> missing"
                continue
            size = int(parts[2])
            data = _read_capped(proc.stdout, size + 1, MAX_BLOB_BYTES + 1)   # +1: trailing newline
            text, binary = decode_text(data[:min(size, MAX_BLOB_BYTES)])
            yield Blob(path, text, binary)
        writer.join()
        proc.wait(timeout=GIT_TIMEOUT_SECONDS)

    def added_lines(self, spec: str, per_commit: bool) -> Iterator[tuple[str, int, str]]:
        """(path, line number, text) for every added line in `spec`.

        per_commit=False diffs the two ends (net change). per_commit=True walks each commit, so a
        value added in one commit and removed in a later one is still seen; merge commits are
        diffed against their first parent, and binary files are diffed as text.
        """
        args = ["--no-color", "--unified=0", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", "--no-renames"]
        if per_commit:
            out = self.git("log", "-p", "--format=%x00commit %H", "--reverse", "--diff-merges=first-parent", "--text", *args, spec)
        else:
            out = self.git("diff", *args, spec)
        path, lineno = None, 0
        for raw in out.split("\n"):
            if raw.startswith("+++ "):
                path = _diff_path(raw[4:])
            elif raw.startswith("@@"):
                after = raw.split("+", 1)[1].split()[0]
                lineno = int(after.split(",")[0]) - 1
            elif raw.startswith("+") and not raw.startswith("+++") and path is not None:
                lineno += 1
                yield path, lineno, raw[1:]
            elif raw.startswith("\0commit ") or raw.startswith("diff "):
                path = None

    def paths_in(self, spec: str) -> list[str]:
        """Paths touched by the commits in `spec`."""
        out = self.git("diff", "--name-only", "--diff-filter=AMR", "-z", spec)
        return [p for p in out.split("\0") if p]

    def commit_messages(self, spec: str) -> list[CommitMessage]:
        """Full message of every commit in `spec`: these are pushed too."""
        parts = self.git("log", "--format=%x00%H%x00%B", spec).split("\0")[1:]
        return [CommitMessage(sha.strip(), body) for sha, body in zip(parts[0::2], parts[1::2])]


def _plain_git(directory: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=directory, capture_output=True, text=True, errors="replace",
                          timeout=GIT_TIMEOUT_SECONDS)


def _read_capped(stream, size: int, cap: int) -> bytes:
    """Read `size` bytes from the stream but keep only the first `cap`."""
    kept = stream.read(min(size, cap))
    remaining = size - len(kept)
    while remaining > 0:
        chunk = stream.read(min(remaining, 1 << 20))
        if not chunk:
            break
        remaining -= len(chunk)
    return kept


def _diff_path(field: str) -> str | None:
    """The path from a `+++ b/...` line; git quotes paths with special characters as C strings."""
    if field.startswith('"') and field.endswith('"'):
        field = field[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode("utf-8", "replace")
    return field[2:] if field.startswith("b/") else None


def decode_text(data: bytes) -> tuple[str, bool]:
    """(text, is_binary). UTF-8, UTF-16 with BOM, Latin-1; binaries decode as Latin-1 so secrets still show."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), False
        except UnicodeDecodeError:
            return data.decode("latin-1"), True
    if b"\0" in data[:BINARY_PROBE_BYTES]:
        return data.decode("latin-1"), True
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("latin-1"), False
