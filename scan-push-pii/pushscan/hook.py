"""Entry point: hook JSON on stdin, a decision on stdout. Any failure denies the push, readably.

Nothing raw is written anywhere: the log holds a hash of the command, masked locations and
masked error text; the reason text holds masked values and masked paths.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone

from . import policy
from .command import Push, find_pushes
from .detectors import set_own_names
from .findings import Finding
from .gitio import GitError, PushRange, Repo
from .policy import Action, Report, action_for, can_be_allowlisted
from .scan import Scanner, masked_text


def main() -> int:
    try:
        return _main()
    except Exception as error:                       # last resort: still a deny, still JSON
        _emit_deny(policy.FAILURE_REASON.format(error=masked_text(describe_error(error))), "scan-push-pii: scan failed, push refused")
        return 0


def _main() -> int:
    payload, problem = _read_payload()
    if payload is None:
        _emit_deny(policy.PAYLOAD_REASON.format(problem=problem), "scan-push-pii: unreadable hook payload, push refused")
        _log("deny(payload)", "", problem)
        return 0
    command, cwd = payload
    try:
        pushes = find_pushes(command, cwd)
        if not pushes:
            return 0
        set_own_names(policy.load_own_names())      # D7: the owner's names, from the private file
        report = scan_pushes(pushes)
    except Exception as error:                      # fail closed, but with a reason instead of a traceback
        reason = masked_text(describe_error(error))
        _emit_deny(policy.FAILURE_REASON.format(error=reason), "scan-push-pii: scan failed, push refused")
        _log("deny(error)", command, reason)
        return 0
    if report.empty:
        _log("allow", command, "")
        return 0
    _emit_deny(report.render(), report.summary())
    _log("deny", command, "; ".join(f"{f.detector}@{f.location}" for f in report.blocked + report.auto + report.ask))
    return 0


class Collector:
    """Findings from one or more repositories, bucketed by action; both entry points use it."""

    def __init__(self):
        self.salt = policy.load_salt()
        self.allowlist = policy.load_allowlist()
        self.blocked: list[Finding] = []
        self.auto: list[Finding] = []
        self.ask: list[Finding] = []
        self.ranges: list[str] = []
        self._seen: set[tuple] = set()

    def scan(self, repo: Repo, ranges: list[PushRange]) -> None:
        scanner = Scanner(repo, self.salt)
        bucket_for = {Action.BLOCK: self.blocked, Action.AUTO_REDACT: self.auto, Action.ASK: self.ask}
        for rng in ranges:
            self.ranges.append(rng.spec)
            findings = (scanner.secrets_in_tree(rng.ref)
                        + scanner.secrets_in_outgoing_commits(rng)
                        + scanner.personal_in_outgoing_diff(rng))
            for finding in findings:
                key = (finding.path, finding.line, finding.detector, finding.masked_value)
                if key in self._seen:
                    continue
                self._seen.add(key)
                if can_be_allowlisted(finding) and finding.fingerprint in self.allowlist:
                    continue
                bucket_for[action_for(finding)].append(finding)

    def report(self) -> Report:
        order = lambda f: (-f.confidence, f.path, f.line)
        return Report(sorted(self.blocked, key=order), sorted(self.auto, key=order), sorted(self.ask, key=order), self.ranges)


def scan_pushes(pushes: list[Push]) -> Report:
    collector = Collector()
    for push in pushes:
        repo = Repo.open(push.cwd)
        if repo is None:
            continue                                     # not a repository: nothing can be pushed
        if not push.certain and not _alias_is_push(repo, push.subcommand):
            continue
        collector.scan(repo, repo.push_ranges(push.args))
    return collector.report()


def _alias_is_push(repo: Repo, name: str, depth: int = 0) -> bool:
    """`git p` is a push if alias.p expands to push, to a shell command containing a push, or to
    another alias that does. `?` means the subcommand is unknown (xargs): treat as a push."""
    if name == "?":
        return True
    expansion = repo.alias(name)
    if not expansion or depth > 5:
        return False
    if expansion.startswith("!"):
        return bool(find_pushes(expansion[1:], repo.toplevel))
    first = expansion.split()[0]
    if first in ("push", "send-pack"):
        return True
    return _alias_is_push(repo, first, depth + 1)


def _read_payload() -> tuple[tuple[str, str] | None, str]:
    try:
        data = json.load(sys.stdin)
    except Exception as error:
        return None, f"stdin is not JSON ({error.__class__.__name__})"
    if not isinstance(data, dict):
        return None, "payload is not an object"
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return None, "payload has no tool_input object"
    command, cwd = tool_input.get("command"), data.get("cwd")
    if not isinstance(command, str):
        return None, "payload tool_input.command is not a string"
    if not isinstance(cwd, str) or not cwd:
        return None, "payload has no cwd"
    return (command, cwd), ""


def _emit_deny(reason: str, summary: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason},
        "systemMessage": summary,
    }))


def describe_error(error: Exception) -> str:
    text = str(error) or error.__class__.__name__
    return text if isinstance(error, GitError) else f"{error.__class__.__name__}: {text}"


def _log(decision: str, command: str, detail: str) -> None:
    """One local line per decision. The command is identified by a hash, never stored.
    `detail` is already masked by the caller (locations and error text)."""
    digest = hashlib.sha256(command.encode()).hexdigest()[:12] if command else "-"
    program = command.split()[0] if command.split() else "-"
    try:
        policy.append_log(f"{_now()} {decision} cmd#{digest} first_word={program} {detail}".rstrip())
    except OSError:
        pass                                         # a logging failure must never change the decision


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
