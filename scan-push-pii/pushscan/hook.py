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
from .findings import Finding
from .gitio import GitError, Repo
from .policy import Action, Report, action_for, can_be_allowlisted
from .scan import Scanner, masked_text


def main() -> int:
    try:
        return _main()
    except Exception as error:                       # last resort: still a deny, still JSON
        _emit_deny(policy.FAILURE_REASON.format(error=masked_text(_describe(error))), "scan-push-pii: scan failed, push refused")
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
        report = scan_pushes(pushes)
    except Exception as error:                      # fail closed, but with a reason instead of a traceback
        reason = masked_text(_describe(error))
        _emit_deny(policy.FAILURE_REASON.format(error=reason), "scan-push-pii: scan failed, push refused")
        _log("deny(error)", command, reason)
        return 0
    if report.empty:
        _log("allow", command, "")
        return 0
    _emit_deny(report.render(), report.summary())
    _log("deny", command, "; ".join(f"{f.detector}@{f.location}" for f in report.blocked + report.auto + report.ask))
    return 0


def scan_pushes(pushes: list[Push]) -> Report:
    salt = policy.load_salt()
    allowlist = policy.load_allowlist()
    blocked: list[Finding] = []
    auto: list[Finding] = []
    ask: list[Finding] = []
    bucket_for = {Action.BLOCK: blocked, Action.AUTO_REDACT: auto, Action.ASK: ask}
    ranges: list[str] = []
    seen: set[tuple] = set()
    for push in pushes:
        repo = Repo.open(push.cwd)
        if repo is None:
            continue                                     # not a repository: nothing can be pushed
        if not push.certain and not _alias_is_push(repo, push.subcommand):
            continue
        scanner = Scanner(repo, salt)
        for rng in repo.push_ranges(push.args):
            ranges.append(rng.spec)
            findings = (scanner.secrets_in_tree(rng.ref)
                        + scanner.secrets_in_outgoing_commits(rng)
                        + scanner.personal_in_outgoing_diff(rng))
            for finding in findings:
                key = (finding.path, finding.line, finding.detector, finding.masked_value)
                if key in seen:
                    continue
                seen.add(key)
                if can_be_allowlisted(finding) and finding.fingerprint in allowlist:
                    continue
                bucket_for[action_for(finding)].append(finding)
    order = lambda f: (-f.confidence, f.path, f.line)
    return Report(sorted(blocked, key=order), sorted(auto, key=order), sorted(ask, key=order), ranges)


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


def _describe(error: Exception) -> str:
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
