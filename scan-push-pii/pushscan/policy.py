"""The rules: thresholds, who acts on what, where state lives, and the text Claude receives."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum

from .findings import Finding, Tier

AUTO_REDACT_THRESHOLD = 0.80          # personal data at or above: Claude redacts without asking
SALT_BYTES = 32
STATE_DIR = os.environ.get("PUSHSCAN_STATE_DIR") or os.path.expanduser("~/.claude/hooks")
ALLOWLIST_PATH = os.path.join(STATE_DIR, "pii-allowlist")
SALT_PATH = os.path.join(STATE_DIR, ".pii-salt")
LOG_PATH = os.path.join(STATE_DIR, "scan-push.log")
OWN_NAMES_PATH = os.path.join(STATE_DIR, "pii-own-names")   # D7: private; one regex per line, optional confidence
OWN_NAME_DEFAULT_CONFIDENCE = 0.90


class Action(Enum):
    BLOCK = "block"                   # secret or protected file: remove, rewrite, never ask
    AUTO_REDACT = "auto"              # personal data, confident: Claude redacts, then reports
    ASK = "ask"                       # personal data, unsure: Claude asks the owner per item


def action_for(finding: Finding) -> Action:
    if finding.tier is Tier.SECRET:
        return Action.BLOCK
    return Action.AUTO_REDACT if finding.confidence >= AUTO_REDACT_THRESHOLD else Action.ASK


def can_be_allowlisted(finding: Finding) -> bool:
    return action_for(finding) is Action.ASK


# ---------------------------------------------------------------- local state

def load_salt() -> bytes:
    """Random local salt for fingerprints; created on first run, regenerated if empty."""
    try:
        with open(SALT_PATH, "rb") as f:
            salt = f.read()
        if len(salt) >= SALT_BYTES:
            return salt
    except FileNotFoundError:
        pass
    salt = os.urandom(SALT_BYTES)
    os.makedirs(STATE_DIR, exist_ok=True)
    fd = os.open(SALT_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(salt)
    return salt


def load_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH, encoding="utf-8-sig") as f:
            return {line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")}
    except FileNotFoundError:
        return set()


class OwnNamesError(ValueError):
    """The private names file cannot be used; the message never repeats a line of it."""


def load_own_names(path: str = OWN_NAMES_PATH) -> list[tuple[str, float]]:
    """(regex, confidence) per line of the owner's names file: `pattern` or `pattern 0.70`.
    Comments start with #. The file lives outside every repository; tests use made-up names."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().split("\n")
    except FileNotFoundError:
        return []
    entries: list[tuple[str, float]] = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, confidence = line, OWN_NAME_DEFAULT_CONFIDENCE
        parts = line.rsplit(None, 1)
        if len(parts) == 2:
            try:
                pattern, confidence = parts[0], float(parts[1])
            except ValueError:
                pass                                  # the last word is part of the pattern
        if not 0.0 <= confidence <= 1.0:
            raise OwnNamesError(f"pii-own-names line {number}: confidence must be between 0 and 1")
        try:
            re.compile(pattern, re.I)
        except re.error as error:
            raise OwnNamesError(f"pii-own-names line {number}: not a valid pattern ({error.msg})") from None
        entries.append((pattern, confidence))
    return entries


def append_log(line: str) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------- the message Claude receives

@dataclass
class Report:
    blocked: list[Finding]
    auto: list[Finding]
    ask: list[Finding]
    ranges: list[str]

    @property
    def empty(self) -> bool:
        return not (self.blocked or self.auto or self.ask)

    def summary(self) -> str:
        return (f"scan-push-pii: push blocked - {len(self.blocked)} secret/protected, "
                f"{len(self.auto)} personal auto-redact, {len(self.ask)} personal need your decision")

    def render(self) -> str:
        parts = [HEADER.format(ranges=", ".join(self.ranges) or "none")]
        if self.blocked:
            parts.append(SECRETS_HEADING.format(n=len(self.blocked)))
            parts += [f.as_report_line(with_fingerprint=False) for f in self.blocked]
            parts.append(SECRETS_PROCEDURE)
        if self.auto:
            parts.append(AUTO_HEADING.format(n=len(self.auto), t=AUTO_REDACT_THRESHOLD))
            parts += [f.as_report_line(with_fingerprint=False) for f in self.auto]
            parts.append(AUTO_PROCEDURE)
        if self.ask:
            parts.append(ASK_HEADING.format(n=len(self.ask), t=AUTO_REDACT_THRESHOLD))
            parts += [f.as_report_line(with_fingerprint=True) for f in self.ask]
            parts.append(ASK_PROCEDURE.format(allowlist=ALLOWLIST_PATH))
        return "\n".join(parts)


HEADER = ("PUSH BLOCKED by scan-push-pii. Outgoing: {ranges}. "
          "Values below are masked; never print raw values.")

SECRETS_HEADING = "\nSECRETS AND PROTECTED FILES ({n}) - must never reach GitHub. No threshold, no bypass, do not ask:"
SECRETS_PROCEDURE = (
    "  Procedure, for each item:\n"
    "    1. Secret value: move it out of the project file into an environment variable or a gitignored\n"
    "       .env / secrets file, and make the code read it from there. Confirm .gitignore covers that file.\n"
    "    2. Protected file (transcript, journal, memory, conversation export, personal notes): remove it from the\n"
    "       repository (git rm --cached) and add its path to .gitignore. Never push it.\n"
    "    3. Commit the change, then rewrite the outgoing commits so the raw value is in none of them:\n"
    "       `git commit --amend` if only in HEAD, otherwise a non-interactive rebase or `git filter-repo`.\n"
    "    4. Re-run the push. The scan runs again.\n"
    "    5. Tell the user what was removed (masked form only). A secret that was committed must be rotated."
)

AUTO_HEADING = "\nPERSONAL DATA, confidence >= {t:.2f} ({n}) - redact WITHOUT asking:"
AUTO_PROCEDURE = (
    "  Replace each value in the project file with a placeholder or a config lookup, commit, rewrite the\n"
    "  outgoing commits as above, re-run the push, and report what was redacted (masked form only)."
)

ASK_HEADING = "\nPERSONAL DATA, confidence < {t:.2f} ({n}) - ASK THE USER with AskUserQuestion before touching these:"
ASK_PROCEDURE = (
    "  Per item ask: redact it, or keep it. Redact: same procedure as above. Keep: append its fingerprint\n"
    "  on its own line to {allowlist} and re-run the push."
)

FAILURE_REASON = ("PUSH BLOCKED by scan-push-pii: the scan could not run, so the push is refused (fail closed).\n"
                  "  Reason: {error}\n"
                  "  If the reason names a directory or git state, fix that and re-run the push. Otherwise the\n"
                  "  hook itself failed: tell the user, and do not work around the hook.")

PAYLOAD_REASON = ("PUSH-SCAN HOOK REFUSED THIS COMMAND: the hook payload could not be read ({problem}), so the\n"
                  "  scan cannot tell whether this is a push. Tell the user: the hook in ~/.claude/settings.json needs\n"
                  "  updating for this Claude Code version. Do not work around the hook.")
