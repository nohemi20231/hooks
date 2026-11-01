"""The scans, each turning repository content into Findings. Paths in findings are masked too."""
from __future__ import annotations

import re

from .detectors import scan_path, scan_text
from .findings import Finding, Hit, Tier, fingerprint, mask
from .gitio import PushRange, Repo

# lockfiles and bundles are skipped for personal data only; secrets are scanned everywhere
PERSONAL_SKIP_PATHS = re.compile(
    r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|Gemfile\.lock|go\.sum)$"
    r"|\.min\.(js|css)$|\.map$"
)
PERSONAL_MAX_LINE_CHARS = 20000      # longer lines are data blobs; secrets are still scanned on them


def masked_path(path: str) -> str:
    """The path with every secret or name inside it masked, for reports and logs."""
    shown = path
    for hit in sorted(scan_path(path), key=lambda h: -h.start):
        shown = shown[:hit.start] + mask(hit.value) + shown[hit.end:]
    return shown


def masked_text(text: str) -> str:
    """Free text (an error message, a command) with every detectable value masked."""
    shown = text
    for hit in sorted(scan_text(text, "message.txt"), key=lambda h: -h.start):
        shown = shown[:hit.start] + mask(hit.value) + shown[hit.end:]
    return shown


class Scanner:
    def __init__(self, repo: Repo, salt: bytes):
        self.repo = repo
        self.salt = salt

    # ---------------------------------------------------------------- building findings

    def _finding(self, hit: Hit, path: str, line: int, ref: str) -> Finding:
        """Tie a hit to its place. The reported path is masked so a secret or a name in the
        file name never reaches the report through the location column."""
        return Finding(
            tier=hit.tier, confidence=hit.confidence, detector=hit.detector, path=masked_path(path), line=line,
            masked_value=mask(hit.value), fingerprint=fingerprint(self.salt, path, hit.detector, hit.value), ref=ref,
        )

    # ---------------------------------------------------------------- secrets

    def secrets_in_tree(self, ref: str) -> list[Finding]:
        """Every secret in the whole tree of `ref`: all of it would be on GitHub."""
        findings: list[Finding] = []
        seen: set[tuple] = set()
        for blob in self.repo.tree_blobs(ref):
            for hit in scan_path(blob.path):
                if hit.tier is Tier.SECRET:
                    self._add(findings, seen, self._finding(hit, blob.path, 0, ref))
            for number, line in enumerate(blob.text.split("\n"), 1):
                for hit in scan_text(line, blob.path):
                    if hit.tier is Tier.SECRET:
                        self._add(findings, seen, self._finding(hit, blob.path, number, ref))
        return findings

    def secrets_in_outgoing_commits(self, rng: PushRange) -> list[Finding]:
        """Secrets added by any outgoing commit (even if removed again later) and in commit messages."""
        findings: list[Finding] = []
        seen: set[tuple] = set()
        for path, number, line in self.repo.added_lines(rng.spec, per_commit=True):
            for hit in scan_text(line, path):
                if hit.tier is Tier.SECRET:
                    self._add(findings, seen, self._finding(hit, path, number, rng.ref))
        for message in self.repo.commit_messages(rng.spec):
            where = f"commit message {message.sha[:10]}"
            for number, line in enumerate(message.text.split("\n"), 1):
                for hit in scan_text(line, "COMMIT_MESSAGE.txt"):
                    if hit.tier is Tier.SECRET:
                        self._add(findings, seen, self._finding(hit, where, number, rng.ref))
        return findings

    # ---------------------------------------------------------------- personal data

    def personal_in_outgoing_diff(self, rng: PushRange) -> list[Finding]:
        """Personal data on lines the outgoing commits add (net change)."""
        findings: list[Finding] = []
        seen: set[tuple] = set()
        for path in self.repo.paths_in(rng.spec):
            for hit in scan_path(path):
                if hit.tier is Tier.PERSONAL:
                    self._add(findings, seen, self._finding(hit, path, 0, rng.ref))
        for path, number, line in self.repo.added_lines(rng.spec, per_commit=False):
            if PERSONAL_SKIP_PATHS.search(path) or len(line) > PERSONAL_MAX_LINE_CHARS:
                continue
            for hit in scan_text(line, path):
                if hit.tier is Tier.PERSONAL:
                    self._add(findings, seen, self._finding(hit, path, number, rng.ref))
        return findings

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _add(findings: list[Finding], seen: set[tuple], finding: Finding) -> None:
        key = (finding.path, finding.line, finding.detector, finding.masked_value)
        if key not in seen:
            seen.add(key)
            findings.append(finding)
