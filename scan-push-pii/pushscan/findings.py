"""The record for one thing the scan found, and how it is shown without revealing it."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class Tier(Enum):
    """Which rule set a finding falls under."""
    SECRET = "secret"        # must never reach GitHub: blocked, no threshold, no allowlist
    PERSONAL = "personal"    # personal data: confidence decides who acts


# masking: values shorter than this reveal nothing but their length
MASK_MIN_LENGTH = 16
MASK_EDGE_CHARS = 2
MASK_STARS = 8
FINGERPRINT_HEX_CHARS = 16


@dataclass(frozen=True)
class Hit:
    """A detector match inside one line or path, before it is tied to a location."""
    detector: str
    tier: Tier
    confidence: float
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class Finding:
    """One finding at one place in the repository, ready to be reported."""
    tier: Tier
    confidence: float
    detector: str
    path: str
    line: int                 # 0 when the finding is the path itself
    masked_value: str
    fingerprint: str
    ref: str = ""             # branch or commit the finding was seen on

    @property
    def location(self) -> str:
        return self.path if self.line == 0 else f"{self.path}:{self.line}"

    def as_report_line(self, with_fingerprint: bool) -> str:
        tail = f"  fingerprint={self.fingerprint}" if with_fingerprint else ""
        return f"  - [{self.confidence:.2f}] {self.detector}  {self.location}  value={self.masked_value}{tail}"


def mask(value: str) -> str:
    """Show at most 2 leading and 2 trailing characters, and only for long values."""
    value = value.strip()
    if len(value) < MASK_MIN_LENGTH:
        return f"<{len(value)} chars>"
    return value[:MASK_EDGE_CHARS] + "*" * MASK_STARS + value[-MASK_EDGE_CHARS:]


def fingerprint(salt: bytes, path: str, detector: str, value: str) -> str:
    """Stable id for allowlisting; salted so it cannot be brute-forced back to the value."""
    digest = hashlib.sha256(salt + f"{path}\0{detector}\0{value}".encode()).hexdigest()
    return digest[:FINGERPRINT_HEX_CHARS]
