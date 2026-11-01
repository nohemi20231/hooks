"""Every detector: what it matches, which tier it belongs to, and how it scores a match.

A detector is a regex plus a small scoring function. The scoring function returns a
confidence, or None to drop the match (placeholders, dev-only values, false shapes).
Secrets are scored too, but their tier means the score never changes the outcome.
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .findings import Hit, Tier

Scorer = Callable[[re.Match, str, str, float], Optional[float]]   # (match, line, path, base) -> confidence or None

PLACEHOLDER = re.compile(
    r"example|changeme|change_me|placeholder|your[_-]?|xxx|dummy|sample|fake|redacted|<[^>]+>|\$\{|\{\{|\*{3,}|\.\.\.",
    re.I,
)
LOCALHOST = re.compile(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)$", re.I)
SAFE_EMAIL_DOMAIN = re.compile(
    r"@(example\.(com|org|net)|anthropic\.com|users\.noreply\.github\.com|localhost|test\.com|email\.com|domain\.com)$",
    re.I,
)
PLACEHOLDER_EMAIL_LOCAL = re.compile(
    r"^(your[-_.]?\w*|you|email|e-?mail|name|user|username|test|example|foo|bar|john\.?doe|jane\.?doe|firstname|lastname|no-?reply|admin|info)$",
    re.I,
)
PERSONAL_EMAIL_DOMAIN = re.compile(r"@(gmail|yahoo|hotmail|outlook|icloud|live|aol|proton(mail)?|me)\.(com|net|ch)$", re.I)
SEMVER_OR_VERSION = re.compile(r"\bversion\b|\bv?\d+\.\d+\.\d+", re.I)
VERSION_WORD = re.compile(r"\bversion\b", re.I)
BARE_SECRET_SHAPE = re.compile(r"^[A-Za-z0-9_\-+/=]{12,}$")
HOST_WORDS = re.compile(r"\b(ip|host|hostname|addr|address|server|endpoint)\b", re.I)
DOTENV_FILE = re.compile(r"(^|/)\.env(\.|$)|\.env$", re.I)
MIN_SECRET_VALUE_LENGTH = 8
MIN_ENTROPY_LENGTH = 12
MIN_CHAR_CLASSES = 3

# D7: words about the owner. Prose only: code, comments and short fragments are not prose.
CODE_LIKE = re.compile(r"[=;{}]|=>|//|\(\)|^\s*#")
PROSE_SUFFIXES = {".md", ".txt", ".rst", ".csv", ".json", ".yaml", ".yml", ".html", ".htm", ".tex", ".org"}
MIN_PROSE_WORDS = 5
ONE_PER_LINE = {"first-person", "own-name"}        # one finding per line is enough for these
# a copyright notice or an authors file names its owner on purpose: ask once instead of redacting
COPYRIGHT_LINE = re.compile(r"copyright|\(c\)\s*\d{4}|©", re.I)
LICENSE_FILES = re.compile(r"^(LICENSE|LICENCE|NOTICE|COPYING|AUTHORS|CONTRIBUTORS|CODEOWNERS)(\.\w+)?$", re.I)
COPYRIGHT_CONFIDENCE = 0.60

# D8: a protected name is only a signal together with a prose-like file: src/memory.rs is code
PROTECTED_WORDS = re.compile(r"^(transcripts?|conversations?|chat[-_]?(logs?|history)|journal|diary|personal|memory|sessions?)$", re.I)
DATED_PROTECTED_WORD = re.compile(r"^(transcripts?|conversations?|chat[-_]?(logs?|history)|journal|diary|sessions?)[-_]\d", re.I)
PROTECTED_SUFFIXES = {".md", ".txt", ".jsonl", ".json", ".csv", ".log", ".html", ".htm", ".rtf", ".org", ".tex", ""}
TRANSCRIPT_KEYS = re.compile(r'"(role|parentUuid|sessionId|conversation_id|speaker)"\s*:', re.I)
TRANSCRIPT_ROLES = re.compile(r'"(user|assistant|human|system|therapist|client)"', re.I)
TRANSCRIPT_SAMPLE_CHARS = 20000


@dataclass(frozen=True)
class Detector:
    name: str
    tier: Tier
    pattern: re.Pattern
    base: float
    score: Scorer
    requires: str = ""        # a substring the line must contain before the regex is tried at all


# ---------------------------------------------------------------- scoring helpers

def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value))


def looks_random(value: str) -> bool:
    """Three of four character classes and long enough: typical of a generated secret."""
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return len(value) >= MIN_ENTROPY_LENGTH and classes >= MIN_CHAR_CLASSES


def luhn_ok(digits: str) -> bool:
    total, double = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        double = not double
    return total % 10 == 0


def private_ip(ip: str) -> bool:
    a, b = (int(x) for x in ip.split(".")[:2])
    return a in (10, 127, 0) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254) or a >= 224


def is_dotenv_file(path: str) -> bool:
    return bool(DOTENV_FILE.search(path))


def is_prose_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in PROSE_SUFFIXES


def is_protected_path(path: str) -> bool:
    """A transcript, journal, memory or personal-notes file.

    Protected: anything under .claude/projects; a prose-like file whose folder is named like a
    transcript store (transcripts/, journal/, memory/, ...); or a prose-like file whose own name
    is that word or that word plus a date (journal-2026-10.md). docs/memory-model.md is not.
    """
    if "/.claude/projects/" in "/" + path:
        return True
    folders, name = path.split("/")[:-1], path.split("/")[-1]
    stem, suffix = os.path.splitext(name)
    if suffix.lower() not in PROTECTED_SUFFIXES:
        return False
    if any(PROTECTED_WORDS.match(folder) for folder in folders):
        return True
    return bool(PROTECTED_WORDS.match(stem) or DATED_PROTECTED_WORD.match(stem))


def looks_like_transcript(text: str) -> bool:
    """JSON lines with speaker roles or Claude session keys: a conversation export, whatever its name."""
    sample = text[:TRANSCRIPT_SAMPLE_CHARS]
    return bool(TRANSCRIPT_KEYS.search(sample) and TRANSCRIPT_ROLES.search(sample))


# ---------------------------------------------------------------- scorers

def score_vendor_key(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    return None if is_placeholder(m.group(0)) else base


def score_jwt(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    """A JWT whose payload is the public jwt.io sample is documentation, not a secret."""
    try:
        payload_b64 = m.group(0).split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except Exception:
        return base
    if payload.get("sub") == "1234567890" or payload.get("name") == "John Doe":
        return None
    return base


def score_url_credentials(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    user, password, host = m.group("user"), m.group("password"), m.group("host")
    if is_placeholder(password) or password.startswith("$") or password.startswith("{"):
        return None
    if LOCALHOST.match(host) or PLACEHOLDER.search(host):
        return None
    if user and password.lower() == user.lower():
        return None            # app:app@db is a dev convention, not a credential
    return base


def score_secret_assignment(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    value = m.group("value")
    if is_placeholder(value):
        return None
    if m.group("quote") or is_dotenv_file(path):
        return 0.90 if looks_random(value) else base      # a quoted literal, or any value in a .env file
    # a bare value elsewhere counts only when it is a random-looking token, never a call or an attribute
    if BARE_SECRET_SHAPE.match(value) and looks_random(value):
        return base
    return None


def score_bearer_token(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    token = m.group("token")
    if is_placeholder(token) or token.startswith("$") or token.startswith("{"):
        return None
    return base if looks_random(token) else None


def score_email(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    address = m.group(0)
    local = address.split("@", 1)[0]
    if SAFE_EMAIL_DOMAIN.search(address) or PLACEHOLDER_EMAIL_LOCAL.match(local) or is_placeholder(address):
        return None
    return 0.85 if PERSONAL_EMAIL_DOMAIN.search(address) else 0.75


def score_phone_us(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    exchange, last4 = m.group("exchange"), m.group("last4")
    if exchange == "555" and last4.startswith("01"):
        return None            # 555-01xx is reserved for fiction
    if SEMVER_OR_VERSION.search(line):
        return None
    return base


def score_ssn(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    area, group, serial = m.group(0).split("-")
    if area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000":
        return None
    return base


def score_card(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    raw = m.group(0)
    digits = re.sub(r"[ -]", "", raw)
    has_separators = len(raw) != len(digits)
    if not has_separators and len(digits) not in (15, 16):
        return None            # bare 13-, 14-, 17-19-digit numbers are ids and timestamps, not cards
    if len(set(digits)) <= 2 or not luhn_ok(digits):
        return None
    return base


def score_ipv4(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    ip = m.group(0)
    if any(int(x) > 255 for x in ip.split(".")) or private_ip(ip):
        return None
    if VERSION_WORD.search(line) or not HOST_WORDS.search(line):
        return None
    return base


def score_always(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    return base


def score_first_person(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    if not is_prose_file(path) or CODE_LIKE.search(line) or len(line.split()) < MIN_PROSE_WORDS:
        return None
    return base


def score_own_name(m: re.Match, line: str, path: str, base: float) -> Optional[float]:
    """Each line of the private names file carries its own confidence (a shared surname lower)."""
    value = m.group(0)
    confidence = next((c for pattern, c in _own_names if pattern.fullmatch(value)), base)
    if COPYRIGHT_LINE.search(line) or LICENSE_FILES.match(os.path.basename(path)):
        return min(confidence, COPYRIGHT_CONFIDENCE)
    return confidence


# ---------------------------------------------------------------- the detectors

def _d(name, tier, regex, base, scorer, flags=0, requires="") -> Detector:
    return Detector(name, tier, re.compile(regex, flags), base, scorer, requires)


SECRET_DETECTORS = [
    _d("private-key", Tier.SECRET, r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0.99, score_always),
    _d("anthropic-key", Tier.SECRET, r"\bsk-ant-[A-Za-z0-9_-]{20,}", 0.99, score_vendor_key),
    _d("openai-key", Tier.SECRET, r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}", 0.90, score_vendor_key),
    _d("aws-access-key", Tier.SECRET, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.95, score_vendor_key),
    _d("github-token", Tier.SECRET, r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{36,}", 0.95, score_vendor_key),
    _d("slack-token", Tier.SECRET, r"\bxox[baprs]-[A-Za-z0-9-]{10,}", 0.95, score_vendor_key),
    _d("stripe-key", Tier.SECRET, r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}", 0.95, score_vendor_key),
    _d("twilio-sid", Tier.SECRET, r"\b(?:AC|SK)[0-9a-f]{32}\b", 0.85, score_vendor_key),
    _d("google-api-key", Tier.SECRET, r"\bAIza[0-9A-Za-z_-]{35}\b", 0.90, score_vendor_key),
    _d("sendgrid-key", Tier.SECRET, r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0.95, score_vendor_key),
    _d("jwt", Tier.SECRET, r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0.85, score_jwt),
    _d("url-with-credentials", Tier.SECRET,
       r"\b[a-z][a-z0-9+.-]*://(?P<user>[^/\s:@'\"]*):(?P<password>[^/\s@'\"]+)@(?P<host>[^/\s:'\"]+)", 0.90,
       score_url_credentials, re.I, requires="://"),
    _d("bearer-token", Tier.SECRET, r"\bBearer\s+(?P<token>[A-Za-z0-9._\-+/=]{20,})", 0.85, score_bearer_token, 0, "Bearer"),
    # DB_PASSWORD=, "api_key":, aws_secret_access_key = ...: any prefix, the secret word last
    _d("secret-assignment", Tier.SECRET,
       r"(?<![\w.])(?P<kq>['\"])?(?:[A-Za-z0-9]+[_-])*"
       r"(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret"
       r"|access[_-]?key|secret[_-]?key|credentials?)(?:_?\d+)?(?(kq)(?P=kq))(?![\w])"
       r"\s*[:=]\s*(?P<quote>['\"])?(?P<value>[^\s'\",;]{8,})(?(quote)(?P=quote))",
       0.80, score_secret_assignment, re.I),
]

PERSONAL_DETECTORS = [
    _d("email", Tier.PERSONAL, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.75, score_email, 0, "@"),
    _d("phone-e164", Tier.PERSONAL, r"(?<![\w.])\+[1-9][0-9]{9,14}\b", 0.85, score_always),
    _d("phone-us", Tier.PERSONAL,
       r"(?<![\w.-])\(?(?P<area>[2-9][0-9]{2})\)?[-. ](?P<exchange>[0-9]{3})[-. ](?P<last4>[0-9]{4})(?![\w.-])",
       0.60, score_phone_us),
    _d("ssn", Tier.PERSONAL, r"(?<![\w-])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![\w-])", 0.80, score_ssn),
    _d("card-number", Tier.PERSONAL, r"(?<![\w-])(?:[0-9][ -]?){12,18}[0-9](?![\w-])", 0.85, score_card),
    _d("public-ipv4", Tier.PERSONAL, r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])", 0.40, score_ipv4),
    _d("first-person", Tier.PERSONAL,
       r"(?<![\w'])(?:I|I'm|I am|I've|I'd|I'll|[Mm]e|[Mm]y|[Mm]ine|[Mm]yself)(?![\w'])", 0.65, score_first_person),
]

PATH_DETECTORS = [
    *[d for d in SECRET_DETECTORS if d.name != "secret-assignment"],
    _d("protected-path", Tier.SECRET, r".+", 0.95, lambda m, line, path, base: base if is_protected_path(path) else None),
]

ALL_DETECTORS = SECRET_DETECTORS + PERSONAL_DETECTORS

# D7: the owner's names. Read from the private pii-own-names file at run time; never in this repo.
OWN_NAME_DEFAULT_CONFIDENCE = 0.90
_own_names: list[tuple[re.Pattern, float]] = []


def set_own_names(entries: list[tuple[str, float]]) -> None:
    """Install the own-name detector for `entries` ((regex, confidence) each); empty removes it."""
    global _own_names
    _own_names = [(re.compile(pattern, re.I), confidence) for pattern, confidence in entries]
    for detectors in (ALL_DETECTORS, PATH_DETECTORS):
        detectors[:] = [d for d in detectors if d.name != "own-name"]
    if _own_names:
        combined = "|".join(f"(?:{pattern.pattern})" for pattern, _ in _own_names)
        detector = _d("own-name", Tier.PERSONAL, combined, OWN_NAME_DEFAULT_CONFIDENCE, score_own_name, re.I)
        ALL_DETECTORS.append(detector)
        PATH_DETECTORS.append(detector)


# ---------------------------------------------------------------- scanning

def _run(detectors: list[Detector], text: str, path: str, one_per_detector: bool) -> list[Hit]:
    hits: list[Hit] = []
    for detector in detectors:
        if detector.requires and detector.requires not in text:
            continue
        for m in detector.pattern.finditer(text):
            confidence = detector.score(m, text, path, detector.base)
            if confidence is None:
                continue
            tier = detector.tier
            if detector.name == "first-person" and is_protected_path(path):
                tier = Tier.SECRET            # D8: personal prose inside a protected file never ships
            value = m.group(0)
            hits.append(Hit(detector.name, tier, confidence, value, m.start(), m.end()))
            if one_per_detector or detector.name in ONE_PER_LINE:
                break
    return _drop_personal_inside_secret(hits)


def _drop_personal_inside_secret(hits: list[Hit]) -> list[Hit]:
    """One finding per secret: an email inside a credential URL, or a generic assignment match around
    a vendor key, is part of that secret, not a second finding. The most confident hit wins."""
    secrets = sorted((h for h in hits if h.tier is Tier.SECRET and h.detector != "first-person"),
                     key=lambda h: -h.confidence)
    kept_secrets: list[Hit] = []
    for hit in secrets:
        if not any(_overlaps(hit, k) for k in kept_secrets):
            kept_secrets.append(hit)
    others = [h for h in hits if h not in secrets
              and not any(k.start <= h.start and h.end <= k.end for k in kept_secrets)]
    return sorted(kept_secrets + others, key=lambda h: (h.start, h.detector))


def _overlaps(a: Hit, b: Hit) -> bool:
    return a.start < b.end and b.start < a.end


def scan_text(line: str, path: str) -> list[Hit]:
    """Every hit on one line of a file at `path`."""
    return _run(ALL_DETECTORS, line, path, one_per_detector=False)


def scan_path(path: str) -> list[Hit]:
    """Hits on the file name itself: a secret used as a file name."""
    return _run(PATH_DETECTORS, path, path, one_per_detector=True)
