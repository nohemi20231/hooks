"""What each detector flags, at what confidence, and what it leaves alone."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pushscan import policy  # noqa: E402
from pushscan.detectors import is_protected_path, looks_like_transcript, scan_path, scan_text, set_own_names, Tier  # noqa: E402
from fixtures import (ANTHROPIC_KEY, AWS_KEY, AWS_SECRET, CARD, E164_PHONE, ENCRYPTED_KEY_HEADER, GMAIL,  # noqa: E402
                      JWT_IO_SAMPLE, JWT_OTHER, PRIVATE_KEY_HEADER, PUBLIC_IP, RANDOM, RANDOM_LONG, SSN, US_PHONE,
                      US_PHONE_DASHED, WORK_EMAIL, assign, bearer, url)


def hits(text, path="app.py"):
    return scan_text(text, path)


def names(text, path="app.py"):
    return sorted(h.detector for h in hits(text, path))


class VendorKeys(unittest.TestCase):
    def test_anthropic_key_is_a_secret(self):
        h = hits(assign("KEY", ANTHROPIC_KEY))
        self.assertEqual([x.detector for x in h], ["anthropic-key"])
        self.assertEqual(h[0].tier, Tier.SECRET)

    def test_aws_key_is_a_secret(self):
        self.assertEqual(names(AWS_KEY), ["aws-access-key"])

    def test_rsa_private_key_block(self):
        self.assertEqual(names(PRIVATE_KEY_HEADER), ["private-key"])

    def test_other_jwt_is_a_secret(self):
        self.assertEqual(names(JWT_OTHER), ["jwt"])


class UrlsWithCredentials(unittest.TestCase):
    def test_real_looking_url(self):
        self.assertEqual(names(assign("DB", url("admin", "Qx7Lm2Vb9Tz4", "db.internal:5432", path="/app"))), ["url-with-credentials"])


class PersonalData(unittest.TestCase):
    def test_personal_email_scores_above_threshold(self):
        h = hits(assign("CONTACT", GMAIL), "notes.md")
        self.assertEqual(h[0].detector, "email")
        self.assertEqual(h[0].confidence, 0.85)
        self.assertEqual(h[0].tier, Tier.PERSONAL)

    def test_work_email_scores_below_threshold(self):
        self.assertEqual(hits(f"mail {WORK_EMAIL}", "notes.md")[0].confidence, 0.75)

    def test_e164_phone(self):
        self.assertEqual(hits(E164_PHONE, "notes.md")[0].confidence, 0.85)

    def test_us_phone_scores_low(self):
        self.assertEqual(hits(US_PHONE, "notes.md")[0].confidence, 0.60)

    def test_valid_ssn(self):
        self.assertEqual(names(f"ssn {SSN}", "notes.md"), ["ssn"])

    def test_luhn_valid_card(self):
        self.assertEqual(names(CARD, "notes.md"), ["card-number"])

    def test_public_ip_only_when_the_line_calls_it_a_host(self):
        self.assertEqual(names(f"host = {PUBLIC_IP}", "notes.md"), ["public-ipv4"])
        self.assertEqual(names("version 1.2.3.4", "notes.md"), [])


class LineShapes(unittest.TestCase):
    def test_uuid_is_ignored(self):
        self.assertEqual(names("id = 123e4567-e89b-12d3-a456-426614174000", "notes.md"), [])

    def test_git_sha_is_ignored(self):
        self.assertEqual(names("at 9fceb02d0ae598e95dc970b74767f19372d61af8", "notes.md"), [])

    def test_two_detectors_on_one_line_both_reported(self):
        line = assign("DB", url("admin", "Qx7Lm2Vb9Tz4", "db.internal", path="/app")) + f"  # ask {GMAIL}"
        self.assertEqual(names(line, "notes.md"), ["email", "url-with-credentials"])
