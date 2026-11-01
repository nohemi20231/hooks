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

    def test_key_made_of_the_word_fake_is_a_placeholder(self):
        self.assertEqual(names("AKIAFAKEFAKEFAKEFAKE is an example key"), [])

    def test_key_with_example_inside_is_a_placeholder(self):
        self.assertEqual(names('sk-ant-api03-EXAMPLEEXAMPLEEXAMPLEEXAMPLE'), [])

    def test_rsa_private_key_block(self):
        self.assertEqual(names(PRIVATE_KEY_HEADER), ["private-key"])

    def test_jwt_io_sample_token_is_a_placeholder(self):
        self.assertEqual(names(JWT_IO_SAMPLE), [])

    def test_other_jwt_is_a_secret(self):
        self.assertEqual(names(JWT_OTHER), ["jwt"])


class SecretAssignments(unittest.TestCase):
    def test_vendor_key_assigned_to_a_secret_name_is_reported_once(self):
        # both the vendor pattern and the assignment pattern match; only the more specific hit stays
        h = hits(assign("API_KEY", ANTHROPIC_KEY))
        self.assertEqual([x.detector for x in h], ["anthropic-key"])

    def test_quoted_password_literal(self):
        self.assertEqual(names(assign("password", "Tr0ub4dor&3xyz")), ["secret-assignment"])

    def test_yaml_style_token(self):
        self.assertEqual(names(assign("api_key", "Qx7Lm2Vb9Tz4Rk8Pw1Yn", quote="'", sep=": ")), ["secret-assignment"])

    def test_django_field_is_not_a_secret(self):
        self.assertEqual(names("password = models.CharField(max_length=128)"), [])

    def test_type_annotation_is_not_a_secret(self):
        self.assertEqual(names("api_key: Optional[str] = None"), [])

    def test_tokenizer_variable_is_not_a_secret(self):
        self.assertEqual(names('tokenizer = AutoTokenizer.from_pretrained("gpt2")'), [])

    def test_token_ttl_is_not_a_secret(self):
        self.assertEqual(names("TOKEN_TTL = timedelta(hours=1)"), [])

    def test_zod_schema_is_not_a_secret(self):
        self.assertEqual(names("password: z.string().min(8),"), [])

    def test_password_hash_call_is_not_a_secret(self):
        self.assertEqual(names("password_hash = hash_password(raw)"), [])

    def test_env_lookup_is_not_a_secret(self):
        self.assertEqual(names('password = os.environ["DB_PASSWORD"]'), [])

    def test_changeme_is_a_placeholder(self):
        self.assertEqual(names('password = "changeme"'), [])

    def test_short_value_is_ignored(self):
        self.assertEqual(names('password = "abc"'), [])


class UrlsWithCredentials(unittest.TestCase):
    def test_real_looking_url(self):
        self.assertEqual(names(assign("DB", url("admin", "Qx7Lm2Vb9Tz4", "db.internal:5432", path="/app"))), ["url-with-credentials"])

    def test_empty_user_part(self):
        self.assertEqual(names(url("", "Qx7Lm2Vb9Tz4Rk8P", "redis:6379", scheme="redis")), ["url-with-credentials"])

    def test_variable_password_is_not_a_secret(self):
        self.assertEqual(names("DATABASE_URL=postgres://app:${DB_PASS}@db:5432/app"), [])

    def test_localhost_dev_credentials_are_not_a_secret(self):
        self.assertEqual(names("URL=postgres://app:app@localhost:5432/app"), [])

    def test_example_host_is_a_placeholder(self):
        self.assertEqual(names("https://user:password@example.com/api"), [])


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


class CommonSecretShapes(unittest.TestCase):
    """Reviewer item 12: the .env / config.json shapes."""
    def test_prefixed_env_names(self):
        for line in (assign("DB_PASSWORD", RANDOM), assign("OPENAI_API_KEY", RANDOM_LONG, quote="", sep="="),
                     assign("AWS_SECRET_ACCESS_KEY", AWS_SECRET, sep="="), assign("STRIPE_SECRET_KEY", RANDOM),
                     assign("JWT_SECRET", RANDOM + "9f8e7d", quote="", sep="=")):
            self.assertIn("secret-assignment", names(line), line)

    def test_json_quoted_keys(self):
        self.assertIn("secret-assignment", names(assign("password", RANDOM, sep=": ", key_quote='"'), "config.json"))
        self.assertIn("secret-assignment", names(assign("api_key", RANDOM, quote="'", sep=": ", key_quote="'")))

    def test_plain_word_value_in_a_dotenv_file_counts(self):
        plain = assign("DB_PASSWORD", "supersecretpassword", quote="", sep="=")
        self.assertIn("secret-assignment", names(plain, ".env"))
        self.assertIn("secret-assignment", names(plain, "deploy/.env.production"))

    def test_plain_word_value_in_code_does_not(self):
        self.assertEqual(names(assign("DB_PASSWORD", "supersecretpassword", quote="", sep="="), "settings.py"), [])

    def test_bearer_token(self):
        self.assertIn("bearer-token", names(bearer(RANDOM + ".9f8e7d6c5b4a3f2e1d")))
        self.assertEqual(names(bearer("<token>")), [])

    def test_token_url_is_not_a_secret(self):
        self.assertEqual(names('token_url = "https://auth.example.com/oauth/token"'), [])


if __name__ == "__main__":
    unittest.main()


# made-up names for the tests; real names live only in the private ~/.claude/hooks/pii-own-names file
FAKE_OWN_NAMES = [("zandrika(vell)?", 0.90), ("vellanquist", 0.70)]


class FirstPerson(unittest.TestCase):
    """D7: prose about the owner. Code and short fragments are not prose."""
    def test_first_person_prose_in_markdown(self):
        h = hits("Today I felt that my session went badly and I am tired.", "journal.md")
        self.assertEqual([x.detector for x in h], ["first-person"])
        self.assertEqual(h[0].confidence, 0.65)

    def test_first_person_in_code_file_is_ignored(self):
        self.assertEqual(names("# I think this loop is slow and my fix is below", "app.py"), [])

    def test_short_fragment_is_not_prose(self):
        self.assertEqual(names("me", "notes.md"), [])

    def test_code_like_line_in_markdown_is_ignored(self):
        self.assertEqual(names("const me = users.find(u => u.id === myId);", "README.md"), [])

    def test_first_person_is_reported_once_per_line(self):
        self.assertEqual(names("I think I should say that I am fine and my day was good.", "notes.md"), ["first-person"])


class OwnNames(unittest.TestCase):
    """D7: the owner's names come from a private file; each line carries its own confidence."""
    def setUp(self):
        set_own_names(FAKE_OWN_NAMES)

    def tearDown(self):
        set_own_names([])

    def test_first_name_in_content_is_auto_tier(self):
        h = hits("Author: Zandrika Vellanquist", "README.md")
        self.assertEqual([(x.detector, x.confidence) for x in h], [("own-name", 0.90)])

    def test_handle_in_a_path_string(self):
        self.assertEqual(names('base = "/Users/zandrikavell/workspace"', "settings.py"), ["own-name"])

    def test_match_is_case_insensitive(self):
        self.assertEqual(names("ZANDRIKA"), ["own-name"])

    def test_name_in_a_path(self):
        self.assertEqual([h.detector for h in scan_path("docs/zandrika-notes.md")], ["own-name"])

    def test_no_names_configured_means_no_detector(self):
        set_own_names([])
        self.assertEqual(names("Author: Zandrika Vellanquist", "README.md"), [])


class OwnNamesFile(unittest.TestCase):
    """policy.load_own_names: one pattern per line, optional confidence, # comments, BOM tolerated."""
    def _file(self, text):
        self.dir = tempfile.TemporaryDirectory()
        path = os.path.join(self.dir.name, "pii-own-names")
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write(text)
        return path

    def tearDown(self):
        if hasattr(self, "dir"):
            self.dir.cleanup()

    def test_parses_patterns_and_confidence(self):
        path = self._file("# names\nzandrika(vell)?\nvellanquist 0.70\n\n")
        self.assertEqual(policy.load_own_names(path), [("zandrika(vell)?", 0.90), ("vellanquist", 0.70)])

    def test_missing_file_means_no_names(self):
        self.assertEqual(policy.load_own_names("/nonexistent/pii-own-names"), [])

    def test_bad_pattern_is_an_error_naming_the_line_not_the_pattern(self):
        path = self._file("zandrika\n(unclosed\n")
        with self.assertRaises(policy.OwnNamesError) as ctx:
            policy.load_own_names(path)
        self.assertIn("line 2", str(ctx.exception))
        self.assertNotIn("unclosed", str(ctx.exception))

    def test_confidence_outside_zero_to_one_is_an_error(self):
        path = self._file("zandrika 1.5\n")
        with self.assertRaises(policy.OwnNamesError):
            policy.load_own_names(path)
