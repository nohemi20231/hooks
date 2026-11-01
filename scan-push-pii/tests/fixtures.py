"""Secret-shaped and personal-shaped values for the tests.

Every value is assembled at run time from parts, so that no single line of this repository
looks like a secret or a personal value to the hook that guards it. tests/test_repo_scan.py
fails if a fixture breaks this rule. None of these values is real.
"""


def joined(*parts: str) -> str:
    return "".join(parts)


# secrets
ANTHROPIC_KEY = joined("sk-ant-api03-", "Qx7Lm2Vb9Tz4Rk8Pw1Yn6Hs3Jd5Fg0Cv")
AWS_KEY = joined("AKIA", "Q7LM2VB9TZ4RK8PW")
RANDOM = "Xk9mPq2vL7nR4wQz"                     # random-looking; not a secret until assigned to a secret name
RANDOM_LONG = RANDOM + "1234"
AWS_SECRET = joined("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCYzz")
PRIVATE_KEY_HEADER = joined("-----BEGIN RSA ", "PRIVATE KEY-----")
ENCRYPTED_KEY_HEADER = joined("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----")
JWT_IO_SAMPLE = ".".join(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                          "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
                          "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])
JWT_OTHER = ".".join(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                      "eyJzdWIiOiJ1c2VyLTkxODIiLCJvcmciOiJ0aGVyYXB5IiwiaWF0IjoxNzMwNDAwMDAwfQ",
                      "Qm9ndXNTaWduYXR1cmVCb2d1c1NpZ25hdHVyZTEyMzQ1Njc4OTA"])

# personal data
GMAIL = joined("someone.real", "@gmail.com")
WORK_EMAIL = joined("someone", "@acme-corp.com")
US_PHONE = joined("(214) 867-", "5309")
US_PHONE_DASHED = joined("214-867-", "5309")
E164_PHONE = joined("+1469", "5551234")
SSN = joined("123-45-", "6789")
CARD = joined("4532 0151 1283 ", "0366")
PUBLIC_IP = joined("203.0.113", ".7")


def assign(key: str, value: str, quote: str = '"', sep: str = " = ", key_quote: str = "") -> str:
    """`key = "value"` and its YAML / JSON / .env variants."""
    return f"{key_quote}{key}{key_quote}{sep}{quote}{value}{quote}"


def url(user: str, password: str, host: str, scheme: str = "postgres", path: str = "") -> str:
    return f"{scheme}://{user}:{password}@{host}{path}"


def bearer(token: str) -> str:
    return joined("Authorization: ", "Bearer ", token)
