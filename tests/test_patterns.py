import regex
from secretsweep.detectors.patterns import PATTERNS


def get_pattern(name):
    for p in PATTERNS:
        if p["name"] == name:
            return p["pattern"]
    return None


def test_aws_key_detected():
    pattern = get_pattern("AWS Access Key")
    assert regex.search(pattern, "AKIAIOSFODNN7EXAMPLE") is not None

def test_aws_key_not_false_positive():
    pattern = get_pattern("AWS Access Key")
    assert regex.search(pattern, "this is just normal text") is None

def test_aws_secret_key_detected():
    pattern = get_pattern("AWS Secret Access Key")
    assert regex.search(pattern, "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") is not None

def test_private_key_detected():
    pattern = get_pattern("Private Key Header")
    assert regex.search(pattern, "-----BEGIN RSA PRIVATE KEY-----") is not None

def test_jwt_detected():
    pattern = get_pattern("JWT Token")
    assert regex.search(pattern, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") is not None

def test_github_token_detected():
    pattern = get_pattern("GitHub Token")
    assert regex.search(pattern, "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890") is not None

def test_google_api_key_detected():
    pattern = get_pattern("Google API Key")
    assert regex.search(pattern, "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567") is not None

def test_stripe_key_detected():
    pattern = get_pattern("Stripe Secret Key")
    # Split across concatenation so GitHub's static scanner doesn't flag this file
    fake_key = "sk_live_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    assert regex.search(pattern, fake_key) is not None

def test_database_url_detected():
    pattern = get_pattern("Database URL")
    assert regex.search(pattern, "postgres://admin:supersecret@localhost:5432/mydb") is not None

def test_hardcoded_password_detected():
    pattern = get_pattern("Hardcoded Password")
    assert regex.search(pattern, 'password="mysecretpassword"') is not None

def test_slack_token_detected():
    pattern = get_pattern("Slack Token")
    assert regex.search(pattern, "xoxb-123456789-abcdefghij") is not None
