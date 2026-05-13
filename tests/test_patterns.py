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

def test_private_key_detected():
    pattern = get_pattern("Private Key Header")
    assert regex.search(pattern, "-----BEGIN RSA PRIVATE KEY-----") is not None

def test_jwt_detected():
    pattern = get_pattern("JWT Token")
    assert regex.search(pattern, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") is not None
