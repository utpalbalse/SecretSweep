PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
    },
    {
        "name": "Private Key Header",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api_key|apikey|api-key)\s*=\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        "severity": "high",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
    },
]