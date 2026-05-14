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
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
        "severity": "critical",
    },
    {
        "name": "GitHub Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "critical",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "severity": "critical",
    },
    {
        "name": "Database URL",
        "pattern": r"(?i)(postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",
        "severity": "critical",
    },
    {
        "name": "Hardcoded Password",
        "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"]?\S{6,}",
        "severity": "high",
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        "severity": "high",
    },
]