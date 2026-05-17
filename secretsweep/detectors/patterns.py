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
    {
        "name": "CI/CD Hardcoded Secret",
        "pattern": r"(?i)(password|secret|token|api_key)\s*:\s*(?!\$)['\"]?[A-Za-z0-9_\-+=]{10,}['\"]?",
        "severity": "high",
    },
    {
        "name": "GCP Service Account",
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
    },
    {
        "name": "Azure Storage Connection String",
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=\w+;AccountKey=[A-Za-z0-9+/=]{20,}",
        "severity": "critical",
    },
    {
        "name": "Azure SAS Token",
        "pattern": r"sv=\d{4}-\d{2}-\d{2}.*?sig=[A-Za-z0-9%+/=]{20,}",
        "severity": "high",
    },
    {
        "name": "Dockerfile Secret",
        "pattern": r"(?i)ENV\s+(PASSWORD|SECRET|API_KEY|TOKEN|DATABASE_URL)\s*[=\s]\s*\S{6,}",
        "severity": "high",
    },
    {
        "name": "Shopify Access Token",
        "pattern": r"shp(at|ca|ss)_[A-Za-z0-9]{32}",
        "severity": "critical",
    },
    {
        "name": "NPM Auth Token",
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": "critical",
    },
    {
        "name": "HashiCorp Vault Token",
        "pattern": r"hvs\.[A-Za-z0-9_-]{90,}",
        "severity": "critical",
    },
    {
        "name": "Cloudflare API Token",
        "pattern": r"(?i)(cloudflare|cf)[-_]?(api[-_]?)?token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{35,45}['\"]?",
        "severity": "critical",
    },
    {
        "name": "Discord Bot Token",
        "pattern": r"[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
        "severity": "critical",
    },
    {
        "name": "Ethereum Private Key",
        "pattern": r"(?i)(private.?key|eth.?key|wallet.?key)\s*[=:]\s*['\"]?0x[a-fA-F0-9]{64}['\"]?",
        "severity": "critical",
    },
    {
        "name": "PGP Private Key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "critical",
    },
]