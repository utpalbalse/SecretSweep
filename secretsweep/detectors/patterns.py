PATTERNS = [
    # Cloud
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical", "category": "cloud"},
    {"name": "AWS STS Session Token", "pattern": r"ASIA[0-9A-Z]{16}", "severity": "critical", "category": "cloud"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "severity": "critical", "category": "cloud"},
    {"name": "GCP Service Account", "pattern": r'"type"\s*:\s*"service_account"', "severity": "critical", "category": "cloud"},
    {"name": "GCP OAuth Token", "pattern": r"ya29\.[A-Za-z0-9_-]{50,}", "severity": "high", "category": "cloud"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high", "category": "cloud"},
    {"name": "Azure Storage Connection String", "pattern": r"DefaultEndpointsProtocol=https?;AccountName=\w+;AccountKey=[A-Za-z0-9+/=]{20,}", "severity": "critical", "category": "cloud"},
    {"name": "Azure SAS Token", "pattern": r"sv=\d{4}-\d{2}-\d{2}.*?sig=[A-Za-z0-9%+/=]{20,}", "severity": "high", "category": "cloud"},
    {"name": "Cloudflare API Token", "pattern": r"(?i)(cloudflare|cf)[-_]?(api[-_]?)?token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{35,45}['\"]?", "severity": "critical", "category": "cloud"},

    # Crypto
    {"name": "Private Key Header", "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical", "category": "crypto"},
    {"name": "PGP Private Key", "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "severity": "critical", "category": "crypto"},
    {"name": "Ethereum Private Key", "pattern": r"(?i)(private.?key|eth.?key|wallet.?key)\s*[=:]\s*['\"]?0x[a-fA-F0-9]{64}['\"]?", "severity": "critical", "category": "crypto"},

    # Database
    {"name": "Database URL", "pattern": r"(?i)(postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@]+@", "severity": "critical", "category": "database"},

    # API / SaaS
    {"name": "Generic API Key", "pattern": r"(?i)(api_key|apikey|api-key)\s*=\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "severity": "high", "category": "api"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "severity": "high", "category": "api"},
    {"name": "Stripe Secret Key", "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}", "severity": "critical", "category": "api"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[A-Za-z0-9\-]{10,}", "severity": "high", "category": "api"},
    {"name": "Discord Bot Token", "pattern": r"[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", "severity": "critical", "category": "api"},
    {"name": "Shopify Access Token", "pattern": r"shp(at|ca|ss)_[A-Za-z0-9]{32}", "severity": "critical", "category": "api"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "critical", "category": "api"},
    {"name": "SendGrid API Key", "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "severity": "critical", "category": "api"},
    {"name": "HuggingFace Token", "pattern": r"hf_[A-Za-z0-9]{34,}", "severity": "critical", "category": "api"},
    {"name": "OpenAI API Key", "pattern": r"sk-[A-Za-z0-9_-]{32,}", "severity": "critical", "category": "api"},
    {"name": "Datadog API Key", "pattern": r"(?i)(dd_api_key|datadog_api_key|dd-api-key)\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", "severity": "high", "category": "api"},
    {"name": "Sentry DSN", "pattern": r"https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+", "severity": "high", "category": "api"},
    {"name": "Facebook Access Token", "pattern": r"EAAG[A-Za-z0-9]{20,}", "severity": "high", "category": "api"},
    {"name": "Bearer Token", "pattern": r"(?i)authorization\s*[=:]\s*['\"]?bearer\s+[A-Za-z0-9_\-\.]{20,}['\"]?", "severity": "high", "category": "api"},
    {"name": "Mailchimp API Key", "pattern": r"[a-f0-9]{32}-us[0-9]{1,2}", "severity": "critical", "category": "api"},

    # CI/CD / VCS
    {"name": "GitHub Token", "pattern": r"ghp_[A-Za-z0-9]{36}", "severity": "critical", "category": "cicd"},
    {"name": "GitLab PAT", "pattern": r"glpat-[A-Za-z0-9_-]{20}", "severity": "critical", "category": "cicd"},
    {"name": "NPM Auth Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "critical", "category": "cicd"},
    {"name": "HashiCorp Vault Token", "pattern": r"hvs\.[A-Za-z0-9_-]{90,}", "severity": "critical", "category": "cicd"},
    {"name": "Terraform Cloud Token", "pattern": r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}", "severity": "critical", "category": "cicd"},
    {"name": "CI/CD Hardcoded Secret", "pattern": r"(?i)(password|secret|token|api_key)\s*:\s*(?!\$)['\"]?[A-Za-z0-9_\-+=]{10,}['\"]?", "severity": "high", "category": "cicd"},
    {"name": "Dockerfile Secret", "pattern": r"(?i)ENV\s+(PASSWORD|SECRET|API_KEY|TOKEN|DATABASE_URL)\s*[=\s]\s*\S{6,}", "severity": "high", "category": "cicd"},

    # Config
    {"name": "Hardcoded Password", "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"]?\S{6,}", "severity": "high", "category": "config"},
]
