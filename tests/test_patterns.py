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

def test_cicd_hardcoded_secret_detected():
    pattern = get_pattern("CI/CD Hardcoded Secret")
    assert regex.search(pattern, "password: mysecretvalue123") is not None

def test_cicd_hardcoded_secret_skips_template():
    pattern = get_pattern("CI/CD Hardcoded Secret")
    assert regex.search(pattern, "password: ${{ secrets.MY_PASSWORD }}") is None

def test_gcp_service_account_detected():
    pattern = get_pattern("GCP Service Account")
    assert regex.search(pattern, '"type": "service_account"') is not None

def test_azure_storage_connection_string_detected():
    pattern = get_pattern("Azure Storage Connection String")
    assert regex.search(pattern, "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789jkl012mno345pqr678==") is not None

def test_azure_sas_token_detected():
    pattern = get_pattern("Azure SAS Token")
    assert regex.search(pattern, "sv=2021-06-08&se=2023-01-01T00:00:00Z&sig=abcDEFghiJKLmnoPQRstuvwxyz1234567890ABCD==") is not None

def test_dockerfile_secret_detected():
    pattern = get_pattern("Dockerfile Secret")
    assert regex.search(pattern, "ENV DATABASE_URL=postgres://user:pass@host/db") is not None

def test_shopify_access_token_detected():
    pattern = get_pattern("Shopify Access Token")
    assert regex.search(pattern, "shpat_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456") is not None

def test_shopify_custom_app_token_detected():
    pattern = get_pattern("Shopify Access Token")
    assert regex.search(pattern, "shpca_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456") is not None

def test_npm_auth_token_detected():
    pattern = get_pattern("NPM Auth Token")
    assert regex.search(pattern, "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890") is not None

def test_hashicorp_vault_token_detected():
    pattern = get_pattern("HashiCorp Vault Token")
    vault_token = "hvs." + "A" * 90
    assert regex.search(pattern, vault_token) is not None

def test_cloudflare_api_token_detected():
    pattern = get_pattern("Cloudflare API Token")
    assert regex.search(pattern, "CLOUDFLARE_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd") is not None

def test_discord_bot_token_detected():
    pattern = get_pattern("Discord Bot Token")
    assert regex.search(pattern, "MTIzNDU2Nzg5MDEyMzQ1NjcA.ABcdef.ABcDeFgHiJkLmNoPqRsTuVwXyZ12") is not None

def test_ethereum_private_key_detected():
    pattern = get_pattern("Ethereum Private Key")
    eth_key = "private_key=0x" + "a1b2c3d4" * 8
    assert regex.search(pattern, eth_key) is not None

def test_pgp_private_key_detected():
    pattern = get_pattern("PGP Private Key")
    assert regex.search(pattern, "-----BEGIN PGP PRIVATE KEY BLOCK-----") is not None

def test_dsa_private_key_detected():
    pattern = get_pattern("Private Key Header")
    assert regex.search(pattern, "-----BEGIN DSA PRIVATE KEY-----") is not None

def test_aws_sts_token_detected():
    pattern = get_pattern("AWS STS Session Token")
    assert regex.search(pattern, "ASIAIOSFODNN7EXAMPLE") is not None

def test_gitlab_pat_detected():
    pattern = get_pattern("GitLab PAT")
    assert regex.search(pattern, "glpat-aBcDeFgHiJkLmNoPqRsT") is not None

def test_twilio_api_key_detected():
    pattern = get_pattern("Twilio API Key")
    assert regex.search(pattern, "SKabcdef1234567890abcdef1234567890ab") is not None

def test_sendgrid_api_key_detected():
    pattern = get_pattern("SendGrid API Key")
    assert regex.search(pattern, "SG.aBcDeFgHiJkLmNoPqRsTuV.wXyZ1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890a") is not None

def test_huggingface_token_detected():
    pattern = get_pattern("HuggingFace Token")
    assert regex.search(pattern, "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678") is not None

def test_openai_api_key_detected():
    pattern = get_pattern("OpenAI API Key")
    assert regex.search(pattern, "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefgh") is not None

def test_datadog_api_key_detected():
    pattern = get_pattern("Datadog API Key")
    assert regex.search(pattern, "DD_API_KEY=abcdef1234567890abcdef1234567890") is not None

def test_sentry_dsn_detected():
    pattern = get_pattern("Sentry DSN")
    assert regex.search(pattern, "https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/789") is not None

def test_facebook_token_detected():
    pattern = get_pattern("Facebook Access Token")
    assert regex.search(pattern, "EAAGaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890") is not None

def test_bearer_token_detected():
    pattern = get_pattern("Bearer Token")
    assert regex.search(pattern, "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") is not None

def test_mailchimp_api_key_detected():
    pattern = get_pattern("Mailchimp API Key")
    # Split to avoid GitHub push protection flagging this file
    fake_key = "abcdef1234567890abcdef1234567890" + "-us12"
    assert regex.search(pattern, fake_key) is not None

def test_terraform_cloud_token_detected():
    pattern = get_pattern("Terraform Cloud Token")
    fake_token = "abcdefghijklmn.atlasv1." + "A" * 60
    assert regex.search(pattern, fake_token) is not None

def test_gcp_oauth_token_detected():
    pattern = get_pattern("GCP OAuth Token")
    assert regex.search(pattern, "ya29." + "A" * 50) is not None
