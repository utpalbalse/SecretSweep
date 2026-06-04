# SecretSweep

SecretSweep is a command-line secret scanner that finds accidentally committed credentials in source code. It covers the full surface area of a typical repo: source files, git commit history, Kubernetes Secret manifests, Terraform state files, and compressed archives.

Detection works in two layers. The first layer matches 36 known credential formats using regex patterns covering cloud providers, databases, CI/CD tokens, and popular APIs. The second layer uses Shannon entropy to flag high-randomness strings that don't match any known pattern, catching secrets with custom or proprietary formats.

Output options include a color-coded terminal table, JSON, and SARIF. The SARIF output can be uploaded directly to GitHub Code Scanning. Exit codes (0/1/2) are designed to integrate with CI pipelines.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-98%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What It Detects

| Category | Patterns |
|---|---|
| Cloud | AWS Access Key, AWS Secret Key, AWS STS Token, GCP Service Account, Azure Connection String, Azure SAS Token, Cloudflare API Token, Google API Key |
| Crypto | Private Key (RSA/DSA/EC/OpenSSH), PGP Private Key |
| Database | Database URL (PostgreSQL, MySQL, MongoDB, Redis) |
| API | OpenAI, HuggingFace, Twilio, SendGrid, Stripe, Shopify, Discord, Datadog, Sentry, Slack, Facebook, Bearer Token, Generic API Key, JWT |
| CI/CD | GitHub Token, GitLab PAT, NPM Auth Token, Vault Token, Terraform Cloud Token, Dockerfile Secret, CI/CD Hardcoded Secret |
| Config | Hardcoded Password |

Plus **entropy-based detection** using Shannon entropy for high-randomness strings with no known prefix, catching secrets that don't match any fixed format.

---

## Scan Surfaces

```bash
secretsweep ./my-repo                   # scan all files
secretsweep ./my-repo --history         # scan full git commit history
secretsweep ./my-repo --entropy         # add entropy-based detection
secretsweep ./my-repo --paths           # flag sensitive filenames (.env, id_rsa, *.pem)
secretsweep ./my-repo --k8s             # decode & scan Kubernetes Secret YAML files
secretsweep ./my-repo --tf-state        # scan Terraform .tfstate files
secretsweep ./my-repo --archives        # scan inside .zip and .tar archives
secretsweep ./my-repo --workers 8       # parallel scan with 8 threads
```

---

## Output Formats

**Console (default)** — color-coded findings table with severity badges and a category breakdown summary

**JSON**
```bash
secretsweep . --json --output findings.json
```

**SARIF**
```bash
secretsweep . --sarif --output findings.sarif
```

Exit codes: `0` (clean), `1` (findings present), `2` (critical findings).

---

## Baseline Suppression

Suppress known findings so future scans only surface *new* secrets:

```bash
# capture current state
secretsweep . --write-baseline baseline.json

# subsequent runs only report new findings
secretsweep . --baseline baseline.json
```

---

## Config File

Place `.secretsweep.yaml` at the repo root:

```yaml
entropy_threshold: 4.5
entropy_min_length: 20
ignore_paths:
  - tests/
  - docs/
custom_patterns:
  - name: "Internal API Key"
    pattern: 'corp_[a-zA-Z0-9]{32}'
    severity: critical
    category: api
```

---

## Ignore File

Place `.secretsweepignore` at the repo root. Supports glob patterns:

```
tests/fixtures/
*.example
docs/
```

---

## Install

```bash
git clone https://github.com/utpalbalse/SecretSweep.git
cd SecretSweep
pip install -e .
secretsweep --help
```

---

## Tests

```bash
pytest   # 98 tests across 12 modules
```
