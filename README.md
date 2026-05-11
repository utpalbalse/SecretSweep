# SecretSweep

A continuous secret scanner that detects exposed credentials, API keys, tokens,
and other sensitive data across codebases, git histories, config files,
CI/CD pipelines, containers, Kubernetes manifests, IaC files, and cloud surfaces.

## What It Detects
- API keys and access tokens
- SSH private keys
- Database connection strings and credentials
- JWT tokens
- Hardcoded passwords
- .env and config file secrets
- Cloud credentials (AWS, GCP, Azure)
- Git history secrets

## Scan Targets (Planned)
- Local codebases and file systems
- Git commit history
- CI/CD pipeline configs (GitHub Actions, GitLab CI, Jenkins)
- Docker and container images
- Kubernetes manifests
- IaC files (Terraform, CloudFormation, Ansible)
- Cloud provider surfaces

## Status
🚧 Under active development