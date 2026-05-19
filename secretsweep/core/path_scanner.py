import os

SENSITIVE_EXTENSIONS = {
    '.pem':      ('Private Key / Certificate', 'critical'),
    '.key':      ('Private Key File', 'critical'),
    '.p12':      ('PKCS#12 Certificate Bundle', 'critical'),
    '.pfx':      ('PKCS#12 Certificate Bundle', 'critical'),
    '.jks':      ('Java Keystore', 'critical'),
    '.keystore': ('Android Keystore', 'critical'),
    '.der':      ('DER Certificate', 'high'),
    '.crt':      ('Certificate File', 'high'),
    '.cert':     ('Certificate File', 'high'),
}

SENSITIVE_NAMES = {
    'id_rsa':                    ('SSH Private Key', 'critical'),
    'id_dsa':                    ('SSH Private Key', 'critical'),
    'id_ecdsa':                  ('SSH Private Key', 'critical'),
    'id_ed25519':                ('SSH Private Key', 'critical'),
    '.env':                      ('Environment File', 'high'),
    '.env.local':                ('Environment File', 'high'),
    '.env.production':           ('Environment File', 'critical'),
    'credentials':               ('Credentials File', 'high'),
    'secrets':                   ('Secrets File', 'high'),
    '.htpasswd':                 ('HTTP Password File', 'critical'),
    'google-services.json':      ('Firebase Config', 'high'),
    'googleservice-info.plist':  ('Firebase iOS Config', 'high'),
    'terraform.tfvars':          ('Terraform Variables', 'high'),
    'terraform.tfstate':         ('Terraform State', 'critical'),
}


def scan_path(filepath):
    findings = []
    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename)

    if ext.lower() in SENSITIVE_EXTENSIONS:
        label, severity = SENSITIVE_EXTENSIONS[ext.lower()]
        findings.append({
            "file": filepath,
            "line": None,
            "name": f"Sensitive File: {label}",
            "severity": severity,
            "category": "path",
            "source": "path",
            "reason": f"Extension {ext} indicates a {label}",
        })

    if filename.lower() in SENSITIVE_NAMES:
        label, severity = SENSITIVE_NAMES[filename.lower()]
        findings.append({
            "file": filepath,
            "line": None,
            "name": f"Sensitive File: {label}",
            "severity": severity,
            "category": "path",
            "source": "path",
            "reason": f"File name '{filename}' indicates {label}",
        })

    return findings
