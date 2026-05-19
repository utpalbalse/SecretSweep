import math
import regex

_UUID_RE = regex.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', regex.I
)
_GIT_HASH_RE = regex.compile(r'^[0-9a-f]{40}$', regex.I)
_BASE64_RE = regex.compile(r'[A-Za-z0-9+/=]{20,}')


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_false_positive(s):
    if _GIT_HASH_RE.match(s):
        return True
    if _UUID_RE.match(s.replace('-', '')):
        return True
    if len(set(s)) <= 3:
        return True
    return False


def scan_content_for_entropy(content, filepath, config=None):
    threshold = config.get('entropy_threshold', 4.5) if config else 4.5
    min_length = config.get('entropy_min_length', 20) if config else 20

    findings = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for match in _BASE64_RE.finditer(line):
            s = match.group()
            if len(s) < min_length or _is_false_positive(s):
                continue
            if _shannon_entropy(s) >= threshold:
                findings.append({
                    "file": filepath,
                    "line": line_number,
                    "name": "High Entropy String",
                    "severity": "high",
                    "category": "entropy",
                    "source": "entropy",
                    "matched": s[:60] + ('...' if len(s) > 60 else ''),
                })
                break
    return findings
