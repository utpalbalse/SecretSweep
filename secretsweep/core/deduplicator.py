def deduplicate(findings):
    seen = set()
    result = []
    for f in findings:
        key = (
            f.get('file', ''),
            str(f.get('line', '')),
            f.get('name', ''),
            f.get('commit', ''),
            f.get('k8s_key', ''),
            f.get('tf_context', ''),
        )
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
