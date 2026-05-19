def print_findings(findings):
    if not findings:
        print("No secrets found.")
        return

    print(f"\nFound {len(findings)} potential secret(s):\n")

    for finding in findings:
        source = finding.get("source", "file")
        sev = f"[{finding['severity'].upper()}]"

        if source == "git_history":
            print(f"  {sev} {finding['name']}  (git history)")
            print(f"  File   : {finding['file']}")
            print(f"  Commit : {finding['commit']}")
            print(f"  Message: {finding['message']}")
            print(f"  Author : {finding['author']}")
        elif source == "path":
            print(f"  {sev} {finding['name']}")
            print(f"  File   : {finding['file']}")
            print(f"  Reason : {finding.get('reason', '')}")
        elif source == "entropy":
            print(f"  {sev} {finding['name']}")
            print(f"  File   : {finding['file']}")
            print(f"  Line   : {finding['line']}")
            print(f"  Value  : {finding.get('matched', '')}")
        elif source == "k8s_secret":
            print(f"  {sev} {finding['name']}  (kubernetes secret)")
            print(f"  File   : {finding['file']}")
            print(f"  Key    : {finding.get('k8s_key', '')}")
        elif source == "terraform_state":
            print(f"  {sev} {finding['name']}  (terraform state)")
            print(f"  File   : {finding['file']}")
            print(f"  Field  : {finding.get('tf_context', '')}")
        else:
            print(f"  {sev} {finding['name']}")
            print(f"  File   : {finding['file']}")
            if finding.get('line'):
                print(f"  Line   : {finding['line']}")

        print()

    _print_summary(findings)


def _print_summary(findings):
    print("─" * 52)
    print("  Summary")
    print("─" * 52)

    sev_counts = {}
    cat_counts = {}
    for f in findings:
        s = f.get('severity', 'unknown')
        c = f.get('category', 'unknown')
        sev_counts[s] = sev_counts.get(s, 0) + 1
        cat_counts[c] = cat_counts.get(c, 0) + 1

    print("  By severity:")
    for s in ['critical', 'high', 'medium', 'low']:
        if s in sev_counts:
            print(f"    {s.upper():<12} {sev_counts[s]}")

    print("  By category:")
    for c, count in sorted(cat_counts.items()):
        print(f"    {c:<15} {count}")
    print()
