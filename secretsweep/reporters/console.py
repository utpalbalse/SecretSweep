def print_findings(findings):
    if not findings:
        print("No secrets found.")
        return

    print(f"\nFound {len(findings)} potential secret(s):\n")

    for finding in findings:
        print(f"  [{finding['severity'].upper()}] {finding['name']}")
        print(f"  File : {finding['file']}")
        print(f"  Line : {finding['line']}")
        print()
