def print_findings(findings):
    if not findings:
        print("No secrets found.")
        return

    print(f"\nFound {len(findings)} potential secret(s):\n")

    for finding in findings:
        source = finding.get("source", "file")

        if source == "git_history":
            print(f"  [{finding['severity'].upper()}] {finding['name']}  (git history)")
            print(f"  File   : {finding['file']}")
            print(f"  Commit : {finding['commit']}")
            print(f"  Message: {finding['message']}")
            print(f"  Author : {finding['author']}")
        else:
            print(f"  [{finding['severity'].upper()}] {finding['name']}")
            print(f"  File : {finding['file']}")
            print(f"  Line : {finding['line']}")

        print()
