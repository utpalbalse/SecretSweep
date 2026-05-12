import argparse
from secretsweep.core.scanner import scan_directory
from secretsweep.reporters.console import print_findings


def main():
    parser = argparse.ArgumentParser(
        description="SecretSweep - Scan for secrets and credentials in your codebase"
    )
    parser.add_argument(
        "path",
        help="Path to the directory you want to scan"
    )
    args = parser.parse_args()

    print(f"Scanning {args.path} ...")
    findings = scan_directory(args.path)
    print_findings(findings)


if __name__ == "__main__":
    main()
