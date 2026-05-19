import argparse
import os
import sys

from secretsweep.core.scanner import scan_directory
from secretsweep.core.git_scanner import scan_git_history
from secretsweep.core.ignorer import Ignorer
from secretsweep.core.config import load_config
from secretsweep.core.baseline import filter_new_findings, write_baseline
from secretsweep.core.deduplicator import deduplicate
from secretsweep.reporters.console import print_findings
from secretsweep.reporters.json_reporter import write_json
from secretsweep.reporters.sarif_reporter import write_sarif


def main():
    parser = argparse.ArgumentParser(
        description="SecretSweep - Scan for secrets and credentials in your codebase"
    )
    parser.add_argument("path", help="Path to the directory you want to scan")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument("--history", action="store_true", help="Scan git commit history")
    scan_group.add_argument("--depth", type=int, default=None, help="Number of git commits to scan (default: all)")
    scan_group.add_argument("--entropy", action="store_true", help="Enable entropy-based detection")
    scan_group.add_argument("--paths", action="store_true", help="Flag suspicious file paths by name/extension")
    scan_group.add_argument("--archives", action="store_true", help="Scan inside .zip and .tar archives")
    scan_group.add_argument("--k8s", action="store_true", help="Decode and scan Kubernetes Secret YAML files")
    scan_group.add_argument("--tf-state", action="store_true", dest="tf_state", help="Scan Terraform state files")

    output_group = parser.add_argument_group("output options")
    output_group.add_argument("--json", action="store_true", dest="json_output", help="Output findings as JSON")
    output_group.add_argument("--sarif", action="store_true", help="Output findings as SARIF")
    output_group.add_argument("--output", help="Write output to a file instead of stdout")

    config_group = parser.add_argument_group("config options")
    config_group.add_argument("--config", help="Path to .secretsweep.yaml config file")
    config_group.add_argument("--baseline", help="Only report findings not in this baseline file")
    config_group.add_argument("--write-baseline", dest="write_baseline", help="Write current findings to a baseline file")

    args = parser.parse_args()

    config = load_config(args.config)

    if config.get('custom_patterns'):
        from secretsweep.detectors.patterns import PATTERNS
        PATTERNS.extend(config['custom_patterns'])

    ignorer = Ignorer(os.path.join(args.path, '.secretsweepignore'))

    print(f"Scanning {args.path} ...", file=sys.stderr)
    findings = scan_directory(
        args.path,
        ignorer=ignorer,
        entropy=args.entropy,
        path_scan=args.paths,
        archives=args.archives,
        k8s=args.k8s,
        tf_state=args.tf_state,
        config=config,
    )

    if args.history:
        print(f"Scanning git history in {args.path} ...", file=sys.stderr)
        findings += scan_git_history(args.path, depth=args.depth)

    findings = deduplicate(findings)

    if args.baseline:
        findings = filter_new_findings(findings, args.baseline)

    if args.write_baseline:
        write_baseline(findings, args.write_baseline)
        print(f"Baseline written to {args.write_baseline}", file=sys.stderr)

    if args.json_output:
        write_json(findings, args.output)
    elif args.sarif:
        write_sarif(findings, args.output)
    else:
        print_findings(findings)

    if not findings:
        sys.exit(0)
    elif any(f.get('severity') == 'critical' for f in findings):
        sys.exit(2)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
