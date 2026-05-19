import git
import regex
from secretsweep.detectors.patterns import PATTERNS


def scan_git_history(repo_path, depth=None):
    repo = git.Repo(repo_path, search_parent_directories=True)
    all_findings = []

    commits = list(repo.iter_commits())
    if depth is not None:
        commits = commits[:depth]

    for commit in commits:
        if commit.parents:
            diffs = commit.parents[0].diff(commit, create_patch=True)
        else:
            diffs = commit.diff(git.NULL_TREE, create_patch=True)

        for diff in diffs:
            if not diff.diff:
                continue

            patch = diff.diff.decode('utf-8', errors='ignore')

            for line in patch.split('\n'):
                if line.startswith('+') and not line.startswith('+++'):
                    added_line = line[1:]
                    for pattern in PATTERNS:
                        if regex.search(pattern['pattern'], added_line):
                            all_findings.append({
                                "file": diff.b_path or diff.a_path,
                                "commit": commit.hexsha[:8],
                                "message": commit.message.strip()[:60],
                                "author": str(commit.author),
                                "name": pattern['name'],
                                "severity": pattern['severity'],
                                "category": pattern.get('category', 'unknown'),
                                "source": "git_history",
                            })

    return all_findings
