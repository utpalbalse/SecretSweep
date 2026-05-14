import git
import regex
from secretsweep.detectors.patterns import PATTERNS


def scan_git_history(repo_path):
    repo = git.Repo(repo_path, search_parent_directories=True)
    all_findings = []

    for commit in repo.iter_commits():
        if commit.parents:
            diffs = commit.parents[0].diff(commit, create_patch=True)
        else:
            diffs = commit.diff(git.NULL_TREE, create_patch=True)

        for diff in diffs:
            if not diff.diff:
                continue

            patch = diff.diff.decode("utf-8", errors="ignore")

            for line in patch.split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    added_line = line[1:]

                    for pattern in PATTERNS:
                        matches = regex.findall(pattern["pattern"], added_line)
                        if matches:
                            all_findings.append({
                                "file": diff.b_path or diff.a_path,
                                "commit": commit.hexsha[:8],
                                "message": commit.message.strip()[:60],
                                "author": str(commit.author),
                                "name": pattern["name"],
                                "severity": pattern["severity"],
                                "source": "git_history",
                            })

    return all_findings
