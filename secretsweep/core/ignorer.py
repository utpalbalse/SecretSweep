import fnmatch
import os


class Ignorer:
    def __init__(self, ignore_path=None):
        self.patterns = []
        if ignore_path and os.path.isfile(ignore_path):
            with open(ignore_path) as f:
                for line in f:
                    line = line.strip().rstrip('/')
                    if line and not line.startswith('#'):
                        self.patterns.append(line)

    def is_ignored(self, filepath):
        name = os.path.basename(filepath)
        normalized = filepath.replace('\\', '/')
        for pattern in self.patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
            if fnmatch.fnmatch(normalized, f'*/{pattern}'):
                return True
            if fnmatch.fnmatch(normalized, pattern):
                return True
        return False
