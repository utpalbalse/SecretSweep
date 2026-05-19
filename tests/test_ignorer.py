import os
import tempfile
from secretsweep.core.ignorer import Ignorer


def _make_ignore_file(patterns):
    d = tempfile.mkdtemp()
    ignore_path = os.path.join(d, '.secretsweepignore')
    with open(ignore_path, 'w') as f:
        f.write('\n'.join(patterns))
    return ignore_path


def test_ignored_filename_is_ignored():
    ignore_path = _make_ignore_file(['*.log', 'vendor'])
    ignorer = Ignorer(ignore_path)
    assert ignorer.is_ignored('/some/path/app.log')


def test_non_ignored_file_passes():
    ignore_path = _make_ignore_file(['*.log'])
    ignorer = Ignorer(ignore_path)
    assert not ignorer.is_ignored('/some/path/app.py')


def test_comment_lines_are_skipped():
    ignore_path = _make_ignore_file(['# this is a comment', '*.log'])
    ignorer = Ignorer(ignore_path)
    assert not ignorer.is_ignored('/some/path/this is a comment')
    assert ignorer.is_ignored('/some/path/app.log')


def test_no_ignore_file_ignores_nothing():
    ignorer = Ignorer('/nonexistent/.secretsweepignore')
    assert not ignorer.is_ignored('/any/file.py')
