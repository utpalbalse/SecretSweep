import json
import tempfile
import os
from secretsweep.core.notebook_scanner import scan_notebook


def _make_notebook(cells):
    return {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": cells}


def _code_cell(source, outputs=None):
    return {
        "cell_type": "code",
        "source": source,
        "metadata": {},
        "outputs": outputs or [],
        "execution_count": None,
    }


def _stream_output(text):
    return {"output_type": "stream", "name": "stdout", "text": text}


def _display_output(text_plain):
    return {"output_type": "display_data", "data": {"text/plain": text_plain}, "metadata": {}}


def _write_notebook(nb):
    f = tempfile.NamedTemporaryFile(suffix=".ipynb", mode="w", delete=False, encoding="utf-8")
    json.dump(nb, f)
    f.close()
    return f.name


def test_secret_in_code_cell_source():
    nb = _make_notebook([_code_cell('AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"')])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)
    assert all(f['source'] == 'notebook' for f in findings)


def test_secret_in_stream_output():
    output = _stream_output(['AKIAIOSFODNN7EXAMPLE1234\n'])
    nb = _make_notebook([_code_cell('print(key)', [output])])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)
    assert all(f['cell_index'] == 1 for f in findings)


def test_secret_in_display_output():
    output = _display_output(['AKIAIOSFODNN7EXAMPLE1234'])
    nb = _make_notebook([_code_cell('display(key)', [output])])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_clean_notebook_no_findings():
    nb = _make_notebook([_code_cell('x = 1 + 1', [_stream_output(['2\n'])])])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert findings == []


def test_malformed_json_returns_empty():
    f = tempfile.NamedTemporaryFile(suffix=".ipynb", mode="w", delete=False, encoding="utf-8")
    f.write("not valid json {{{{")
    f.close()
    findings = scan_notebook(f.name)
    os.unlink(f.name)
    assert findings == []


def test_non_code_cells_skipped():
    nb = _make_notebook([
        {"cell_type": "markdown", "source": 'AKIAIOSFODNN7EXAMPLE1234', "metadata": {}, "outputs": []},
    ])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert findings == []


def test_cell_index_reported_correctly():
    nb = _make_notebook([
        _code_cell('x = 1'),
        _code_cell('AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"'),
    ])
    path = _write_notebook(nb)
    findings = scan_notebook(path)
    os.unlink(path)
    assert any(f['cell_index'] == 2 for f in findings)
