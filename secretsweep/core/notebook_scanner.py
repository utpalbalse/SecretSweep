import json

from secretsweep.core.scanner import scan_file_content


def scan_notebook(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            nb = json.load(f)
    except Exception:
        return []

    cells = nb.get('cells', [])
    if not isinstance(cells, list):
        return []

    findings = []
    for i, cell in enumerate(cells):
        if not isinstance(cell, dict) or cell.get('cell_type') != 'code':
            continue

        cell_num = i + 1

        source = cell.get('source', [])
        if isinstance(source, list):
            source = ''.join(source)
        for f in scan_file_content(source, filepath):
            f['source'] = 'notebook'
            f['cell_index'] = cell_num
            findings.append(f)

        for output in cell.get('outputs', []):
            if not isinstance(output, dict):
                continue

            texts = []
            raw = output.get('text', [])
            if isinstance(raw, list):
                texts.append(''.join(raw))
            elif isinstance(raw, str):
                texts.append(raw)

            data = output.get('data', {})
            if isinstance(data, dict):
                plain = data.get('text/plain', [])
                if isinstance(plain, list):
                    texts.append(''.join(plain))
                elif isinstance(plain, str):
                    texts.append(plain)

            for text in texts:
                for f in scan_file_content(text, filepath):
                    f['source'] = 'notebook'
                    f['cell_index'] = cell_num
                    findings.append(f)

    return findings
