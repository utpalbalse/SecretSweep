from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

_SEV_STYLE = {
    'critical': 'bold red',
    'high':     'bold yellow',
    'medium':   'bold cyan',
    'low':      'bold green',
}


def _sev(severity):
    return Text(severity.upper(), style=_SEV_STYLE.get(severity.lower(), 'white'))


def _location(finding):
    source = finding.get('source', 'file')
    if source == 'git_history':
        return f"commit {finding.get('commit', '')}"
    if source == 'k8s_secret':
        return f"key: {finding.get('k8s_key', '')}"
    if source == 'terraform_state':
        ctx = finding.get('tf_context', '')
        return ctx[:40] + ('…' if len(ctx) > 40 else '')
    if source == 'notebook':
        return f"cell {finding.get('cell_index', '?')}"
    if source == 'cicd':
        key = finding.get('cicd_key', '')
        return f"key: {key}" if key else '—'
    if source == 'path':
        return '—'
    if finding.get('line'):
        return f"line {finding['line']}"
    return '—'


def print_findings(findings):
    if not findings:
        console.print("\n[bold green]✓ No secrets found.[/bold green]\n")
        return

    console.print(f"\n[bold]Found [red]{len(findings)}[/red] potential secret(s)[/bold]\n")

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=True)
    table.add_column("Severity",  no_wrap=True, min_width=10)
    table.add_column("Type",      style="bold white")
    table.add_column("Category",  style="dim", no_wrap=True)
    table.add_column("File",      style="dim")
    table.add_column("Location",  justify="right", no_wrap=True)

    for f in findings:
        table.add_row(
            _sev(f.get('severity', 'unknown')),
            f.get('name', ''),
            f.get('category', ''),
            f.get('file', ''),
            _location(f),
        )

    console.print(table)
    _print_summary(findings)


def _print_summary(findings):
    sev_counts = {}
    cat_counts = {}
    for f in findings:
        s = f.get('severity', 'unknown')
        c = f.get('category', 'unknown')
        sev_counts[s] = sev_counts.get(s, 0) + 1
        cat_counts[c] = cat_counts.get(c, 0) + 1

    sev_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for s in ['critical', 'high', 'medium', 'low']:
        if s in sev_counts:
            sev_table.add_row(Text(s.upper(), style=_SEV_STYLE[s]), str(sev_counts[s]))

    cat_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    cat_table.add_column("Category")
    cat_table.add_column("Count", justify="right")
    for c, n in sorted(cat_counts.items()):
        cat_table.add_row(c, str(n))

    console.print(Columns([sev_table, cat_table], padding=(0, 4)))
