import yara
import os
from rich.console import Console

console = Console()

def run_yara_scan(dump_path, rules):
    for rule_path in rules:
        if not os.path.exists(rule_path):
            console.print(f"[yellow]Skipping missing YARA rule:[/yellow] {rule_path}")
            continue

        try:
            rule = yara.compile(filepath=rule_path)
            console.print(f"[green]Scanning with YARA rule:[/green] {rule_path}")
            with open(dump_path, 'rb') as f:
                data = f.read()
                matches = rule.match(data=data)
                for match in matches:
                    console.print(f"[bold magenta]Match:[/bold magenta] {match}")
        except Exception as e:
            console.print(f"[red]YARA scan error for {rule_path}:[/red] {e}")
