import os
import pandas as pd
from rich.console import Console
from extractors.browser_history import extract_browser_history

console = Console()

def run_extraction(mode, path, config):
    events = []

    if config.get("extract_browser", True):
        console.print("[cyan]Extracting browser history...[/cyan]")
        events += extract_browser_history(path, mode)

    os.makedirs("output", exist_ok=True)
    df = pd.DataFrame(events or [], columns=["timestamp", "source", "artifact"])
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    df.to_csv("output/artifactscope.csv", index=False)

    os.makedirs("logs", exist_ok=True)
    with open("logs/scope.log", "w") as logf:
        for e in events:
            logf.write(f"{e['timestamp']} - {e['source']} - {e['artifact']}\n")

    if df.empty:
        console.print("[yellow]No artifacts extracted.[/yellow]")
    else:
        console.print("[bold green]Artifacts saved to output/artifactscope.csv[/bold green]")
