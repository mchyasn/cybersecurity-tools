import os
import pandas as pd
from rich.console import Console
from parsers.evtx_parser import parse_evtx

console = Console()

def run_timeline_build(input_dir, output_path, config):
    timeline = []

    if config.get("parse_evtx", True):
        evtx_folder = os.path.join(input_dir, "evtx")
        if os.path.isdir(evtx_folder):
            console.print("[cyan]Parsing EVTX logs...[/cyan]")
            timeline.extend(parse_evtx(evtx_folder))

    df = pd.DataFrame(timeline or [], columns=["timestamp", "source", "description"])
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    df.to_csv(output_path, index=False)

    log_path = "logs/build.log"
    os.makedirs("logs", exist_ok=True)
    with open(log_path, "w") as logf:
        for row in df.itertuples(index=False):
            logf.write(f"{row.timestamp}, {row.source}, {row.description}\n")

    if df.empty:
        console.print("[yellow]No timeline events collected.[/yellow]")
    else:
        console.print(f"[bold green]Timeline saved to:[/bold green] {output_path}")
