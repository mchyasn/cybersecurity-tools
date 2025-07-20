import os
import sys
from rich.console import Console
from volatility3.cli import main as vol_main
from modules.yara_scanner import run_yara_scan

console = Console()

def run_analysis(dump_path, config, profile):
    if not os.path.isfile(dump_path):
        console.print(f"[bold red]Memory dump not found:[/bold red] {dump_path}")
        return

    console.print(f"[bold green]Analyzing dump:[/bold green] {dump_path}")

    if config.get("run_volatility", True):
        console.print("[cyan]Running Volatility3 analysis...[/cyan]")
        plugins = config.get("volatility_plugins", [])
        for plugin in plugins:
            try:
                console.print(f"[blue]Executing plugin:[/blue] {plugin}")
                base_args = [
                    "-f", dump_path,
                    "--cache-path", "logs/vol_cache",
                    plugin
                ]
                if profile:
                    base_args += ["--profile", profile]

                sys.argv = ["vol.py"] + base_args
                vol_main()
            except Exception as e:
                console.print(f"[red]Plugin {plugin} failed:[/red] {e}")

    if config.get("run_yara", True):
        yara_rules = config.get("yara_rules", [])
        if yara_rules:
            console.print("[cyan]Running YARA scan...[/cyan]")
            run_yara_scan(dump_path, yara_rules)
