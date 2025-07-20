from rich import print
import datetime

def log_event(msg):
    ts = datetime.datetime.now().isoformat()
    print(f"[cyan]{ts}[/cyan] - {msg}")
