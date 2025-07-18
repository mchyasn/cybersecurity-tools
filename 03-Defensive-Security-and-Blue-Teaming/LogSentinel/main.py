import os
import time
import argparse
import importlib
import pandas as pd
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console
import logging
import colorlog
from threading import Thread
from web.dashboard import run_dashboard, update_dashboard_log

# Logging setup
log_formatter = colorlog.ColoredFormatter(
    "%(log_color)s[%(levelname)s]%(reset)s %(asctime)s - %(message)s",
    log_colors={"DEBUG": "cyan", "INFO": "green", "WARNING": "yellow", "ERROR": "red"}
)
handler = colorlog.StreamHandler()
handler.setFormatter(log_formatter)
logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

console = Console()


def handle_alert(message, method="console", webhook_url=None):
    if method == "file":
        os.makedirs("scans", exist_ok=True)
        with open("scans/alerts.txt", "a") as f:
            f.write(message + "\n")
    elif method == "webhook" and webhook_url:
        try:
            requests.post(webhook_url, json={"text": message}, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
    else:
        logger.warning(message)


class LogMonitor(FileSystemEventHandler):
    def __init__(self, logfile, parser_module, detector_class, threshold, alert_method, webhook_url):
        self.logfile = logfile
        self.parser = parser_module.Parser()
        self.detector = detector_class(contamination=threshold)
        self.last_position = 0
        self.alert_method = alert_method
        self.webhook_url = webhook_url

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(self.logfile):
            with open(self.logfile, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

            if not new_lines:
                return

            parsed_df = self.parser.parse(new_lines)
            if parsed_df.empty:
                return

            try:
                preds = self.detector.predict(parsed_df)
                parsed_df['__anomaly__'] = preds
                for _, row in parsed_df.iterrows():
                    msg = row['raw'].strip()
                    if row['__anomaly__'] == -1:
                        update_dashboard_log(msg, is_anomaly=True)
                        handle_alert(f"Anomaly: {msg}", self.alert_method, self.webhook_url)
                    else:
                        update_dashboard_log(msg, is_anomaly=False)
                        logger.info(f"Normal: {msg}")
            except Exception as e:
                logger.error(f"Detection error: {e}")


def load_module(module_path, class_name=None):
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name) if class_name else mod


def tail_log_file(args, parser_module, detector_class):
    handler = LogMonitor(
        logfile=args.log,
        parser_module=parser_module,
        detector_class=detector_class,
        threshold=args.threshold,
        alert_method=args.alert_to,
        webhook_url=args.webhook_url
    )
    observer = Observer()
    watch_path = os.path.dirname(args.log) or "."
    observer.schedule(handler, path=watch_path, recursive=False)
    observer.start()
    logger.info(f"Monitoring started on {args.log}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Monitoring stopped.")
    observer.join()


def main():
    parser = argparse.ArgumentParser(description="LogSentinel - Real-time Log Anomaly Detection")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--parser", required=True, help="Parser module name (e.g., syslog)")
    parser.add_argument("--detector", default="isoforest", help="Detector name (e.g., isoforest)")
    parser.add_argument("--threshold", type=float, default=0.1, help="Anomaly threshold (0.01 to 0.5)")
    parser.add_argument("--alert-to", choices=["console", "file", "webhook"], default="console", help="Alert output method")
    parser.add_argument("--webhook-url", help="Webhook URL for Slack or custom endpoint")
    args = parser.parse_args()

    if not os.path.isfile(args.log):
        logger.error("Log file not found.")
        return

    try:
        parser_module = load_module(f"parsers.{args.parser}")
        detector_class = load_module(f"detectors.{args.detector}", "Detector")
    except Exception as e:
        logger.error(f"Failed to load parser or detector: {e}")
        return

    Thread(target=run_dashboard, daemon=True).start()
    tail_log_file(args, parser_module, detector_class)


if __name__ == "__main__":
    main()
