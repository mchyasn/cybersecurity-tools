import re
import pandas as pd
from datetime import datetime

class Parser:
    TIMESTAMP_REGEX = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    LOGLEVEL_REGEX = r'\b(INFO|DEBUG|WARNING|ERROR|CRITICAL)\b'
    IP_REGEX = r'(\d{1,3}(?:\.\d{1,3}){3})'

    def __init__(self):
        self.current_year = datetime.now().year

    def parse(self, lines):
        rows = []
        for line in lines:
            ts_match = re.search(self.TIMESTAMP_REGEX, line)
            if not ts_match:
                continue  # Skip unstructured line

            try:
                timestamp = datetime.strptime(
                    f"{self.current_year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S"
                )
                timestamp_epoch = timestamp.timestamp()
            except ValueError:
                continue  # Skip line with invalid date

            loglevel_match = re.search(self.LOGLEVEL_REGEX, line, re.IGNORECASE)
            ip_match = re.search(self.IP_REGEX, line)

            loglevel = loglevel_match.group(1).upper() if loglevel_match else "INFO"
            ip = ip_match.group(1) if ip_match else "0.0.0.0"

            row = {
                "raw": line.strip(),
                "timestamp": timestamp,
                "timestamp_epoch": timestamp_epoch,
                "loglevel": loglevel,
                "ip": ip,
                "length": len(line),
                "digit_count": sum(c.isdigit() for c in line),
                "upper_count": sum(c.isupper() for c in line),
            }
            rows.append(row)

        return pd.DataFrame(rows)
