import os
import sqlite3
from datetime import datetime

def extract_browser_history(root_path, mode):
    records = []

    # In triage, use known paths
    if mode == "triage":
        target_paths = [
            os.path.expanduser("~/.mozilla/firefox"),
            os.path.expanduser("~/Library/Application Support/Firefox"),
            os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox")
        ]
    else:
        # In bulk mode, scan entire root_path recursively
        target_paths = [root_path]

    for base in target_paths:
        if not os.path.exists(base):
            continue
        for dirpath, dirs, files in os.walk(base):
            for file in files:
                if file == "places.sqlite":
                    fullpath = os.path.join(dirpath, file)
                    try:
                        con = sqlite3.connect(fullpath)
                        cur = con.cursor()
                        cur.execute("SELECT url, title, last_visit_date FROM moz_places")
                        for row in cur.fetchall():
                            ts = convert_firefox_time(row[2])
                            records.append({
                                "timestamp": ts,
                                "source": fullpath,
                                "artifact": f"Visited: {row[0]} | {row[1]}"
                            })
                        con.close()
                    except Exception:
                        continue
    return records

def convert_firefox_time(ts_micro):
    if ts_micro:
        try:
            return datetime.utcfromtimestamp(ts_micro / 1e6).isoformat()
        except:
            return ""
    return ""
