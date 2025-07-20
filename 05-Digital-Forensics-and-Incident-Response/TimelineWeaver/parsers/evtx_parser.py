import os
from evtx import PyEvtxParser
from datetime import datetime

def parse_evtx(evtx_folder):
    events = []
    for fname in os.listdir(evtx_folder):
        if not fname.endswith(".evtx"):
            continue

        full_path = os.path.join(evtx_folder, fname)
        try:
            parser = PyEvtxParser(full_path)
            for record in parser.records_json():
                ts = record.get("timestamp", "")
                msg = record.get("message", "")
                if ts:
                    events.append({
                        "timestamp": ts,
                        "source": fname,
                        "description": msg.strip()
                    })
        except Exception:
            continue
    return events
