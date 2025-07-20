# TimelineWeaver

**TimelineWeaver** is an automated forensic timeline reconstruction tool. It parses and correlates event data from various Windows artifacts such as EVTX event logs, Prefetch, Shimcache, USN Journal, and registry hives. The output is a structured, chronologically ordered timeline suitable for forensic reports, visual analysis, or case investigation.

---

## Features

* Correlates multiple forensic sources: EVTX, Prefetch, Shimcache, USN Journal, Registry
* Clean, sortable CSV timeline output
* YAML-based configuration for toggling specific artifact types
* Modular architecture for plugging in new parsers
* Designed for IR professionals and forensic analysts

---

## Example Usage

```bash
source venv/bin/activate
python3 main.py test_artifacts --config config/weaver.yml --output timelines/output.csv
```

---

## Configuration

```yaml
# config/weaver.yml
parse_prefetch: true
parse_shimcache: true
parse_usn: true
parse_evtx: true
parse_registry: true

output_format: csv
```

---

## Folder Structure

```
TimelineWeaver/
├── config/
│   ├── loader.py
│   └── weaver.yml
├── dumps/                    # (optional future use)
├── logs/                     # (not currently used)
├── modules/
│   └── controller.py
├── parsers/
│   └── evtx_parser.py
├── screenshots/
├── test_artifacts/
│   └── evtx/                 # (empty EVTX dir for test)
├── tests/
│   └── test_controller.py
├── timelines/
│   └── output.csv            # Generated timeline file
├── main.py
├── requirements.txt
└── README.md
```

---

## Output Example (CSV)

```
timestamp,source,description
2023-07-20T10:32:45Z,System.evtx,User logon event
2023-07-20T10:34:12Z,Application.evtx,Service started: AVEngine
...
```

---

## Testing

```bash
python3 -m unittest discover tests
```

This will:

* Build a timeline from an empty folder
* Confirm that the timeline CSV is still generated (empty)

---

## Extending the Tool

* Add additional parsers in `parsers/`
* Hook them into `modules/controller.py`
* Examples: `parse_shimcache()`, `parse_usn_journal()`, `parse_registry_hives()`

---

## Author

Built by **mchyasn**
Engineered for forensic analysts, incident responders, and anyone needing high-fidelity Windows timeline correlation.
