# ArtifactScope

**ArtifactScope** is a modular, cross-platform artifact extraction tool for Windows, macOS, and Linux. It extracts critical forensic artifacts including browser history, USB history, and MRU items. It supports both live triage and offline evidence acquisition modes. Built to mimic commercial DFIR tools like Magnet AXIOM and Velociraptor.

---

## Features

* Cross-platform support (Win/Mac/Linux)
* Triage mode (live analysis) and Bulk mode (offline image mount)
* Extracts browser history from Firefox `places.sqlite`
* Output in CSV format
* Logs all extracted artifacts
* Easily extensible with new extractors

---

## Example Usage

```bash
source venv/bin/activate
python3 main.py bulk test_target --config config/scope.yml
```

* `triage` mode scans the current system
* `bulk` mode scans mounted folders or forensic images

---

## Configuration File

```yaml
# config/scope.yml
extract_browser: true
extract_usb: true
extract_mru: true

output_format: csv
```

Disable any module by setting the corresponding key to `false`.

---

## Folder Structure

```
ArtifactScope/
├── config/
│   ├── loader.py
│   └── scope.yml
├── extractors/
│   └── browser_history.py
├── logs/
│   └── scope.log
├── modules/
│   └── extractor_core.py
├── output/
│   └── artifactscope.csv
├── screenshots/
├── tests/
│   └── test_core.py
├── test_target/
│   └── UserData/FirefoxProfile/places.sqlite
├── main.py
├── requirements.txt
└── README.md
```

---

## Output Format

**CSV:**

```
timestamp,source,artifact
2025-07-20T22:14:22,test_target/.../places.sqlite,Visited: http://example.com | Example Site
```

**Log File:**

```
2025-07-20T22:14:22 - test_target/.../places.sqlite - Visited: http://example.com | Example Site
```

---

## Testing

```bash
python3 -m unittest discover tests
```

Also manually test with a fake `places.sqlite` for real output verification.

---

## Extending the Tool

To add more extractors:

1. Create `extractors/usb_history.py`, `extractors/mru.py`, etc.
2. Hook into `modules/extractor_core.py`
3. Return `[{timestamp, source, artifact}]` style dicts

# screenshots

![Digital Artifact Collector](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/05-Digital-Forensics-and-Incident-Response/ArtifactScope/screenshots/0.png)
![Digital Artifact Collector](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/05-Digital-Forensics-and-Incident-Response/ArtifactScope/screenshots/1.png)

---

## Author

Built by **mchyasn**
Created for host-based DFIR analysis and real-world triage exercises.
