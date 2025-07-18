from flask import Flask, render_template_string, jsonify
from threading import Lock
import os
import time

app = Flask(__name__)

log_buffer = []
anomaly_buffer = []
lock = Lock()

@app.route('/')
def dashboard():
    return render_template_string("""
    <html>
    <head><title>LogSentinel Dashboard</title></head>
    <body style="font-family:monospace;background:#111;color:#eee">
        <h2>LogSentinel :: Live Anomaly Dashboard</h2>
        <div id="anomalies" style="color:red;"></div>
        <hr>
        <h4>Last 10 Logs</h4>
        <pre id="logs"></pre>

        <script>
            async function fetchLogs() {
                let res = await fetch('/api/logs');
                let json = await res.json();
                document.getElementById("logs").innerText = json.logs.join("\\n");

                let res2 = await fetch('/api/anomalies');
                let json2 = await res2.json();
                document.getElementById("anomalies").innerText = json2.anomalies.join("\\n");
            }

            setInterval(fetchLogs, 1000);
            fetchLogs();
        </script>
    </body>
    </html>
    """)

@app.route('/api/logs')
def api_logs():
    with lock:
        return jsonify(logs=log_buffer[-10:])

@app.route('/api/anomalies')
def api_anomalies():
    with lock:
        return jsonify(anomalies=anomaly_buffer[-10:])

# Public method used by main.py
def update_dashboard_log(line, is_anomaly=False):
    with lock:
        log_buffer.append(line)
        if is_anomaly:
            anomaly_buffer.append(line)

def run_dashboard():
    app.run(host="0.0.0.0", port=8080, debug=False)
