
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
import json

collector_app = Flask(__name__)

# Project ke logs folder ka path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "security_events.jsonl"


@collector_app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "service": "security-log-collector"
    }), 200


@collector_app.route("/collect", methods=["POST"])
def collect_event():
    event = request.get_json(silent=True)

    if not isinstance(event, dict):
        return jsonify({"error": "A JSON event is required"}), 400

    required_fields = ["event_type", "username", "result"]

    if not all(event.get(field) for field in required_fields):
        return jsonify({
            "error": "event_type, username and result are required"
        }), 400

    received_event = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "event_type": event["event_type"],
        "username": event["username"],
        "result": event["result"],
        "source_ip": request.remote_addr,
    }

    # Event ko permanent JSONL file mein save karo
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(received_event) + "\n")

    print(received_event, flush=True)

    return jsonify({
        "status": "event_received"
    }), 201


if __name__ == "__main__":
    collector_app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )
