from incidents.incident_manager import (
    get_all_incidents,
    get_incident,
    update_status,
    add_investigation_note,
    record_response,
    resolve_incident
)
from flask_wtf.csrf import CSRFProtect
from flask import (
    Flask, render_template, request,
    session, redirect, url_for, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from collections import Counter
import requests
import json
import secrets

app = Flask(__name__, template_folder="app/templates")
csrf = CSRFProtect(app)
# Persistent Flask Session Security

PROJECT_ROOT = Path(__file__).resolve().parent

SECRET_KEY_FILE = PROJECT_ROOT / "data" / "flask_secret.key"

app.secret_key = SECRET_KEY_FILE.read_text(
    encoding="utf-8"
).strip()

# Session Cookie Security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

EVENT_FILE = PROJECT_ROOT / "logs" / "security_events.jsonl"
ALERT_FILE = PROJECT_ROOT / "logs" / "security_alerts.jsonl"

# Demo accounts for local security testing
DEMO_USERS = {
    "admin": {
        "password_hash": generate_password_hash("AdminDemo@123"),
        "role": "Admin",
    },
    "developer": {
        "password_hash": generate_password_hash("DevDemo@123"),
        "role": "Developer",
    },
    "employee": {
        "password_hash": generate_password_hash("EmployeeDemo@123"),
        "role": "Employee",
    },
    "user": {
        "password_hash": generate_password_hash("UserDemo@123"),
        "role": "User",
    },
}


def load_jsonl(file_path):
    records = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print("Warning: Invalid JSON record skipped.")

    return records


def send_security_event(event_type, username, result):
    event = {
        "event_type": event_type,
        "username": username,
        "result": result,
    }

    try:
        response = requests.post(
            "http://127.0.0.1:5001/collect",
            json=event,
            timeout=3,
        )
        response.raise_for_status()
    except requests.RequestException as error:
        print(f"Security event delivery failed: {error}")


@app.route("/", methods=["GET"])
def home():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    account = DEMO_USERS.get(username)

    if account and check_password_hash(
        account["password_hash"], password
    ):
        session.clear()
        session["username"] = username
        session["role"] = account["role"]

        send_security_event("login", username, "success")

        if account["role"] == "Admin":
            return redirect(url_for("dashboard"))

        return (
            f"<h1>Login successful</h1>"
            f"<p>Welcome, {username}.</p>"
            f"<p>Role: {account['role']}</p>"
            '<a href="/logout">Logout</a>'
        ), 200

    send_security_event("login", username or "unknown", "failed")

    return (
        "<h1>Login failed</h1>"
        "<p>Invalid username or password.</p>"
        '<a href="/">Try again</a>'
    ), 401


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("home"))

    if session.get("role") != "Admin":
        return "<h1>Access Denied</h1><p>Admin access required.</p>", 403

    events = load_jsonl(EVENT_FILE)
    alerts = load_jsonl(ALERT_FILE)

    severity_counts = Counter(
        alert.get("severity", "unknown").lower()
        for alert in alerts
    )

    login_events = [
        event for event in events
        if event.get("event_type") == "login"
    ]

    return render_template(
        "dashboard.html",
        username=session["username"],
        total_events=len(events),
        total_alerts=len(alerts),
        high_alerts=severity_counts.get("high", 0),
        medium_alerts=severity_counts.get("medium", 0),
        low_alerts=severity_counts.get("low", 0),
        recent_events=list(reversed(login_events[-10:])),
        recent_alerts=list(reversed(alerts[-10:])),
    )

@app.route("/api/dashboard-data", methods=["GET"])
def dashboard_data():
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    events = load_jsonl(EVENT_FILE)
    alerts = load_jsonl(ALERT_FILE)

    severity_counts = Counter(
        alert.get("severity", "unknown").lower()
        for alert in alerts
    )

    login_events = [
        event for event in events
        if event.get("event_type") == "login"
    ]

    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "high_alerts": severity_counts.get("high", 0),
        "medium_alerts": severity_counts.get("medium", 0),
        "low_alerts": severity_counts.get("low", 0),
        "recent_events": list(reversed(login_events[-10:])),
        "recent_alerts": list(reversed(alerts[-10:]))
    })

@app.route("/api/incidents", methods=["GET"])
def incidents_api():
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({"incidents": get_all_incidents()})


@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
def incident_status_api(incident_id):
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json(silent=True) or {}

    try:
        incident = update_status(
            incident_id,
            data.get("status", "")
        )
        return jsonify({"message": "Status updated", "incident": incident})

    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/incidents/<incident_id>/notes", methods=["POST"])
def incident_note_api(incident_id):
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json(silent=True) or {}

    try:
        incident = add_investigation_note(
            incident_id,
            data.get("note", ""),
            author=session["username"]
        )
        return jsonify({"message": "Note saved", "incident": incident})

    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/incidents/<incident_id>/response", methods=["POST"])
def incident_response_api(incident_id):
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json(silent=True) or {}

    try:
        incident = record_response(
            incident_id,
            data.get("action", ""),
            author=session["username"]
        )
        return jsonify({"message": "Response recorded", "incident": incident})

    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
def incident_resolve_api(incident_id):
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401

    if session.get("role") != "Admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json(silent=True) or {}

    try:
        incident = resolve_incident(
            incident_id,
            data.get("resolution", ""),
            author=session["username"]
        )
        return jsonify({"message": "Incident resolved", "incident": incident})

    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
