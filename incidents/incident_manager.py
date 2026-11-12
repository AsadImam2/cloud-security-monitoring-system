
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
INCIDENT_FILE = PROJECT_ROOT / "data" / "security_incidents.json"


def current_time():
    return datetime.now(timezone.utc).isoformat()


def load_incidents():
    if not INCIDENT_FILE.exists():
        return []

    try:
        with INCIDENT_FILE.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError("Incident database must contain a JSON list.")

        return data

    except json.JSONDecodeError as error:
        raise ValueError("Incident database contains invalid JSON.") from error


def save_incidents(incidents):
    INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = INCIDENT_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    temporary_file.replace(INCIDENT_FILE)


def create_incident(alert):
    required_fields = ["alert_type", "username", "severity"]

    for field in required_fields:
        if not alert.get(field):
            raise ValueError(f"Missing alert field: {field}")

    incidents = load_incidents()

    alert_key = "|".join([
        str(alert.get("alert_type")),
        str(alert.get("username")),
        str(alert.get("detected_at", "unknown"))
    ])

    for incident in incidents:
        if incident.get("source_alert_key") == alert_key:
            print("Incident already exists for this alert.")
            return incident

    timestamp = current_time()

    incident = {
        "incident_id": "INC-" + secrets.token_hex(4).upper(),
        "source_alert_key": alert_key,
        "title": alert["alert_type"].replace("_", " ").title(),
        "username": alert["username"],
        "severity": str(alert["severity"]).lower(),
        "status": "Open",
        "source_alert": alert,
        "created_at": timestamp,
        "updated_at": timestamp,
        "investigation_notes": [],
        "response_actions": [],
        "resolution": None,
        "history": [
            {
                "action": "Incident created",
                "timestamp": timestamp
            }
        ]
    }

    incidents.append(incident)
    save_incidents(incidents)

    print(f"Incident created: {incident['incident_id']}")

    return incident


def update_status(incident_id, new_status):
    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if new_status not in allowed_statuses:
        raise ValueError("Invalid incident status.")

    incidents = load_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:

            if incident["status"] == "Resolved":
                raise ValueError("Resolved incidents cannot be reopened in this version.")

            timestamp = current_time()

            incident["status"] = new_status
            incident["updated_at"] = timestamp

            incident["history"].append({
                "action": f"Status changed to {new_status}",
                "timestamp": timestamp
            })

            save_incidents(incidents)

            print(f"Incident status updated: {new_status}")
            return incident

    raise ValueError("Incident not found.")


def add_investigation_note(incident_id, note, author="Admin"):
    if not note or not note.strip():
        raise ValueError("Investigation note cannot be empty.")

    incidents = load_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:

            if incident["status"] == "Resolved":
                raise ValueError("Cannot modify a resolved incident.")

            timestamp = current_time()

            incident["investigation_notes"].append({
                "author": author,
                "note": note.strip(),
                "timestamp": timestamp
            })

            incident["updated_at"] = timestamp

            incident["history"].append({
                "action": "Investigation note added",
                "timestamp": timestamp
            })

            save_incidents(incidents)

            print("Investigation note saved.")
            return incident

    raise ValueError("Incident not found.")


def record_response(incident_id, action, author="Admin"):
    if not action or not action.strip():
        raise ValueError("Response action cannot be empty.")

    incidents = load_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:

            if incident["status"] == "Resolved":
                raise ValueError("Cannot modify a resolved incident.")

            timestamp = current_time()

            incident["response_actions"].append({
                "author": author,
                "action": action.strip(),
                "timestamp": timestamp
            })

            incident["updated_at"] = timestamp

            incident["history"].append({
                "action": "Response action recorded",
                "timestamp": timestamp
            })

            save_incidents(incidents)

            print("Response action recorded.")
            return incident

    raise ValueError("Incident not found.")


def resolve_incident(incident_id, resolution, author="Admin"):
    if not resolution or not resolution.strip():
        raise ValueError("Resolution details cannot be empty.")

    incidents = load_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:

            if incident["status"] == "Resolved":
                raise ValueError("Incident is already resolved.")

            timestamp = current_time()

            incident["status"] = "Resolved"

            incident["resolution"] = {
                "author": author,
                "details": resolution.strip(),
                "resolved_at": timestamp
            }

            incident["updated_at"] = timestamp

            incident["history"].append({
                "action": "Incident resolved",
                "timestamp": timestamp
            })

            save_incidents(incidents)

            print(f"Incident resolved: {incident_id}")
            return incident

    raise ValueError("Incident not found.")


def get_all_incidents():
    return load_incidents()


def get_incident(incident_id):
    incidents = load_incidents()

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            return incident

    return None
