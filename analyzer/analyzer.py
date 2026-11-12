
from pathlib import Path
from datetime import datetime, timedelta, timezone
import json

from incidents.incident_manager import create_incident


PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENT_FILE = PROJECT_ROOT / "logs" / "security_events.jsonl"
ALERT_FILE = PROJECT_ROOT / "logs" / "security_alerts.jsonl"

# Brute-force detection settings
FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

# Successful login after multiple failures settings
SUCCESS_AFTER_FAILURE_THRESHOLD = 5
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 10


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


def save_alert(alert):
    with ALERT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(alert) + "\n")


def alert_already_exists(username, first_event_time, alert_type):
    existing_alerts = load_jsonl(ALERT_FILE)

    for alert in existing_alerts:
        if (
            alert.get("alert_type") == alert_type
            and alert.get("username") == username
            and alert.get("window_start") == first_event_time
        ):
            return True

    return False


def detect_brute_force(events):
    failed_logins = {}

    for event in events:
        if (
            event.get("event_type") == "login"
            and event.get("result") == "failed"
        ):
            username = event.get("username", "unknown")
            failed_logins.setdefault(username, []).append(event)

    for username, user_events in failed_logins.items():

        user_events.sort(
            key=lambda event: event["received_at"]
        )

        for index, first_event in enumerate(user_events):

            start_time = datetime.fromisoformat(
                first_event["received_at"]
            )

            matching_events = []

            for event in user_events[index:]:
                event_time = datetime.fromisoformat(
                    event["received_at"]
                )

                if event_time - start_time <= timedelta(
                    minutes=TIME_WINDOW_MINUTES
                ):
                    matching_events.append(event)
                else:
                    break

            if len(matching_events) >= FAILURE_THRESHOLD:

                first_event_time = first_event["received_at"]

                if alert_already_exists(
                    username,
                    first_event_time,
                    "brute_force_login"
                ):
                    print(
                        f"Duplicate brute-force alert skipped for {username}"
                    )
                    break

                alert = {
                    "detected_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "alert_type": "brute_force_login",
                    "severity": "high",
                    "username": username,
                    "failed_attempts": len(matching_events),
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "window_start": first_event_time,
                    "source_ip": matching_events[-1].get(
                        "source_ip", "unknown"
                    ),
                    "description": (
                        "Multiple failed login attempts detected."
                    )
                }

                save_alert(alert)
                create_incident(alert)

                print("SECURITY ALERT:", alert)
                break


def detect_success_after_failures(events):
    user_events = {}

    for event in events:
        if event.get("event_type") == "login":
            username = event.get("username", "unknown")
            user_events.setdefault(username, []).append(event)

    for username, events_list in user_events.items():

        events_list.sort(
            key=lambda event: event["received_at"]
        )

        for index, event in enumerate(events_list):

            if event.get("result") != "success":
                continue

            success_time = datetime.fromisoformat(
                event["received_at"]
            )

            failed_events = []

            for previous_event in reversed(events_list[:index]):

                if previous_event.get("result") != "failed":
                    continue

                failed_time = datetime.fromisoformat(
                    previous_event["received_at"]
                )

                if success_time - failed_time > timedelta(
                    minutes=SUCCESS_AFTER_FAILURE_WINDOW_MINUTES
                ):
                    break

                failed_events.append(previous_event)

            if len(failed_events) >= SUCCESS_AFTER_FAILURE_THRESHOLD:

                success_event_time = event["received_at"]

                if alert_already_exists(
                    username,
                    success_event_time,
                    "success_after_multiple_failures"
                ):
                    print(
                        f"Duplicate success-after-failures alert skipped for {username}"
                    )
                    continue

                alert = {
                    "detected_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "alert_type": "success_after_multiple_failures",
                    "severity": "medium",
                    "username": username,
                    "failed_attempts": len(failed_events),
                    "time_window_minutes": SUCCESS_AFTER_FAILURE_WINDOW_MINUTES,
                    "window_start": success_event_time,
                    "source_ip": event.get("source_ip", "unknown"),
                    "description": (
                        "Successful login detected after multiple "
                        "failed login attempts."
                    )
                }

                save_alert(alert)
                create_incident(alert)

                print("SECURITY ALERT:", alert)


def main():
    events = load_jsonl(EVENT_FILE)

    print(f"Total events loaded: {len(events)}")

    if not events:
        print("No security events available.")
        return

    detect_brute_force(events)
    detect_success_after_failures(events)


if __name__ == "__main__":
    main()
