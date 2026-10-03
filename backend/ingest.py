import json
from backend.database import initialize_database, save_alert
from detection.rules import (
    detect_multiple_failed_logins,
    detect_success_after_failures,
    detect_port_scan
)

def load_logs(file_path):
    with open(file_path, "r") as file:
        logs = json.load(file)

    return logs


def normalize_event(log):
    return {
        "timestamp": log.get("timestamp"),
        "source": log.get("source"),
        "event_type": log.get("event_type"),
        "username": log.get("username"),
        "status": log.get("status"),
        "source_ip": log.get("ip_address"),
	"destination_port": log.get("destination_port")
    }


if __name__ == "__main__":
    logs = load_logs("logs/sample_logs.json")

    events = []

    for log in logs:
        event = normalize_event(log)
        events.append(event)

    alerts = []
    alerts.extend(detect_multiple_failed_logins(events))
    alerts.extend(detect_success_after_failures(events))
    alerts.extend(detect_port_scan(events))

    initialize_database()

    for alert in alerts:
    	save_alert(alert)

    print("Normalized Events:")
    for event in events:
        print(event)

    print("\nAlerts:")
    for alert in alerts:
        print(alert)
