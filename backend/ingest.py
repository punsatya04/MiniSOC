import json
from detection.rules import detect_multiple_failed_logins

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
        "source_ip": log.get("ip_address")
    }


if __name__ == "__main__":
    logs = load_logs("logs/sample_logs.json")

    events = []

    for log in logs:
        event = normalize_event(log)
        events.append(event)

    alerts = detect_multiple_failed_logins(events)

    print("Normalized Events:")
    for event in events:
        print(event)

    print("\nAlerts:")
    for alert in alerts:
        print(alert)
