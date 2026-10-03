def detect_multiple_failed_logins(events, threshold=2):
    failed_attempts = {}

    for event in events:
        if (
            event.get("event_type") == "login"
            and event.get("status") == "failed"
        ):
            source_ip = event.get("source_ip")

            failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1

    alerts = []

    for source_ip, count in failed_attempts.items():
        if count >= threshold:
            alerts.append({
                "rule": "Multiple Failed Logins",
                "source_ip": source_ip,
                "failed_attempts": count,
                "severity": "medium"
            })

    return alerts

def detect_success_after_failures(events, threshold=2):
    failed_attempts = {}
    alerts = []

    for event in events:
        source_ip = event.get("source_ip")
        event_type = event.get("event_type")
        status = event.get("status")

        if event_type == "login" and status == "failed":
            failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1

        elif event_type == "login" and status == "success":
            if failed_attempts.get(source_ip, 0) >= threshold:
                alerts.append({
                    "rule": "Successful Login After Failed Attempts",
                    "source_ip": source_ip,
                    "failed_attempts": failed_attempts[source_ip],
                    "severity": "high"
                })

    return alerts
