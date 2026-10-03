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
