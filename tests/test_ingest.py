from backend.ingest import normalize_event
from detection.rules import (
    detect_multiple_failed_logins,
    detect_success_after_failures,
    detect_port_scan
)


def test_normalize_event():
    raw_log = {
        "timestamp": "2026-10-03T01:10:00",
        "source": "test-server",
        "event_type": "login",
        "username": "admin",
        "status": "failed",
        "ip_address": "192.168.1.50"
    }

    event = normalize_event(raw_log)

    assert event["source_ip"] == "192.168.1.50"
    assert event["event_type"] == "login"


def test_multiple_failed_logins():
    events = [
        {"event_type": "login", "status": "failed", "source_ip": "1.1.1.1"},
        {"event_type": "login", "status": "failed", "source_ip": "1.1.1.1"}
    ]

    alerts = detect_multiple_failed_logins(events)

    assert len(alerts) == 1


def test_success_after_failures():
    events = [
        {"event_type": "login", "status": "failed", "source_ip": "1.1.1.1"},
        {"event_type": "login", "status": "failed", "source_ip": "1.1.1.1"},
        {"event_type": "login", "status": "success", "source_ip": "1.1.1.1"}
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1


def test_port_scan():
    events = [
        {"event_type": "connection", "source_ip": "2.2.2.2", "destination_port": 22},
        {"event_type": "connection", "source_ip": "2.2.2.2", "destination_port": 80},
        {"event_type": "connection", "source_ip": "2.2.2.2", "destination_port": 443}
    ]

    alerts = detect_port_scan(events)

    assert len(alerts) == 1

