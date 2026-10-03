import sqlite3

DB_PATH = "minisoc.db"


def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule TEXT NOT NULL,
        source_ip TEXT,
        severity TEXT,
        failed_attempts INTEGER,
        unique_ports INTEGER,
        UNIQUE(rule, source_ip, failed_attempts, unique_ports)
    )
""")

    conn.commit()
    conn.close()


def save_alert(alert):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE rule = ?
          AND source_ip = ?
          AND severity = ?
          AND failed_attempts IS ?
          AND unique_ports IS ?
    """, (
        alert.get("rule"),
        alert.get("source_ip"),
        alert.get("severity"),
        alert.get("failed_attempts"),
        alert.get("unique_ports")
    ))

    existing_alert = cursor.fetchone()

    if existing_alert is None:
        cursor.execute("""
            INSERT INTO alerts (
                rule,
                source_ip,
                severity,
                failed_attempts,
                unique_ports
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert.get("rule"),
            alert.get("source_ip"),
            alert.get("severity"),
            alert.get("failed_attempts"),
            alert.get("unique_ports")
        ))

        conn.commit()

    conn.close()
