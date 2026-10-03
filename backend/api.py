import sqlite3

from fastapi import FastAPI


app = FastAPI(title="MiniSOC API")

DB_PATH = "minisoc.db"


@app.get("/")
def root():
    return {"message": "MiniSOC API is running"}


@app.get("/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            rule,
            source_ip,
            severity,
            failed_attempts,
            unique_ports
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

