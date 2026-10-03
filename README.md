# MiniSOC

MiniSOC is a lightweight personal Security Operations Center / SIEM learning project.

## Features

- JSON log ingestion
- Event normalization
- Detection rules
- SQLite alert storage
- Duplicate alert prevention
- FastAPI backend
- Simple security dashboard
- Basic automated testing

## Detection Rules

1. Multiple Failed Logins
2. Successful Login After Failed Attempts
3. Possible Port Scan

## Project Flow

Log Source
→ Ingestion
→ Normalization
→ Detection
→ Alert Storage
→ FastAPI
→ Dashboard

## Run the Project

Activate the virtual environment:

```bash
source .venv/bin/activate
