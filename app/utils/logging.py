# app/utils/logging.py
import json
import os
from datetime import datetime

LOG_FILE = "logs/audit_log.jsonl"

def log_request(entry: dict):
    """Append one JSON line to the audit log."""
    os.makedirs("logs", exist_ok=True)
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")