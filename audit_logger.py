import os
import json
import time
from typing import List

AUDIT_LOG_FILE = "audit.log"

def log_audit_event(
    operation: str,
    blob_ids: List[str],
    label_hashes: List[str],
    result_count: int,
    log_file: str = AUDIT_LOG_FILE
):
    """
    Appends a structured JSON line to audit.log.
    CRITICAL SECURITY GUARANTEE: Never writes plaintext content, search terms,
    tokens, or secret keys.
    """
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "operation": operation,
        "blob_ids": blob_ids or [],
        "label_hashes": label_hashes or [],
        "result_count": result_count
    }
    
    line = json.dumps(event) + "\n"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line)

def read_audit_log(log_file: str = AUDIT_LOG_FILE) -> List[dict]:
    """Reads and parses all JSON lines from audit.log."""
    if not os.path.exists(log_file):
        return []
    records = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return records
