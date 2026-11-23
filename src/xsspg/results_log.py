"""Save a local for every history record of test run"""

"""Only a non-sensitive data is stored and written such as timestamps, target, payload used.
    It is not depend whether the test is succeed or not, the record will be written in this log."""

import json
import os
from datetime import datetime

OUTPUT_DIR = "output"

def save_result(target: str, payload: str, verified: bool, security_level: str | None) -> str:
    """Append one JSON line describing this run to a local, dated log file."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log_path = os.path.join(OUTPUT_DIR, "xss_pg_results.jsonl")

    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "payload_used": payload,
        "verified": verified,
        "security_level": security_level,
        "note": "Local record only. No data is sent off this machine.",
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return log_path