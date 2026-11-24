"""Save a local for every history record of test run"""

"""Only a non-sensitive data is stored and written such as timestamps, target, payload used.
    It is not depend whether the test is succeed or not, the record will be written in this log."""

import json
import os
from datetime import datetime


OUTPUT_DIR = "output"


def save_result(target: str, payload: str, verified: bool, security_level: str | None) -> str | None:
    """Append one JSON line describing this run to a local, dated log file"""
    entry = {
        "timestamp": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p"),
        "target": target,
        "payload_used": payload,
        "verified": verified,
        "security_level": security_level,
        "note": "Local record only. No data is sent off this machine.",
    }

    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except OSError as exc:
        print(f"[!] Could not create '{OUTPUT_DIR}/' for local logging: {exc}")
        print("[!] The XSS test result above is unaffected; only this local record was skipped.")
        return None

    log_path = os.path.join(OUTPUT_DIR, "xss_pg_results.jsonl")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        print(f"[!] Could not write local result record to '{log_path}': {exc}")
        print("[!] The XSS test result above is unaffected; only this local record was skipped.")
        return None

    return log_path
