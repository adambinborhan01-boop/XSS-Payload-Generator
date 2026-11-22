"""Authorization and local-scope enforcement for the DVWA lab."""

from urllib.parse import urlsplit, urlunsplit

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_PORT = 4280
DEFAULT_TARGET = "http://127.0.0.1:4280"

LEGAL_NOTICE = """
ETHICAL USE NOTICE
XSS-PG is intended only for an explicitly authorized, locally hosted DVWA lab.
Testing systems without permission may violate the Malaysian Computer Crimes Act
1997 and other applicable laws. Continue only if you own or have explicit
permission to assess this local lab. The tool restricts targets to loopback on
port 4280 and tests only DVWA's Reflected XSS module.
""".strip()


class ScopeError(ValueError):
    """Raised when a target falls outside the permitted local lab scope."""


def normalize_local_target(raw_target: str) -> str:
    """Validate and normalize a DVWA base URL on localhost port 4280."""
    candidate = (raw_target or "").strip() or DEFAULT_TARGET
    parts = urlsplit(candidate)

    if parts.scheme.lower() != "http":
        raise ScopeError("Only http:// localhost targets are allowed.")
    if parts.hostname not in ALLOWED_HOSTS:
        raise ScopeError("Target must be localhost or a loopback address.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError("Target contains an invalid port.") from exc
    if port != ALLOWED_PORT:
        raise ScopeError(f"Target must use port {ALLOWED_PORT}.")
    if parts.username or parts.password:
        raise ScopeError("Credentials in the target URL are not permitted.")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ScopeError("Provide only the DVWA base URL, without a path or query.")

    host = parts.hostname
    return urlunsplit(("http", f"{host}:{ALLOWED_PORT}", "", "", ""))


def require_authorization() -> bool:
    """Ask for explicit authorization confirmation; default to no."""
    print(LEGAL_NOTICE)
    answer = input("Do you confirm that you are authorized to test this local DVWA lab? [y/N]: ")
    return answer.strip().lower() in {"y", "yes"}
