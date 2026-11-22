"""Identify a local DVWA instance before any browser test is started."""

from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .security import ScopeError, normalize_local_target


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent a local preflight response from redirecting urllib off-origin."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


DVWA_SIGNATURES = (
    "damn vulnerable web application",
    'name="username"',
    'name="password"',
)


def check_dvwa(target: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Return (is_dvwa, message) after checking the unauthenticated login page."""
    try:
        target = normalize_local_target(target)
    except ScopeError as exc:
        return False, f"Target scope rejected: {exc}"

    login_url = f"{target}/login.php"
    request = Request(login_url, headers={"User-Agent": "XSS-PG-local-lab/1.0"})

    try:
        opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            body = response.read(256_000).decode("utf-8", errors="replace").lower()
            if status != 200:
                return False, f"DVWA login page returned HTTP {status}."
    except HTTPError as exc:
        return False, f"DVWA login page returned HTTP {exc.code}."
    except (URLError, TimeoutError, OSError) as exc:
        return False, f"Could not reach the local DVWA instance: {exc}"

    if not all(signature in body for signature in DVWA_SIGNATURES):
        return False, "The local service responded, but its login page does not match DVWA."

    return True, "DVWA login page identified successfully."
