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


def generate_payload(profile: PayloadProfile = PayloadProfile.REFLECTED) -> GeneratedPayload:
    """Return the supported, harmless payload for DVWA's reflected `name` input."""
    try:
        selected = PayloadProfile(profile)
    except ValueError as exc:
        raise ValueError(f"Unsupported payload profile: {profile}") from exc

    if selected is PayloadProfile.REFLECTED:
        return GeneratedPayload(
            profile=selected,
            value=REFLECTED_POC,
            description="Harmless JavaScript alert proof-of-execution for DVWA Reflected XSS (Low).",
            parameter="name",
        )

    raise ValueError(f"Unsupported payload profile: {profile}")
