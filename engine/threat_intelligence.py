"""
CyberRakshak - Threat Intelligence Interface

Provides a safe interface for checking whether a URL has a match
in a configured threat intelligence source.

No external provider is contacted by this initial implementation.
"""

from typing import Any


def check_threat_intelligence(url: str) -> dict[str, Any]:
    """
    Return an explicit inconclusive result until a provider is configured.

    We deliberately do not claim that a URL is safe or malicious
    without evidence from an actual configured source.
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "invalid_input",
            "matched": None,
            "source": None,
            "message": "A non-empty URL is required.",
        }

    return {
        "status": "not_configured",
        "matched": None,
        "source": None,
        "message": (
            "No threat intelligence provider is configured yet. "
            "This URL has not been checked against an external feed."
        ),
    }