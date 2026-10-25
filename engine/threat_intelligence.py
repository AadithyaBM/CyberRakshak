
"""
CyberRakshak - Threat Intelligence Interface

Optional Google Safe Browsing integration.
If no API key is configured, the result remains inconclusive.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import requests


GOOGLE_SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

REQUEST_TIMEOUT_SECONDS = 8

SUPPORTED_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def _result(
    status: str,
    matched: bool | None,
    source: str | None,
    message: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "matched": matched,
        "source": source,
        "message": message,
    }


def _is_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )
    except ValueError:
        return False


def check_threat_intelligence(url: str) -> dict[str, Any]:
    """Check a URL using Google Safe Browsing when configured."""

    if not isinstance(url, str) or not url.strip():
        return _result(
            "invalid_input",
            None,
            None,
            "A non-empty URL is required.",
        )

    normalized_url = url.strip()

    if not _is_http_url(normalized_url):
        return _result(
            "invalid_input",
            None,
            None,
            "Only complete HTTP or HTTPS URLs can be checked.",
        )

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()


    if not api_key:
        return _result(
            "not_configured",
            None,
            None,
            "Threat intelligence is not configured. This URL has not been "
            "checked against an external feed. Set "
            "GOOGLE_SAFE_BROWSING_API_KEY to enable online checks.",
        )



    payload = {
        "client": {
            "clientId": "CyberRakshak",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": SUPPORTED_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized_url}],
        },
    }

    try:
        response = requests.post(
            GOOGLE_SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code == 429:
            return _result(
                "unavailable",
                None,
                "Google Safe Browsing",
                "The provider rate-limited this request. Try again later.",
            )

        response.raise_for_status()
        data = response.json()

    except requests.Timeout:
        return _result(
            "unavailable",
            None,
            "Google Safe Browsing",
            "The online threat check timed out. Local analysis remains available.",
        )

    except requests.RequestException:
        return _result(
            "unavailable",
            None,
            "Google Safe Browsing",
            "The online threat check failed. Check network access and API configuration.",
        )

    except ValueError:
        return _result(
            "unavailable",
            None,
            "Google Safe Browsing",
            "The provider returned an unreadable response.",
        )

    matches = data.get("matches")

    if isinstance(matches, list) and matches:
        threat_types = sorted(
            {
                str(item.get("threatType"))
                for item in matches
                if isinstance(item, dict) and item.get("threatType")
            }
        )

        detail = (
            "Google Safe Browsing reported a threat match"
            + (f" ({', '.join(threat_types)})" if threat_types else "")
            + ". Avoid visiting this URL or entering sensitive information."
        )

        return _result(
            "match",
            True,
            "Google Safe Browsing",
            detail,
        )

    return _result(
        "no_match",
        False,
        "Google Safe Browsing",
        "No match was returned by Google Safe Browsing. "
        "This does not guarantee that the URL is safe.",
    )

