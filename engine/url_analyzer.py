
"""
CyberRakshak: Phishing Intelligence Engine

Purpose:
    Inspect URL structure for potentially suspicious indicators.

Important:
    This is a heuristic screening tool, not a definitive malware detector.
    A low risk score does not guarantee that a URL is safe.
"""

import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "update",
    "banking",
    "signin",
    "wallet",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
}


def _invalid_result(message: str) -> dict:
    """Return a consistent result for invalid input."""
    return {
        "valid": False,
        "normalized_url": None,
        "hostname": None,
        "risk_score": 0,
        "risk_level": "Invalid",
        "indicators": [message],
        "recommendation": "Check the URL and try again.",
    }


def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return its indicators and heuristic risk score.

    The score is a manually designed screening score, not a probability
    that the URL is malicious.
    """

    if not isinstance(url, str) or not url.strip():
        return _invalid_result("Please enter a URL.")

    url = url.strip()

    # Reject whitespace and control characters rather than silently
    # interpreting a potentially malformed input.
    if re.search(r"\s", url) or any(ord(char) < 32 for char in url):
        return _invalid_result(
            "The URL contains whitespace or control characters."
        )

    # Require a recognizable URL scheme or a domain-like input.
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return _invalid_result(
                "Only HTTP and HTTPS URLs can be analyzed."
            )

        if not parsed.hostname:
            return _invalid_result("The URL does not contain a hostname.")

        hostname = parsed.hostname.lower().rstrip(".")

        # Accessing .port detects malformed port values.
        port = parsed.port

        # Reject obvious malformed hostnames.
        if hostname.startswith(".") or ".." in hostname:
            return _invalid_result("The hostname format is invalid.")

    except (ValueError, UnicodeError):
        return _invalid_result("The URL format could not be parsed.")

    indicators = []
    score = 0

    # 1. IP address used as the hostname.
    try:
        ipaddress.ip_address(hostname)
        indicators.append(
            "The hostname is an IP address rather than a domain name."
        )
        score += 25
    except ValueError:
        pass

    # 2. Unusually long URL.
    if len(url) > 100:
        indicators.append("The URL is unusually long.")
        score += 10

    # 3. @ symbol in the authority section.
    # This can make the actual destination harder to notice.
    if "@" in parsed.netloc:
        indicators.append(
            "The URL contains '@', which can obscure the destination."
        )
        score += 25

    # 4. Many subdomain levels.
    if len(hostname.split(".")) >= 5:
        indicators.append(
            "The hostname contains many subdomain levels."
        )
        score += 15

    # 5. Known URL-shortening services.
    if hostname in SHORTENER_DOMAINS:
        indicators.append(
            "The URL uses a known URL-shortening service."
        )
        score += 15

    # 6. Potentially sensitive terms in the hostname or path.
    url_text = f"{hostname}{parsed.path}".lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_text
    )

    if matched_keywords:
        indicators.append(
            "Potentially sensitive terms found: "
            + ", ".join(matched_keywords)
            + "."
        )
        score += min(20, len(matched_keywords) * 5)

    # 7. HTTP does not encrypt the connection like HTTPS.
    # HTTPS, however, does not prove that a website is trustworthy.
    if parsed.scheme.lower() == "http":
        indicators.append(
            "The URL uses HTTP instead of HTTPS."
        )
        score += 10

    # 8. Non-standard port.
    if port is not None and port not in {80, 443}:
        indicators.append(
            f"The URL uses a non-standard port ({port})."
        )
        score += 10

    score = min(score, 100)

    # Assign a screening category.
    if score >= 50:
        risk_level = "High"
        recommendation = (
            "Avoid entering credentials or sensitive information. "
            "Verify the destination using an independently obtained "
            "official source."
        )
    elif score >= 25:
        risk_level = "Medium"
        recommendation = (
            "Inspect the hostname carefully and verify the destination "
            "before sharing sensitive information."
        )
    else:
        risk_level = "Low"
        recommendation = (
            "No major indicators were detected by these rules. "
            "This does not guarantee that the URL is safe."
        )

    if not indicators:
        indicators.append(
            "No suspicious indicators were detected by the current rules."
        )

    return {
        "valid": True,
        "normalized_url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
    }

