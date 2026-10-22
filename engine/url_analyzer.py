
"""
CyberRakshak: Phishing Intelligence Engine

Purpose:
    Inspect URL structure for potentially suspicious indicators.

Important:
    This is a heuristic screening tool, not a definitive malware detector.
    A low risk score does not guarantee that a URL is safe.
    No network requests or external threat intelligence checks are performed.
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

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253


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


def _is_valid_hostname(hostname: str) -> bool:
    """
    Check basic hostname syntax without performing a DNS lookup.

    Accepts valid IP addresses and ordinary ASCII domain names.
    This is syntax validation, not proof that a domain exists or is safe.
    """
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        return False

    # Accept valid IPv4 and IPv6 addresses.
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Remove no additional characters here: hostname normalization
    # is handled before this function is called.
    labels = hostname.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

    # Avoid treating a single numeric-looking hostname as a domain.
    if re.fullmatch(r"[0-9.]+", hostname):
        return False

    return True


def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return indicators and a heuristic risk score.

    The score is a manually designed screening score, not a probability
    that the URL is malicious.

    The function does not visit the URL, resolve DNS, or contact a server.
    """

    # 1. Validate input type and empty values.
    if not isinstance(url, str) or not url.strip():
        return _invalid_result("Please enter a URL.")

    url = url.strip()

    # 2. Reject whitespace and control characters.
    if any(char.isspace() or ord(char) < 32 for char in url):
        return _invalid_result(
            "The URL contains whitespace or control characters."
        )

    # 3. Limit URL length.
    if len(url) > MAX_URL_LENGTH:
        return _invalid_result(
            f"The URL exceeds the maximum length of {MAX_URL_LENGTH} characters."
        )

    # 4. Add HTTPS when the user supplies a domain without a scheme.
    if "://" not in url:
        url = "https://" + url

    # 5. Parse and validate the URL.
    try:
        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            return _invalid_result(
                "Only HTTP and HTTPS URLs can be analyzed."
            )

        if not parsed.hostname:
            return _invalid_result(
                "The URL does not contain a hostname."
            )

        hostname = parsed.hostname.lower().rstrip(".")

        # Accessing .port detects malformed port values.
        port = parsed.port

        # Require a syntactically valid hostname.
        if not _is_valid_hostname(hostname):
            return _invalid_result(
                "The hostname format is invalid."
            )

    except (ValueError, UnicodeError):
        return _invalid_result(
            "The URL format could not be parsed."
        )

    indicators = []
    score = 0

    # 6. Detect IP addresses used as hostnames.
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        indicators.append(
            "The hostname is an IP address rather than a domain name."
        )
        score += 25

    # 7. Detect unusually long URLs.
    if len(url) > 100:
        indicators.append("The URL is unusually long.")
        score += 10

    # 8. Detect the @ symbol in the authority section.
    if "@" in parsed.netloc:
        indicators.append(
            "The URL contains '@', which can obscure the destination."
        )
        score += 25

    # 9. Detect many subdomain levels.
    if not is_ip_address and len(hostname.split(".")) >= 5:
        indicators.append(
            "The hostname contains many subdomain levels."
        )
        score += 15

    # 10. Detect known URL-shortening services.
    if hostname in SHORTENER_DOMAINS:
        indicators.append(
            "The URL uses a known URL-shortening service. "
            "Its final destination has not been checked."
        )
        score += 20

    # 11. Detect potentially sensitive terms.
    # Search the hostname and path, not query values or fragments.
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

    # 12. Detect HTTP connections.
    if scheme == "http":
        indicators.append(
            "The URL uses HTTP instead of HTTPS. "
            "The connection is not protected by HTTPS encryption."
        )
        score += 10

    # 13. Detect non-standard ports.
    if port is not None and port not in {80, 443}:
        indicators.append(
            f"The URL uses a non-standard port ({port})."
        )
        score += 10

    # 14. Cap the score at 100.
    score = min(score, 100)

    # 15. Assign a screening category and recommendation.
    if score >= 50:
        risk_level = "High"
        recommendation = (
            "Multiple warning signs were detected. Avoid entering "
            "credentials or sensitive information. Verify the destination "
            "using an independently obtained official source."
        )

    elif score >= 25:
        risk_level = "Medium"
        recommendation = (
            "Inspect the hostname and warning signs carefully. "
            "Verify the destination independently before sharing "
            "sensitive information."
        )

    else:
        risk_level = "Low"
        recommendation = (
            "Few warning signs were detected by these rules. "
            "This does not guarantee that the URL is safe. "
            "The destination has not been checked against external "
            "threat intelligence."
        )

    # A shortener can hide its destination even when the numeric
    # score remains below the Medium threshold.
    if hostname in SHORTENER_DOMAINS:
        recommendation += (
            " This URL uses a shortening service, and its final "
            "destination is unknown to this analyzer."
        )

    # 16. Explain when no indicators were found.
    if not indicators:
        indicators.append(
            "No suspicious indicators were detected by the current rules."
        )

    # 17. Return the established result structure.
    return {
        "valid": True,
        "normalized_url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
    }

