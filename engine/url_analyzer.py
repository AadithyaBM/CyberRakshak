
"""
CyberRakshak: Phishing Intelligence Engine

Purpose:
    Inspect URL structure for potentially suspicious indicators.

Important:
    This is a heuristic screening tool, not a definitive malware detector.
    Risk scores are not probabilities.
    No network requests or external threat-intelligence checks are performed.
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

# Heuristic thresholds, not probabilities of maliciousness.
RISK_THRESHOLDS = {
    "medium": 25,
    "high": 50,
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
        "analysis_method": "local_heuristics",
        "verification_status": "not_checked",
    }


def _is_ip_address(hostname: str) -> bool:
    """Return True if the hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_valid_hostname(hostname: str) -> bool:
    """
    Check basic hostname syntax without performing a DNS lookup.

    This does not establish whether a hostname exists or is trustworthy.
    """
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        return False

    if _is_ip_address(hostname):
        return True

    labels = hostname.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

    # Reject numeric-only hostname forms that are not valid IP addresses.
    if re.fullmatch(r"[0-9.]+", hostname):
        return False

    return True


def analyze_url(url: str) -> dict:
    """
    Analyze URL structure and return heuristic indicators.

    Does not visit the URL, resolve DNS, follow redirects, or contact
    an external threat-intelligence provider.
    """

    # 1. Validate input.
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
            f"The URL exceeds the maximum length of "
            f"{MAX_URL_LENGTH} characters."
        )

    # 4. Add HTTPS if no scheme is provided.
    if "://" not in url:
        url = "https://" + url

    # 5. Parse and validate URL structure.
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
        port = parsed.port

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

    is_ip = _is_ip_address(hostname)
    is_shortener = hostname in SHORTENER_DOMAINS

    # 6. IP address used as the hostname.
    if is_ip:
        indicators.append(
            "The hostname is an IP address rather than a domain name."
        )
        score += 25

    # 7. Unusually long URL.
    if len(url) > 100:
        indicators.append("The URL is unusually long.")
        score += 10

    # 8. @ symbol in the authority section.
    if "@" in parsed.netloc:
        indicators.append(
            "The URL contains '@', which can obscure the destination."
        )
        score += 25

    # 9. Many hostname subdomains.
    if not is_ip and len(hostname.split(".")) >= 5:
        indicators.append(
            "The hostname contains many subdomain levels."
        )
        score += 15

    # 10. Known URL-shortening service.
    if is_shortener:
        indicators.append(
            "The URL uses a known URL-shortening service."
        )
        indicators.append(
            "The final destination of this shortened URL has not been checked."
        )
        score += 20

    # 11. Potentially sensitive terms in hostname and path.
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

    # 12. HTTP connection.
    if scheme == "http":
        indicators.append(
            "The URL uses HTTP instead of HTTPS. "
            "The connection does not use HTTPS encryption."
        )
        score += 10

    # 13. Non-standard port.
    if port is not None and port not in {80, 443}:
        indicators.append(
            f"The URL uses a non-standard port ({port})."
        )
        score += 10

    # 14. Cap the score.
    score = min(score, 100)

    # 15. Assign the risk category.
    if score >= RISK_THRESHOLDS["high"]:
        risk_level = "High"
        recommendation = (
            "Multiple warning signs were detected. Avoid entering "
            "credentials or sensitive information. Verify the destination "
            "using an independently obtained official source."
        )

    elif score >= RISK_THRESHOLDS["medium"]:
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
            "This does not guarantee that the URL is safe."
        )

    # 16. Explicitly explain the uncertainty of shortened URLs.
    if is_shortener:
        recommendation += (
            " The final destination is unknown because this analyzer "
            "does not follow shortened links."
        )

    # 17. Explain when no indicators are detected.
    if not indicators:
        indicators.append(
            "No suspicious indicators were detected by the current rules."
        )

    # 18. Return the complete result.
    return {
        "valid": True,
        "normalized_url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
        "analysis_method": "local_heuristics",
        "verification_status": "not_checked",
    }

