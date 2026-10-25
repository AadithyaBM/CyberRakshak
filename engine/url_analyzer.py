"""
CyberRakshak: Phishing Intelligence Engine

Local heuristic URL analysis with optional Google Safe Browsing checks.
The analyzer does not visit URLs, resolve DNS, or follow redirects.
Online threat-intelligence checks are opt-in via check_online=True.

Risk scores are heuristic indicators, not probabilities.
"""

import ipaddress
import re
from urllib.parse import urlparse, unquote

from engine.threat_intelligence import check_threat_intelligence


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

RISK_THRESHOLDS = {
    "medium": 25,
    "high": 50,
}

# Selected brands for basic lookalike screening.
LOOKALIKE_TARGETS = {
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
}

# Character substitutions commonly used in deceptive domain names.
LOOKALIKE_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})


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
        "destination_status": "unknown",
    }


def _is_ip_address(hostname: str) -> bool:
    """Check whether a hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_valid_hostname(hostname: str) -> bool:
    """Check basic hostname syntax without performing a DNS lookup."""
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

    if re.fullmatch(r"[0-9.]+", hostname):
        return False

    return True


def _detect_lookalike_domain(hostname: str) -> bool:
    """
    Detect selected character substitutions in hostname labels.

    Examples: paypa1.com, g00gle.com, amaz0n.com.
    This is a simple heuristic and can produce false positives/negatives.
    """
    labels = hostname.lower().split(".")

    for label in labels:
        normalized = label.translate(LOOKALIKE_SUBSTITUTIONS)
        if normalized in LOOKALIKE_TARGETS and normalized != label:
            return True

    return False


def _detect_suspicious_brand_subdomain(hostname: str) -> bool:
    """
    Flag a selected brand in a subdomain when the registrable-looking
    domain portion does not itself represent that brand.
    Example: paypal.example.com
    """
    labels = hostname.lower().split(".")
    if len(labels) < 3:
        return False

    subdomains = labels[:-2]
    return any(label in LOOKALIKE_TARGETS for label in subdomains)


def analyze_url(url: str, check_online: bool = False) -> dict:
    """
    Analyze URL structure and return heuristic indicators.

    By default, only local heuristics run, keeping tests and offline use
    deterministic. Set check_online=True to query configured Google Safe
    Browsing threat intelligence. This checks the submitted URL but does not
    visit the destination or follow redirects.
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
            f"The URL exceeds the maximum length of {MAX_URL_LENGTH} characters."
        )

    # 4. Add HTTPS if no scheme is provided.
    if "://" not in url:
        url = "https://" + url

    # 5. Parse and validate URL.
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            return _invalid_result("Only HTTP and HTTPS URLs can be analyzed.")

        if not parsed.hostname:
            return _invalid_result("The URL does not contain a hostname.")

        hostname = parsed.hostname.lower().rstrip(".")
        port = parsed.port

        if not _is_valid_hostname(hostname):
            return _invalid_result("The hostname format is invalid.")

    except (ValueError, UnicodeError):
        return _invalid_result("The URL format could not be parsed.")

    indicators = []
    score = 0

    is_ip = _is_ip_address(hostname)
    is_shortener = hostname in SHORTENER_DOMAINS
    has_lookalike = not is_ip and _detect_lookalike_domain(hostname)
    has_brand_subdomain = (
        not is_ip and _detect_suspicious_brand_subdomain(hostname)
    )

    destination_status = "unknown" if is_shortener else "not_checked"

    # 6. IP address as hostname.
    if is_ip:
        indicators.append(
            "The hostname is an IP address rather than a domain name."
        )
        score += 25

    # 7. URL length: a minor signal by itself, not proof of phishing.
    if len(url) > 200:
        indicators.append("The URL is unusually long.")
        score += 5

    # 8. @ symbol in authority section.
    if "@" in parsed.netloc:
        indicators.append(
            "The URL contains '@', which can obscure the destination."
        )
        score += 25

    # 9. Many hostname subdomains.
    if not is_ip and len(hostname.split(".")) >= 5:
        indicators.append("The hostname contains many subdomain levels.")
        score += 15

    # 10. Lookalike-domain detection gets a strong weight.
    if has_lookalike:
        indicators.append(
            "Possible brand impersonation: character-substitution resembling "
            "a selected well-known brand was detected."
        )
        score += 20

    # 11. Suspicious brand subdomain detection.
    if has_brand_subdomain:
        indicators.append(
            "A selected well-known brand appears in a subdomain. "
            "Check the actual registered domain independently."
        )
        score += 15

    # 12. Known URL shortener.
    if is_shortener:
        indicators.append("The URL uses a known URL-shortening service.")
        indicators.append(
            "The final destination of this shortened URL has not been checked."
        )
        score += 15

    # 13. Look for sensitive terms in the hostname, path, and query.
    # Decode percent-encoded text for analysis, but keep the submitted URL
    # unchanged in the returned normalized_url.
    url_text = unquote(
        f"{hostname}{parsed.path}?{parsed.query}"
    ).lower()

    matched_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in url_text
    )

    if matched_keywords:
        indicators.append(
            "Potentially sensitive terms found: "
            + ", ".join(matched_keywords)
            + "."
        )
        # Keyword matches are weak signals and have a strict cap.
        score += min(15, len(matched_keywords) * 5)

    # 14. HTTP connection.
    if scheme == "http":
        indicators.append(
            "The URL uses HTTP instead of HTTPS. "
            "The connection does not use HTTPS encryption."
        )
        score += 10

    # 15. Non-standard port.
    if port is not None and port not in {80, 443}:
        indicators.append(f"The URL uses a non-standard port ({port}).")
        score += 10

    # 16. Contextual combination: a lookalike plus sensitive terms is
    # more concerning than either weak signal alone.
    if (has_lookalike or has_brand_subdomain) and matched_keywords:
        indicators.append(
            "Brand-impersonation pattern combined with sensitive URL terms; "
            "treat this URL as high risk until independently verified."
        )
        score += 15

    # 17. Optional online threat-intelligence check.
    threat_intelligence = {
        "status": "not_requested",
        "matched": None,
        "source": None,
        "message": "Online threat intelligence was not requested.",
    }
    verification_status = "not_checked"
    analysis_method = "local_heuristics"

    if check_online:
        threat_intelligence = check_threat_intelligence(url)
        analysis_method = "local_heuristics+threat_intelligence"

        if threat_intelligence["status"] == "match":
            indicators.append(
                "Google Safe Browsing reported this URL as a known threat."
            )
            # A provider match is a strong signal; keep the result in High risk.
            score = max(score, 75)
            verification_status = "threat_match"
        elif threat_intelligence["status"] == "no_match":
            verification_status = "checked_no_match"
        elif threat_intelligence["status"] == "not_configured":
            verification_status = "not_configured"
        elif threat_intelligence["status"] == "unavailable":
            verification_status = "unavailable"
        else:
            verification_status = threat_intelligence["status"]

    # 18. Cap score.
    score = min(score, 100)

    # 19. Assign risk category and recommendation.
    if score >= RISK_THRESHOLDS["high"]:
        risk_level = "High"
        recommendation = (
            "Multiple or strong warning signs were detected. Avoid entering "
            "credentials or sensitive information. Verify the destination "
            "using an independently obtained official source."
        )
    elif score >= RISK_THRESHOLDS["medium"]:
        risk_level = "Medium"
        recommendation = (
            "Review the hostname and warning signs carefully. Verify the "
            "destination independently before sharing sensitive information."
        )
    else:
        risk_level = "Low"
        recommendation = (
            "Few warning signs were detected by these rules. This does not "
            "guarantee that the URL is safe."
        )

    if is_shortener:
        recommendation += (
            " The final destination is unknown because this analyzer "
            "does not follow shortened links."
        )

    if not indicators:
        indicators.append(
            "No suspicious indicators were detected by the current rules."
        )

    if threat_intelligence["status"] == "match":
        recommendation = (
            "Google Safe Browsing reported this URL as a known threat. "
            "Avoid visiting it or entering credentials or sensitive information."
        )
    elif threat_intelligence["status"] == "no_match":
        recommendation += (
            " Google Safe Browsing returned no known threat match, but this "
            "does not guarantee that the URL is safe."
        )

    # 20. Return the complete result.
    return {
        "valid": True,
        "normalized_url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
        "analysis_method": analysis_method,
        "verification_status": verification_status,
        "destination_status": destination_status,
        "threat_intelligence": threat_intelligence,
    }
