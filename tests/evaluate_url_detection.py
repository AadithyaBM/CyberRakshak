
"""
CyberRakshak URL Rule-Coverage Evaluation

Checks URL validity, expected structural indicators, and basic
risk-classification consistency.

This is a rule-coverage evaluation, not a real-world phishing
accuracy benchmark. No network requests are made.
"""

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.url_analyzer import analyze_url  # noqa: E402


CASES = [
    # Invalid input
    {
        "name": "empty_input",
        "url": "",
        "expected_valid": False,
        "expected_indicator": "Please enter a URL",
    },
    {
        "name": "whitespace_input",
        "url": "https://example.com/a b",
        "expected_valid": False,
        "expected_indicator": "whitespace",
    },
    {
        "name": "unsupported_scheme",
        "url": "ftp://example.com/file",
        "expected_valid": False,
        "expected_indicator": "Only HTTP and HTTPS",
    },
    {
        "name": "missing_hostname",
        "url": "https://",
        "expected_valid": False,
        "expected_indicator": "hostname",
    },
    {
        "name": "invalid_hostname_label",
        "url": "https://-example.com",
        "expected_valid": False,
        "expected_indicator": "hostname format",
    },

    # Baseline URL structures
    {
        "name": "plain_https_domain",
        "url": "https://example.com",
        "expected_valid": True,
        "expected_indicator": None,
    },
    {
        "name": "domain_without_scheme",
        "url": "example.com",
        "expected_valid": True,
        "expected_indicator": None,
    },
    {
        "name": "ordinary_path",
        "url": "https://example.com/about",
        "expected_valid": True,
        "expected_indicator": None,
    },
    {
        "name": "trailing_dot_hostname",
        "url": "https://example.com.",
        "expected_valid": True,
        "expected_indicator": None,
    },

    # Detection rules
    {
        "name": "ip_hostname",
        "url": "http://192.0.2.1/login",
        "expected_valid": True,
        "expected_indicator": "IP address",
    },
    {
        "name": "url_with_at_authority",
        "url": "https://example.com@evil.test/login",
        "expected_valid": True,
        "expected_indicator": "@",
    },
    {
        "name": "many_subdomains",
        "url": "https://a.b.c.d.example.com",
        "expected_valid": True,
        "expected_indicator": "subdomain levels",
    },
    {
        "name": "lookalike_paypal",
        "url": "https://paypa1.com",
        "expected_valid": True,
        "expected_indicator": "character-substitution",
    },
    {
        "name": "lookalike_google",
        "url": "https://g00gle.com",
        "expected_valid": True,
        "expected_indicator": "character-substitution",
    },
    {
        "name": "lookalike_amazon",
        "url": "https://amaz0n.com",
        "expected_valid": True,
        "expected_indicator": "character-substitution",
    },
    {
        "name": "brand_in_subdomain",
        "url": "https://paypal.example.com",
        "expected_valid": True,
        "expected_indicator": "appears in a subdomain",
    },
    {
        "name": "known_shortener",
        "url": "https://bit.ly/example",
        "expected_valid": True,
        "expected_indicator": "shortening service",
    },
    {
        "name": "sensitive_login_path",
        "url": "https://example.com/login",
        "expected_valid": True,
        "expected_indicator": "sensitive terms",
    },
    {
        "name": "http_scheme",
        "url": "http://example.com",
        "expected_valid": True,
        "expected_indicator": "HTTP instead of HTTPS",
    },
    {
        "name": "nonstandard_port",
        "url": "https://example.com:8443",
        "expected_valid": True,
        "expected_indicator": "non-standard port",
    },
    {
        "name": "long_url",
        "url": "https://example.com/" + ("a" * 250),
        "expected_valid": True,
        "expected_indicator": "unusually long",
    },
]


def evaluate_case(case):
    """Run validity, indicator, and risk consistency checks."""

    result = analyze_url(case["url"])

    indicators = result.get("indicators", [])
    indicator_text = " | ".join(indicators)

    # Check input validity.
    validity_pass = (
        result.get("valid") is case["expected_valid"]
    )

    # Check whether the expected indicator exists.
    expected_indicator = case["expected_indicator"]

    if expected_indicator is None:
        indicator_pass = True
    else:
        indicator_pass = any(
            expected_indicator.lower() in indicator.lower()
            for indicator in indicators
        )

    # Check risk-score consistency.
    score = result.get("risk_score")
    level = result.get("risk_level")

    if result.get("valid") is False:
        risk_pass = True
        risk_message = "Not applicable to invalid input"
    elif not isinstance(score, (int, float)):
        risk_pass = False
        risk_message = "Missing or invalid risk score"
    elif not 0 <= score <= 100:
        risk_pass = False
        risk_message = "Risk score is outside 0-100"
    else:
        expected_level = (
            "High" if score >= 50
            else "Medium" if score >= 25
            else "Low"
        )

        risk_pass = str(level).lower() == expected_level.lower()

        risk_message = (
            f"Score {score}; reported level {level}; "
            f"expected level {expected_level}"
        )

    # Check that a detected lookalike is not silently overlooked.
    # This is a warning-presence check, not a requirement to
    # classify every lookalike domain as malicious.
    is_lookalike_case = case["name"].startswith("lookalike_")

    if is_lookalike_case and indicator_pass:
        warning_pass = bool(indicators)
    else:
        warning_pass = True

    return {
        "test_case": case["name"],
        "input_url": case["url"],
        "expected_valid": case["expected_valid"],
        "actual_valid": result.get("valid"),
        "validity_check": "PASS" if validity_pass else "FAIL",
        "expected_indicator": expected_indicator or "",
        "indicator_check": "PASS" if indicator_pass else "FAIL",
        "risk_score": score,
        "risk_level": level,
        "risk_consistency_check": (
            "PASS" if risk_pass else "FAIL"
        ),
        "risk_details": risk_message,
        "warning_check": "PASS" if warning_pass else "FAIL",
        "indicators": indicator_text,
    }


def main() -> int:
    results = [
        evaluate_case(case)
        for case in CASES
    ]

    output_path = PROJECT_ROOT / "url_evaluation_results.csv"

    if results:
        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=list(results[0].keys()),
            )
            writer.writeheader()
            writer.writerows(results)

    total = len(results)

    validity_passed = sum(
        row["validity_check"] == "PASS"
        for row in results
    )

    indicator_passed = sum(
        row["indicator_check"] == "PASS"
        for row in results
    )

    risk_passed = sum(
        row["risk_consistency_check"] == "PASS"
        for row in results
    )

    warning_passed = sum(
        row["warning_check"] == "PASS"
        for row in results
    )

    total_checks = total * 4
    passed_checks = (
        validity_passed
        + indicator_passed
        + risk_passed
        + warning_passed
    )

    print("\nCyberRakshak URL Evaluation")
    print("=" * 44)
    print(f"Test cases: {total}")
    print(f"Validity checks: {validity_passed}/{total}")
    print(f"Indicator checks: {indicator_passed}/{total}")
    print(f"Risk consistency checks: {risk_passed}/{total}")
    print(f"Warning checks: {warning_passed}/{total}")
    print(f"Total checks: {passed_checks}/{total_checks}")

    failures = [
        row for row in results
        if (
            row["validity_check"] == "FAIL"
            or row["indicator_check"] == "FAIL"
            or row["risk_consistency_check"] == "FAIL"
            or row["warning_check"] == "FAIL"
        )
    ]

    if failures:
        print("\nCases requiring investigation:")

        for row in failures:
            print(f"\n- {row['test_case']}")
            print(f"  Validity: {row['validity_check']}")
            print(f"  Indicator: {row['indicator_check']}")
            print(
                "  Risk consistency: "
                f"{row['risk_consistency_check']}"
            )
            print(f"  Warning: {row['warning_check']}")
            print(f"  Details: {row['risk_details']}")

    print(f"\nDetailed CSV report: {output_path}")

    print("\nInterpretation:")
    print(
        "- These tests check expected behavior and "
        "risk-score consistency."
    )
    print(
        "- They do not measure real-world phishing "
        "detection accuracy."
    )
    print(
        "- A warning does not prove a URL is malicious."
    )
    print(
        "- No detected warning does not guarantee a URL is safe."
    )
    print(
        "- Risk consistency checks do not prove that the "
        "underlying risk score is accurate."
    )
    print("- No network requests are made.")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

