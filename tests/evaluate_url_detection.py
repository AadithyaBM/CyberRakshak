"""
CyberRakshak URL Rule-Coverage Evaluation

This script evaluates the existing local URL analyzer against a small,
transparent set of structural test cases. Labels describe the pattern being
tested, NOT whether a real URL is malicious or safe.

Run from the project root:
    python tests/evaluate_url_detection.py

No network requests are made.
"""

import csv
import sys
from pathlib import Path

# Allow this script to run directly from the project root on Windows.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.url_analyzer import analyze_url  # noqa: E402


CASES = [
    # Invalid input / URL parsing
    {"name": "empty_input", "url": "", "expected_valid": False, "pattern": "invalid_input"},
    {"name": "whitespace_input", "url": "https://example.com/a b", "expected_valid": False, "pattern": "invalid_input"},
    {"name": "unsupported_scheme", "url": "ftp://example.com/file", "expected_valid": False, "pattern": "unsupported_scheme"},
    {"name": "missing_hostname", "url": "https://", "expected_valid": False, "pattern": "invalid_url"},
    {"name": "invalid_hostname_label", "url": "https://-example.com", "expected_valid": False, "pattern": "invalid_hostname"},

    # Baseline structures. These are not claims that the sites are safe.
    {"name": "plain_https_domain", "url": "https://example.com", "expected_valid": True, "pattern": "baseline"},
    {"name": "domain_without_scheme", "url": "example.com", "expected_valid": True, "pattern": "scheme_normalization"},
    {"name": "ordinary_path", "url": "https://example.com/about", "expected_valid": True, "pattern": "baseline"},
    {"name": "trailing_dot_hostname", "url": "https://example.com.", "expected_valid": True, "pattern": "hostname_normalization"},

    # Rules implemented by the analyzer
    {"name": "ip_hostname", "url": "http://192.0.2.1/login", "expected_valid": True, "pattern": "ip_hostname"},
    {"name": "url_with_at_authority", "url": "https://example.com@evil.test/login", "expected_valid": True, "pattern": "at_in_authority"},
    {"name": "many_subdomains", "url": "https://a.b.c.d.example.com", "expected_valid": True, "pattern": "many_subdomains"},
    {"name": "lookalike_paypal", "url": "https://paypa1.com", "expected_valid": True, "pattern": "lookalike_domain"},
    {"name": "lookalike_google", "url": "https://g00gle.com", "expected_valid": True, "pattern": "lookalike_domain"},
    {"name": "lookalike_amazon", "url": "https://amaz0n.com", "expected_valid": True, "pattern": "lookalike_domain"},
    {"name": "brand_in_subdomain", "url": "https://paypal.example.com", "expected_valid": True, "pattern": "brand_subdomain"},
    {"name": "known_shortener", "url": "https://bit.ly/example", "expected_valid": True, "pattern": "shortener"},
    {"name": "sensitive_login_path", "url": "https://example.com/login", "expected_valid": True, "pattern": "sensitive_keyword"},
    {"name": "http_scheme", "url": "http://example.com", "expected_valid": True, "pattern": "http_scheme"},
    {"name": "nonstandard_port", "url": "https://example.com:8443", "expected_valid": True, "pattern": "nonstandard_port"},
    {"name": "long_url", "url": "https://example.com/" + ("a" * 110), "expected_valid": True, "pattern": "long_url"},
]


def main() -> int:
    results = []
    passed = 0

    for case in CASES:
        result = analyze_url(case["url"])
        valid_pass = result.get("valid") is case["expected_valid"]
        passed += int(valid_pass)

        indicators = " | ".join(result.get("indicators", []))
        results.append({
            "test_case": case["name"],
            "pattern_under_test": case["pattern"],
            "input_url": case["url"],
            "expected_valid": case["expected_valid"],
            "actual_valid": result.get("valid"),
            "validity_check": "PASS" if valid_pass else "FAIL",
            "risk_score": result.get("risk_score"),
            "risk_level": result.get("risk_level"),
            "hostname": result.get("hostname") or "",
            "indicators": indicators,
            "analysis_method": result.get("analysis_method"),
            "verification_status": result.get("verification_status"),
            "destination_status": result.get("destination_status"),
        })

    output_path = PROJECT_ROOT / "url_evaluation_results.csv"
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    print("\nCyberRakshak URL Rule-Coverage Evaluation")
    print("=" * 44)
    print(f"Validity checks passed: {passed}/{total}")
    print(f"Validity checks failed: {total - passed}/{total}")
    print("\nRisk-level counts (valid URLs only):")
    levels = {"Low": 0, "Medium": 0, "High": 0}
    for case, row in zip(CASES, results):
        if row["actual_valid"]:
            levels[row["risk_level"]] = levels.get(row["risk_level"], 0) + 1
    for level, count in levels.items():
        print(f"  {level}: {count}")

    print(f"\nDetailed CSV report: {output_path}")
    print("\nImportant interpretation:")
    print("- This is a small rule-coverage/behavior check, not a security accuracy benchmark.")
    print("- Pattern labels are not verified malicious/benign ground truth.")
    print("- A Low score does not prove a URL is safe; a warning does not prove it is malicious.")
    print("- The analyzer uses local heuristics and does not visit URLs or verify destinations.")

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
