"""
CyberRakshak - Defense Validation Engine

Runs controlled checks against authentication security controls.

A PASS means the tested behavior matched the expected result.
It does not certify the entire application as secure.
"""

from datetime import datetime, timezone

from security.auth_security import (
    LoginRateLimiter,
    create_otp,
    hash_password,
    verify_otp,
    verify_password,
)


def validate_password_hashing() -> dict:
    """Check that password hashing and verification behave correctly."""

    try:
        password = "CyberRakshak-Demo-Password-123!"
        stored = hash_password(password)

        checks = {
            "plaintext_not_stored": (
                stored["password_hash"] != password
            ),
            "correct_password_accepted": (
                verify_password(password, stored) is True
            ),
            "incorrect_password_rejected": (
                verify_password("Incorrect-Demo-Password!", stored)
                is False
            ),
            "salt_present": bool(stored["salt"]),
        }

        passed = all(checks.values())

        return {
            "test": "Password Hashing",
            "status": "PASS" if passed else "FAIL",
            "checks": checks,
            "details": (
                "Password hashing and verification behaved as expected."
                if passed
                else "One or more password hashing checks failed."
            ),
        }

    except Exception as exc:
        return {
            "test": "Password Hashing",
            "status": "FAIL",
            "checks": {},
            "details": f"Validation could not complete: {type(exc).__name__}",
        }


def validate_otp_security() -> dict:
    """Check OTP expiry, one-time use and incorrect-code rejection."""

    try:
        now = 1_000_000.0

        valid_challenge = create_otp(ttl_seconds=60, now=now)
        correct_code_accepted = verify_otp(
            valid_challenge,
            valid_challenge.code,
            now=now + 10,
        )
        reused_code_rejected = not verify_otp(
            valid_challenge,
            valid_challenge.code,
            now=now + 11,
        )

        expired_challenge = create_otp(ttl_seconds=10, now=now)
        expired_code_rejected = not verify_otp(
            expired_challenge,
            expired_challenge.code,
            now=now + 10,
        )

        wrong_challenge = create_otp(ttl_seconds=60, now=now)
        wrong_code = (
            "000000"
            if wrong_challenge.code != "000000"
            else "000001"
        )
        incorrect_code_rejected = not verify_otp(
            wrong_challenge,
            wrong_code,
            now=now + 1,
        )

        checks = {
            "valid_code_accepted": correct_code_accepted,
            "reused_code_rejected": reused_code_rejected,
            "expired_code_rejected": expired_code_rejected,
            "incorrect_code_rejected": incorrect_code_rejected,
        }

        passed = all(checks.values())

        return {
            "test": "OTP Security",
            "status": "PASS" if passed else "FAIL",
            "checks": checks,
            "details": (
                "OTP expiry and one-time-use checks behaved as expected."
                if passed
                else "One or more OTP security checks failed."
            ),
        }

    except Exception as exc:
        return {
            "test": "OTP Security",
            "status": "FAIL",
            "checks": {},
            "details": f"Validation could not complete: {type(exc).__name__}",
        }


def validate_login_rate_limiting() -> dict:
    """Check that repeated failed attempts are restricted."""

    try:
        limiter = LoginRateLimiter(
            max_attempts=3,
            window_seconds=60,
        )

        now = 2_000_000.0
        account = "cyberrakshak-demo-account"

        initially_allowed = limiter.is_allowed(account, now=now)

        for offset in range(3):
            limiter.record_failure(
                account,
                now=now + offset,
            )

        blocked_after_failures = not limiter.is_allowed(
            account,
            now=now + 3,
        )

        different_account_allowed = limiter.is_allowed(
            "another-demo-account",
            now=now + 3,
        )

        checks = {
            "initial_attempt_allowed": initially_allowed,
            "blocked_after_repeated_failures": blocked_after_failures,
            "different_account_independent": different_account_allowed,
        }

        passed = all(checks.values())

        return {
            "test": "Login Rate Limiting",
            "status": "PASS" if passed else "FAIL",
            "checks": checks,
            "details": (
                "Rate-limiting checks behaved as expected."
                if passed
                else "One or more rate-limiting checks failed."
            ),
        }

    except Exception as exc:
        return {
            "test": "Login Rate Limiting",
            "status": "FAIL",
            "checks": {},
            "details": f"Validation could not complete: {type(exc).__name__}",
        }


def run_all_validations() -> dict:
    """Execute all registered defense checks and summarize the results."""

    results = [
        validate_password_hashing(),
        validate_otp_security(),
        validate_login_rate_limiting(),
    ]

    passed = sum(
        result["status"] == "PASS"
        for result in results
    )
    failed = len(results) - passed

    return {
        "project": "CyberRakshak",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "overall_status": "PASS" if failed == 0 else "FAIL",
        },
        "results": results,
    }