"""
CyberRakshak - Authentication Security Lab

Demonstrates:
1. Secure password hashing using PBKDF2
2. Time-limited, one-time OTP verification
3. Login rate limiting

Educational prototype only. Not a production authentication service.
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field


# ============================================================
# 1. PASSWORD HASHING
# ============================================================

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, salt: bytes | None = None) -> dict:
    """
    Hash a password using PBKDF2-HMAC-SHA256.

    A random salt is generated when one is not supplied.
    Store the returned salt and hash, never the plaintext password.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    if salt is None:
        salt = secrets.token_bytes(16)

    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must contain at least 16 bytes.")

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return {
        "salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "iterations": PBKDF2_ITERATIONS,
    }


def verify_password(password: str, stored: dict) -> bool:
    """Verify a password against its stored hash."""

    if not isinstance(password, str):
        return False

    try:
        salt = bytes.fromhex(stored["salt"])
        expected_hash = bytes.fromhex(stored["password_hash"])
        iterations = stored["iterations"]

        if len(salt) < 16 or iterations < 1:
            return False

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(actual_hash, expected_hash)

    except (KeyError, TypeError, ValueError):
        return False


# ============================================================
# 2. ONE-TIME PASSWORD (OTP) DEMONSTRATION
# ============================================================

@dataclass
class OTPChallenge:
    """
    A simulated OTP challenge.

    In this lab, the code is returned to the caller for testing.
    A real application must deliver codes through a secure,
    independently configured channel.
    """

    code: str
    expires_at: float
    used: bool = False
    failed_attempts: int = 0
    max_attempts: int = 5


def create_otp(
    ttl_seconds: int = 120,
    now: float | None = None,
) -> OTPChallenge:
    """Create a random six-digit OTP with an expiry time."""

    if ttl_seconds <= 0:
        raise ValueError("OTP lifetime must be positive.")

    current_time = time.time() if now is None else now

    return OTPChallenge(
        code=f"{secrets.randbelow(1_000_000):06d}",
        expires_at=current_time + ttl_seconds,
    )


def verify_otp(
    challenge: OTPChallenge,
    submitted_code: str,
    now: float | None = None,
) -> bool:
    """Verify an OTP, enforcing expiry, attempt limits and one-time use."""

    current_time = time.time() if now is None else now

    if challenge.used:
        return False

    if current_time >= challenge.expires_at:
        return False

    if challenge.failed_attempts >= challenge.max_attempts:
        return False

    if not isinstance(submitted_code, str):
        challenge.failed_attempts += 1
        return False

    if not hmac.compare_digest(challenge.code, submitted_code):
        challenge.failed_attempts += 1
        return False

    challenge.used = True
    return True


# ============================================================
# 3. LOGIN RATE LIMITING
# ============================================================

@dataclass
class LoginRateLimiter:
    """
    In-memory rate limiter for an educational login simulation.

    Failed attempts are counted separately for each account key.
    """

    max_attempts: int = 5
    window_seconds: int = 60
    failures: dict[str, list[float]] = field(default_factory=dict)

    def __post_init__(self):
        if self.max_attempts <= 0:
            raise ValueError("Maximum attempts must be positive.")

        if self.window_seconds <= 0:
            raise ValueError("Window duration must be positive.")

    def is_allowed(
        self,
        account_key: str,
        now: float | None = None,
    ) -> bool:
        """Return whether another login attempt is currently allowed."""

        if not isinstance(account_key, str) or not account_key:
            raise ValueError("Account key must be a non-empty string.")

        current_time = time.time() if now is None else now
        cutoff = current_time - self.window_seconds

        recent_failures = [
            timestamp
            for timestamp in self.failures.get(account_key, [])
            if cutoff < timestamp <= current_time
        ]

        self.failures[account_key] = recent_failures

        return len(recent_failures) < self.max_attempts

    def record_failure(
        self,
        account_key: str,
        now: float | None = None,
    ) -> None:
        """Record a failed login attempt."""

        if not isinstance(account_key, str) or not account_key:
            raise ValueError("Account key must be a non-empty string.")

        current_time = time.time() if now is None else now

        self.failures.setdefault(account_key, []).append(current_time)

    def record_success(self, account_key: str) -> None:
        """Clear the account's failed-attempt history after success."""

        self.failures.pop(account_key, None)