import pytest

from security.auth_security import (
    LoginRateLimiter,
    create_otp,
    hash_password,
    verify_otp,
    verify_password,
)


# ============================================================
# PASSWORD HASHING TESTS
# ============================================================

def test_password_is_hashed():
    stored = hash_password("DemoPassword123!")

    assert "password_hash" in stored
    assert "salt" in stored
    assert stored["password_hash"] != "DemoPassword123!"


def test_correct_password_is_verified():
    stored = hash_password("DemoPassword123!")

    assert verify_password("DemoPassword123!", stored) is True


def test_incorrect_password_is_rejected():
    stored = hash_password("DemoPassword123!")

    assert verify_password("WrongPassword!", stored) is False


def test_password_hash_uses_a_random_salt():
    first = hash_password("DemoPassword123!")
    second = hash_password("DemoPassword123!")

    assert first["salt"] != second["salt"]
    assert first["password_hash"] != second["password_hash"]


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        hash_password("")


# ============================================================
# OTP TESTS
# ============================================================

def test_correct_otp_is_accepted():
    challenge = create_otp(ttl_seconds=120, now=1000)

    assert verify_otp(challenge, challenge.code, now=1050) is True


def test_otp_cannot_be_reused():
    challenge = create_otp(ttl_seconds=120, now=1000)

    assert verify_otp(challenge, challenge.code, now=1050) is True
    assert verify_otp(challenge, challenge.code, now=1051) is False


def test_expired_otp_is_rejected():
    challenge = create_otp(ttl_seconds=30, now=1000)

    assert verify_otp(challenge, challenge.code, now=1030) is False


def test_incorrect_otp_is_rejected():
    challenge = create_otp(ttl_seconds=120, now=1000)

    wrong_code = "000000"
    if wrong_code == challenge.code:
        wrong_code = "000001"

    assert verify_otp(challenge, wrong_code, now=1010) is False


def test_otp_attempt_limit_is_enforced():
    challenge = create_otp(ttl_seconds=120, now=1000)

    for _ in range(challenge.max_attempts):
        verify_otp(challenge, "incorrect", now=1010)

    assert verify_otp(challenge, challenge.code, now=1011) is False


def test_non_positive_otp_lifetime_is_rejected():
    with pytest.raises(ValueError):
        create_otp(ttl_seconds=0)


# ============================================================
# RATE LIMITER TESTS
# ============================================================

def test_rate_limiter_allows_initial_attempts():
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)

    assert limiter.is_allowed("demo-user", now=1000) is True


def test_rate_limiter_blocks_after_maximum_failures():
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)

    for timestamp in (1000, 1001, 1002):
        limiter.record_failure("demo-user", now=timestamp)

    assert limiter.is_allowed("demo-user", now=1003) is False


def test_rate_limiter_recovers_after_window():
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)

    limiter.record_failure("demo-user", now=1000)
    limiter.record_failure("demo-user", now=1001)

    assert limiter.is_allowed("demo-user", now=1062) is True


def test_success_clears_failed_attempt_history():
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)

    limiter.record_failure("demo-user", now=1000)
    limiter.record_failure("demo-user", now=1001)
    limiter.record_success("demo-user")

    assert limiter.is_allowed("demo-user", now=1002) is True


def test_rate_limit_is_separate_for_each_account():
    limiter = LoginRateLimiter(max_attempts=1, window_seconds=60)

    limiter.record_failure("user-a", now=1000)

    assert limiter.is_allowed("user-a", now=1001) is False
    assert limiter.is_allowed("user-b", now=1001) is True


def test_invalid_rate_limiter_configuration_is_rejected():
    with pytest.raises(ValueError):
        LoginRateLimiter(max_attempts=0)