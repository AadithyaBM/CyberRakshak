"""
CyberRakshak - Controlled Phishing Awareness Simulation

Uses fictional scenarios and synthetic data.
Does not collect credentials or contact real targets.
"""

from engine.url_analyzer import analyze_url


SCENARIOS = {
    "urgent_account_warning": {
        "title": "Urgent Account Warning",
        "message": (
            "A fictional message claims that your account will be "
            "restricted unless you verify your details immediately."
        ),
        "example_url": "http://192.0.2.10/account/verify",
        "warning_signs": [
            "The message creates urgency.",
            "The hostname is an IP address.",
            "The connection uses HTTP.",
            "The URL contains account-verification language.",
        ],
        "safe_action": (
            "Do not follow the message's instructions. "
            "Visit the service through its independently verified "
            "official app or website."
        ),
    },
    "unexpected_reward": {
        "title": "Unexpected Reward",
        "message": (
            "A fictional message claims that you have won a reward "
            "and asks you to open a shortened link."
        ),
        "example_url": "https://bit.ly/example",
        "warning_signs": [
            "The reward is unexpected.",
            "The destination is hidden behind a shortened URL.",
            "The message may be designed to encourage impulsive clicking.",
        ],
        "safe_action": (
            "Verify the offer independently. Do not provide payment "
            "details or sensitive information to claim an unverified prize."
        ),
    },
}


def run_simulation(scenario_id: str) -> dict:
    """
    Return an educational scenario and analyze its example URL.

    This function performs no network requests.
    """

    scenario = SCENARIOS.get(scenario_id)

    if scenario is None:
        return {
            "success": False,
            "error": "Unknown simulation scenario.",
        }

    analysis = analyze_url(scenario["example_url"])

    return {
        "success": True,
        "scenario_id": scenario_id,
        "title": scenario["title"],
        "message": scenario["message"],
        "example_url": scenario["example_url"],
        "warning_signs": list(scenario["warning_signs"]),
        "url_analysis": analysis,
        "safe_action": scenario["safe_action"],
        "network_requests_made": 0,
        "credentials_collected": False,
    }