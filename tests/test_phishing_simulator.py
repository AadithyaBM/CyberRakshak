from simulation.phishing_simulator import run_simulation


def test_urgent_warning_scenario():
    result = run_simulation("urgent_account_warning")

    assert result["success"] is True
    assert result["title"] == "Urgent Account Warning"
    assert result["url_analysis"]["valid"] is True


def test_reward_scenario():
    result = run_simulation("unexpected_reward")

    assert result["success"] is True
    assert result["title"] == "Unexpected Reward"
    assert result["url_analysis"]["valid"] is True


def test_unknown_scenario_is_rejected():
    result = run_simulation("unknown_scenario")

    assert result["success"] is False
    assert "error" in result


def test_simulation_does_not_collect_credentials():
    result = run_simulation("urgent_account_warning")

    assert result["credentials_collected"] is False
    assert result["network_requests_made"] == 0


def test_scenarios_include_safety_guidance():
    for scenario_id in (
        "urgent_account_warning",
        "unexpected_reward",
    ):
        result = run_simulation(scenario_id)

        assert result["safe_action"]
        assert len(result["warning_signs"]) >= 2