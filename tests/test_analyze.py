"""
TraceX Analyzer Test Suite
Verifies ML pipeline inference, behavioural rule categories, identity indicator metrics,
and composite risk calculation.
"""

import os
import pytest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import (
    detect_behavioural_patterns, analyze_fake_identity,
    calculate_risk, analyze_message_full, load_model
)


def test_model_loaded():
    model = load_model()
    assert model is not None
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_proba")


def test_behavioural_patterns_detection():
    # 1. Location Monitoring
    loc_res = detect_behavioural_patterns("Where do you live? Send me your location.")
    assert "LOCATION MONITORING" in loc_res

    # 2. Surveillance / Tracking
    surv_res = detect_behavioural_patterns("I am watching your every move from outside your building.")
    assert "SURVEILLANCE / TRACKING" in surv_res

    # 3. Repeated Unwanted Contact
    repeat_res = detect_behavioural_patterns("Stop ignoring me! Why aren't you replying?")
    assert "REPEATED UNWANTED CONTACT" in repeat_res

    # 4. Threats / Intimidation
    threat_res = detect_behavioural_patterns("You cannot hide, I will find you.")
    assert "THREATS / INTIMIDATION" in threat_res

    # 5. Personal Information Targeting
    target_res = detect_behavioural_patterns("I know your home address and your phone number.")
    assert "PERSONAL INFORMATION TARGETING" in target_res

    # 6. Harassment / Pressure
    harass_res = detect_behavioural_patterns("You must reply immediately, I will not stop.")
    assert "HARASSMENT / PRESSURE" in harass_res

    # 7. Safe message
    safe_res = detect_behavioural_patterns("Hello! Hope you have a wonderful day.")
    assert safe_res == ["No strong suspicious pattern detected"]


def test_fake_identity_indicators():
    # Suspicious anonymous account
    susp_res = analyze_fake_identity(
        platform="Other",
        sender_username="anon_ghost_984712",
        sender_name="",
        profile_url=""
    )
    assert susp_res["status"] in ["SUSPICIOUS", "UNVERIFIED"]
    assert susp_res["score"] >= 40
    assert any("Handle contains deceptive indicator keywords" in ind for ind in susp_res["indicators"])
    assert any("display name omitted" in ind.lower() for ind in susp_res["indicators"])

    # Normal complete account
    norm_res = analyze_fake_identity(
        platform="Instagram",
        sender_username="sarah_miller",
        sender_name="Sarah Miller",
        profile_url="https://instagram.com/sarah_miller"
    )
    assert norm_res["status"] == "LOW INDICATOR"
    assert norm_res["score"] < 25


def test_risk_score_calculation():
    # High risk inputs
    score_high, level_high = calculate_risk(
        ml_prediction="cyberstalking",
        ml_proba_dict={"safe": 0.05, "suspicious": 0.15, "cyberstalking": 0.80},
        detected_patterns=["SURVEILLANCE / TRACKING", "LOCATION MONITORING", "THREATS / INTIMIDATION"],
        fake_id_score=75
    )
    assert score_high >= 70
    assert level_high == "HIGH"
    assert 0 <= score_high <= 100

    # Low risk inputs
    score_low, level_low = calculate_risk(
        ml_prediction="safe",
        ml_proba_dict={"safe": 0.95, "suspicious": 0.04, "cyberstalking": 0.01},
        detected_patterns=["No strong suspicious pattern detected"],
        fake_id_score=0
    )
    assert score_low <= 39
    assert level_low == "LOW"
    assert 0 <= score_low <= 100


def test_demo_cyberstalking_message():
    """
    Test Master Prompt specified demo message:
    'I am tracking your location and I will follow you everywhere.'
    Must detect relevant patterns naturally and output HIGH risk.
    """
    demo_msg = "I am tracking your location and I will follow you everywhere."
    result = analyze_message_full(
        message=demo_msg,
        platform="Instagram",
        sender_username="stalker_unknown",
        sender_name="",
        profile_url=""
    )

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 70
    assert any("LOCATION" in p or "TRACKING" in p or "SURVEILLANCE" in p for p in result["detected_patterns"])
    assert result["fake_id_status"] in ["SUSPICIOUS", "UNVERIFIED"]


def test_safe_collaborative_message():
    safe_msg = "Hey, are you joining the team meeting this afternoon?"
    result = analyze_message_full(
        message=safe_msg,
        platform="Email",
        sender_username="colleague_jane",
        sender_name="Jane Doe",
        profile_url="https://example.com/jane"
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] <= 39
    assert result["ai_prediction"] == "safe"
