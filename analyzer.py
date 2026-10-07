"""
TraceX Analyzer Engine
Combines:
1. TF-IDF + Logistic Regression ML classification
2. Rule-based behavioural detection
3. Potential identity indicator analysis
4. Weighted risk score & level calculation
"""

import os
import re
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "cyberstalking_model.pkl")

# Behavioural pattern rule sets
BEHAVIOURAL_PATTERNS = {
    "LOCATION MONITORING": [
        r"where are you",
        r"where do you live",
        r"where you live",
        r"your location",
        r"track your location",
        r"i know where you live",
        r"i know where you work",
        r"live location",
        r"send me your location",
        r"gps coordinates",
        r"gps",
        r"your coordinates",
        r"where you spend",
        r"what floor your apartment",
        r"front door",
        r"doorstep"
    ],
    "SURVEILLANCE / TRACKING": [
        r"i am watching you",
        r"i'm watching you",
        r"watching you",
        r"i am tracking you",
        r"i'm tracking you",
        r"tracking you",
        r"i am following you",
        r"i'm following you",
        r"following you",
        r"watching your every move",
        r"eyes on you",
        r"following behind",
        r"parked outside",
        r"tracker on",
        r"monitoring all your",
        r"outside your window",
        r"outside your building",
        r"took photos of",
        r"took pictures of",
        r"saw you driving",
        r"standing outside",
        r"standing in your hallway"
    ],
    "REPEATED UNWANTED CONTACT": [
        r"stop ignoring me",
        r"why aren't you replying",
        r"why are you ignoring me",
        r"why won't you reply",
        r"answer me",
        r"reply to me",
        r"why haven't you answered",
        r"pick up your phone",
        r"made (?:new|\d+) accounts",
        r"keep messaging",
        r"leaving me on read",
        r"keep checking your status",
        r"rejecting my follow requests"
    ],
    "THREATS / INTIMIDATION": [
        r"you cannot hide",
        r"can't hide",
        r"you cannot escape",
        r"can't escape",
        r"i will find you",
        r"i'll find you",
        r"i will follow you",
        r"you cannot get away",
        r"can't get away",
        r"you will regret",
        r"life becomes a nightmare",
        r"confront you",
        r"hunt you",
        r"hunting your whereabouts",
        r"nowhere left to hide",
        r"nowhere you can go"
    ],
    "PERSONAL INFORMATION TARGETING": [
        r"your address",
        r"your phone number",
        r"your family",
        r"your workplace",
        r"your school",
        r"where your sister",
        r"what car you drive",
        r"daily routine",
        r"daily commute",
        r"what time you leave",
        r"home address",
        r"private number"
    ],
    "HARASSMENT / PRESSURE": [
        r"reply immediately",
        r"you must reply",
        r"i won't stop",
        r"i will not stop",
        r"can't keep avoiding",
        r"you need to reply",
        r"what are you hiding",
        r"don't talk to other",
        r"only talk to me",
        r"whether you like it or not"
    ]
}

SUSPICIOUS_HANDLE_TERMS = [
    "anon", "anonymous", "unknown", "fake", "hidden", "secret", "nobody",
    "ghost", "burner", "throwaway", "stalker", "shadow", "temp", "void", "spy"
]

VALID_PLATFORMS = [
    "Instagram", "WhatsApp", "Telegram", "Facebook", "X", "Email", "SMS", "Other"
]

_loaded_model = None


def load_model():
    """
    Load the cached ML model pipeline or train on-the-fly if missing.
    """
    global _loaded_model
    if _loaded_model is not None:
        return _loaded_model

    if os.path.exists(MODEL_PATH):
        try:
            _loaded_model = joblib.load(MODEL_PATH)
            return _loaded_model
        except Exception as e:
            print(f"[!] Warning: Failed to load model from {MODEL_PATH}: {e}")

    # Fallback to train if not available
    try:
        from train_model import train_model
        _loaded_model = train_model()
        return _loaded_model
    except Exception as e:
        print(f"[!] Error: Could not train model fallback: {e}")
        return None


def detect_behavioural_patterns(message):
    """
    Run regex rule-based behavioral detection on message.
    Returns list of matched categories or ['No strong suspicious pattern detected'].
    """
    if not message:
        return ["No strong suspicious pattern detected"]

    clean_text = message.lower()
    detected = []

    for category, regex_list in BEHAVIOURAL_PATTERNS.items():
        matched = False
        for pattern in regex_list:
            if re.search(pattern, clean_text, re.IGNORECASE):
                matched = True
                break
        if matched:
            detected.append(category)

    if not detected:
        return ["No strong suspicious pattern detected"]
    return detected


def analyze_fake_identity(platform, sender_username, sender_name, profile_url):
    """
    Analyze potential identity indicators from sender metadata.
    Does NOT prove identity or verify true individual.
    Returns dict: status, score, indicators.
    """
    indicators = []
    points = 0

    username = (sender_username or "").strip()
    name = (sender_name or "").strip()
    url = (profile_url or "").strip()
    plat = (platform or "").strip()

    # Platform check
    if not plat or plat not in VALID_PLATFORMS:
        indicators.append("Unverified communication platform specified")
        points += 15

    # Username check
    if not username:
        indicators.append("Sender handle/username not provided")
        points += 25
    else:
        # Check suspicious keywords
        lower_u = username.lower()
        matched_kw = [kw for kw in SUSPICIOUS_HANDLE_TERMS if kw in lower_u]
        if matched_kw:
            indicators.append(f"Handle contains deceptive indicator keywords: {', '.join(matched_kw)}")
            points += 25

        # Check excessive digits pattern (e.g. user_84719283)
        if re.search(r"\d{5,}$", username):
            indicators.append("Handle contains extended numeric sequence typical of automated or temporary accounts")
            points += 15

        # Extreme short or random symbols
        if len(username) < 3:
            indicators.append("Handle is unusually short or incomplete")
            points += 10

    # Sender Name check
    if not name:
        indicators.append("Sender display name omitted")
        points += 15
    elif username and name and username.lower() == name.lower():
        # Handle equals name
        pass

    # Profile URL check
    if not url:
        indicators.append("Profile URL reference not provided")
        points += 15
    else:
        # Basic URL format check
        if not re.match(r"^https?://[^\s/$.?#].[^\s]*$", url, re.IGNORECASE):
            indicators.append("Profile URL format does not conform to standard HTTP/HTTPS syntax")
            points += 15

    # Clamp score
    fake_id_score = min(100, points)

    # Determine status
    if fake_id_score >= 50:
        status = "SUSPICIOUS"
    elif fake_id_score >= 25:
        status = "UNVERIFIED"
    else:
        status = "LOW INDICATOR"

    if not indicators:
        indicators.append("Standard profile metadata provided with no overt deceptive indicators detected")

    return {
        "status": status,
        "score": fake_id_score,
        "indicators": indicators
    }


def calculate_risk(ml_prediction, ml_proba_dict, detected_patterns, fake_id_score):
    """
    Calculate consolidated risk score (0-100) and risk level (LOW, MEDIUM, HIGH).
    Uses weighted ML probabilities + behavioral indicators + identity indicators.
    """
    # 1. Base ML Contribution (up to 55 points)
    p_stalk = ml_proba_dict.get("cyberstalking", 0.0)
    p_susp = ml_proba_dict.get("suspicious", 0.0)
    p_safe = ml_proba_dict.get("safe", 0.0)

    # Weighted ML points
    ml_points = (p_stalk * 55.0) + (p_susp * 32.0) + (p_safe * 2.0)

    # 2. Behavioural Pattern Contribution (up to 35 points)
    active_patterns = [p for p in detected_patterns if p != "No strong suspicious pattern detected"]
    # Severe categories give higher weight
    high_threat_cats = {"SURVEILLANCE / TRACKING", "THREATS / INTIMIDATION", "LOCATION MONITORING"}
    pattern_points = 0
    for pat in active_patterns:
        if pat in high_threat_cats:
            pattern_points += 12
        else:
            pattern_points += 8
    pattern_points = min(35, pattern_points)

    # 3. Identity Indicator Contribution (up to 10 points)
    identity_points = (fake_id_score / 100.0) * 10.0

    # Total Score clamped 0 to 100
    raw_score = ml_points + pattern_points + identity_points

    # Override: If threats or surveillance + location are detected, ensure minimum HIGH floor
    has_threat = any(p in active_patterns for p in ["THREATS / INTIMIDATION", "SURVEILLANCE / TRACKING"])
    if has_threat and len(active_patterns) >= 2:
        raw_score = max(raw_score, 72.0)

    risk_score = int(round(max(0, min(100, raw_score))))

    # Risk Level mapping
    if risk_score <= 39:
        risk_level = "LOW"
    elif risk_score <= 69:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return risk_score, risk_level


def analyze_message_full(message, platform="", sender_username="", sender_name="", profile_url=""):
    """
    Comprehensive analysis pipeline for TraceX.
    """
    clean_message = (message or "").strip()
    if not clean_message:
        raise ValueError("Message content is required for analysis.")

    model = load_model()

    # ML Inference
    if model is not None:
        try:
            preds = model.predict([clean_message])
            ai_prediction = str(preds[0])

            probas = model.predict_proba([clean_message])[0]
            classes = list(model.classes_)
            proba_dict = {cls: float(prob) for cls, prob in zip(classes, probas)}

            # AI confidence = maximum class probability * 100
            max_prob = max(probas)
            ai_confidence = round(float(max_prob) * 100, 1)
        except Exception as e:
            print(f"[!] ML prediction error: {e}")
            ai_prediction = "suspicious"
            proba_dict = {"safe": 0.2, "suspicious": 0.5, "cyberstalking": 0.3}
            ai_confidence = 50.0
    else:
        ai_prediction = "suspicious"
        proba_dict = {"safe": 0.2, "suspicious": 0.5, "cyberstalking": 0.3}
        ai_confidence = 50.0

    # Behavioural Detection
    detected_patterns = detect_behavioural_patterns(clean_message)

    # Identity Indicator Analysis
    fake_id_data = analyze_fake_identity(platform, sender_username, sender_name, profile_url)

    # Consolidated Risk Calculation
    risk_score, risk_level = calculate_risk(
        ai_prediction, proba_dict, detected_patterns, fake_id_data["score"]
    )

    return {
        "ai_prediction": ai_prediction,
        "ai_confidence": ai_confidence,
        "proba_dict": proba_dict,
        "detected_patterns": detected_patterns,
        "fake_id_status": fake_id_data["status"],
        "fake_id_score": fake_id_data["score"],
        "fake_id_indicators": fake_id_data["indicators"],
        "risk_score": risk_score,
        "risk_level": risk_level
    }
