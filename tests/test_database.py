"""
TraceX Database Test Suite
Verifies schema creation, user CRUD, duplicate constraints, incident storage, and audit logs.
"""

import os
import tempfile
import pytest
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import (
    initialize_database, create_user, get_user_by_username,
    get_user_by_id, save_incident, get_incidents_by_user,
    get_incident_by_id, get_statistics, save_audit_log,
    get_audit_logs, get_all_users
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_database_initialization(temp_db):
    assert os.path.exists(temp_db)
    # Check tables exist
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    assert "users" in tables
    assert "incidents" in tables
    assert "audit_logs" in tables


def test_user_creation_and_retrieval(temp_db):
    pwd_hash = generate_password_hash("SecretP@ssword123")
    user_id = create_user("testuser", pwd_hash, role="user", db_path=temp_db)
    assert user_id > 0

    user = get_user_by_username("testuser", db_path=temp_db)
    assert user is not None
    assert user["id"] == user_id
    assert user["username"] == "testuser"
    assert user["role"] == "user"
    assert check_password_hash(user["password_hash"], "SecretP@ssword123")

    user_by_id = get_user_by_id(user_id, db_path=temp_db)
    assert user_by_id is not None
    assert user_by_id["username"] == "testuser"


def test_duplicate_user_rejection(temp_db):
    pwd_hash = generate_password_hash("Password123")
    create_user("duplicate_user", pwd_hash, role="user", db_path=temp_db)

    with pytest.raises(sqlite3.IntegrityError):
        create_user("duplicate_user", pwd_hash, role="user", db_path=temp_db)


def test_incident_storage_and_query(temp_db):
    pwd_hash = generate_password_hash("Password123")
    uid1 = create_user("alice", pwd_hash, role="user", db_path=temp_db)
    uid2 = create_user("bob", pwd_hash, role="user", db_path=temp_db)

    # Save incident for user 1
    inc_id = save_incident(
        user_id=uid1,
        message="I know where you live",
        platform="Instagram",
        sender_username="anon_stalker",
        sender_name="Anonymous",
        profile_url="https://instagram.com/anon",
        risk_level="HIGH",
        risk_score=85,
        ai_prediction="cyberstalking",
        ai_confidence=92.5,
        detected_patterns=["LOCATION MONITORING", "SURVEILLANCE / TRACKING"],
        fake_id_status="SUSPICIOUS",
        fake_id_score=60,
        fake_id_indicators=["Handle contains suspicious keyword: anon"],
        evidence_filename="evidence_123.png",
        evidence_hash="abcdef1234567890",
        db_path=temp_db
    )
    assert inc_id > 0

    # User 1 should see it
    incidents_u1 = get_incidents_by_user(user_id=uid1, is_admin=False, db_path=temp_db)
    assert len(incidents_u1) == 1
    assert incidents_u1[0]["id"] == inc_id
    assert incidents_u1[0]["risk_level"] == "HIGH"
    assert isinstance(incidents_u1[0]["detected_patterns"], list)

    # User 2 should NOT see user 1's incident
    incidents_u2 = get_incidents_by_user(user_id=uid2, is_admin=False, db_path=temp_db)
    assert len(incidents_u2) == 0

    # Single incident query
    item = get_incident_by_id(inc_id, user_id=uid1, is_admin=False, db_path=temp_db)
    assert item is not None
    assert item["message"] == "I know where you live"

    item_forbidden = get_incident_by_id(inc_id, user_id=uid2, is_admin=False, db_path=temp_db)
    assert item_forbidden is None


def test_statistics_calculation(temp_db):
    pwd_hash = generate_password_hash("Password123")
    uid = create_user("analyst", pwd_hash, role="user", db_path=temp_db)

    # Add 1 high, 1 low
    save_incident(
        user_id=uid, message="Threat message", platform="SMS", sender_username="u1", sender_name="N1",
        profile_url="", risk_level="HIGH", risk_score=80, ai_prediction="cyberstalking", ai_confidence=90.0,
        detected_patterns=[], fake_id_status="SUSPICIOUS", fake_id_score=55, fake_id_indicators=[],
        db_path=temp_db
    )
    save_incident(
        user_id=uid, message="Hello friend", platform="Email", sender_username="u2", sender_name="N2",
        profile_url="", risk_level="LOW", risk_score=10, ai_prediction="safe", ai_confidence=95.0,
        detected_patterns=[], fake_id_status="LOW INDICATOR", fake_id_score=0, fake_id_indicators=[],
        db_path=temp_db
    )

    stats = get_statistics(user_id=uid, is_admin=False, db_path=temp_db)
    assert stats["total_incidents"] == 2
    assert stats["high_risk"] == 1
    assert stats["medium_risk"] == 0
    assert stats["low_risk"] == 1
    assert stats["potential_identity_flags"] == 1


def test_audit_logs(temp_db):
    pwd_hash = generate_password_hash("Password123")
    uid = create_user("auditor", pwd_hash, role="admin", db_path=temp_db)

    log_id = save_audit_log(uid, "auditor", "TEST_ACTION", "Testing audit log entry", db_path=temp_db)
    assert log_id > 0

    logs = get_audit_logs(limit=10, db_path=temp_db)
    assert len(logs) == 1
    assert logs[0]["action"] == "TEST_ACTION"
    assert logs[0]["username"] == "auditor"
