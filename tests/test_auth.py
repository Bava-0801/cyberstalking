"""
TraceX Authentication & API Security Test Suite
Tests registration, login, session auth, RBAC authorization, evidence upload, and analyze endpoints.
"""

import os
import io
import tempfile
import pytest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database import initialize_database, create_user, get_connection
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    # Setup temporary database
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(db_path)

    app.config["TESTING"] = True
    app.config["TRACEX_DB_PATH"] = db_path
    os.environ["TRACEX_DB_PATH"] = db_path

    # Create admin user
    admin_pwd_hash = generate_password_hash("AdminPass123!")
    create_user("superadmin", admin_pwd_hash, role="admin", db_path=db_path)

    with app.test_client() as test_client:
        yield test_client

    if os.path.exists(db_path):
        os.remove(db_path)


def test_public_pages(client):
    r_index = client.get("/")
    assert r_index.status_code == 200
    assert b"TraceX" in r_index.data

    r_login = client.get("/login")
    assert r_login.status_code == 200

    r_reg = client.get("/register-page")
    assert r_reg.status_code == 200


def test_registration_flow(client):
    # Valid registration
    r_ok = client.post("/register", json={
        "username": "newuser",
        "password": "Password123",
        "confirm_password": "Password123"
    })
    assert r_ok.status_code == 201
    assert r_ok.get_json()["success"] is True

    # Duplicate username
    r_dup = client.post("/register", json={
        "username": "newuser",
        "password": "Password123",
        "confirm_password": "Password123"
    })
    assert r_dup.status_code == 409

    # Password too short
    r_short = client.post("/register", json={
        "username": "shortpassuser",
        "password": "123",
        "confirm_password": "123"
    })
    assert r_short.status_code == 400

    # Password mismatch
    r_mismatch = client.post("/register", json={
        "username": "mismatchuser",
        "password": "Password123",
        "confirm_password": "DifferentPassword123"
    })
    assert r_mismatch.status_code == 400


def test_login_logout_and_session(client):
    # Register user
    client.post("/register", json={
        "username": "validuser",
        "password": "Password123",
        "confirm_password": "Password123"
    })

    # Unauthenticated /me
    r_me_unauth = client.get("/me")
    assert r_me_unauth.get_json()["authenticated"] is False

    # Failed login
    r_fail = client.post("/login", json={
        "username": "validuser",
        "password": "WrongPassword!"
    })
    assert r_fail.status_code == 401
    assert "Invalid username or password" in r_fail.get_json()["error"]

    # Successful login
    r_login = client.post("/login", json={
        "username": "validuser",
        "password": "Password123"
    })
    assert r_login.status_code == 200
    assert r_login.get_json()["success"] is True

    # Authenticated /me
    r_me_auth = client.get("/me")
    assert r_me_auth.status_code == 200
    me_data = r_me_auth.get_json()
    assert me_data["authenticated"] is True
    assert me_data["user"]["username"] == "validuser"

    # Logout
    r_logout = client.post("/logout")
    assert r_logout.status_code == 200

    # Verify session cleared
    r_me_cleared = client.get("/me")
    assert r_me_cleared.get_json()["authenticated"] is False


def test_authorization_protection(client):
    # Unauthenticated user visiting dashboard -> redirect to /login
    r_dash_unauth = client.get("/dashboard")
    assert r_dash_unauth.status_code == 302
    assert "/login" in r_dash_unauth.headers["Location"]

    # Register & Login regular user
    client.post("/register", json={
        "username": "regularjoe",
        "password": "Password123",
        "confirm_password": "Password123"
    })
    client.post("/login", json={
        "username": "regularjoe",
        "password": "Password123"
    })

    # Regular user can access dashboard
    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 200

    # Regular user CANNOT access admin (403 Forbidden)
    r_admin_forbidden = client.get("/admin")
    assert r_admin_forbidden.status_code == 403

    r_admin_users_api = client.get("/admin/users", headers={"Accept": "application/json"})
    assert r_admin_users_api.status_code == 403


def test_admin_access(client):
    # Login as admin
    client.post("/login", json={
        "username": "superadmin",
        "password": "AdminPass123!"
    })

    # Admin CAN access admin dashboard
    r_admin = client.get("/admin")
    assert r_admin.status_code == 200

    r_users = client.get("/admin/users", headers={"Accept": "application/json"})
    assert r_users.status_code == 200
    users_list = r_users.get_json()
    assert len(users_list) >= 1
    # Verify password_hash is omitted
    for u in users_list:
        assert "password_hash" not in u

    r_audit = client.get("/admin/audit-logs", headers={"Accept": "application/json"})
    assert r_audit.status_code == 200


def test_evidence_upload_validation(client):
    # Login
    client.post("/register", json={
        "username": "uploader",
        "password": "Password123",
        "confirm_password": "Password123"
    })
    client.post("/login", json={
        "username": "uploader",
        "password": "Password123"
    })

    # Valid PNG upload
    fake_png = (io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRtest_data"), "screenshot.png")
    r_up_ok = client.post("/upload-evidence", data={"file": fake_png}, content_type="multipart/form-data")
    assert r_up_ok.status_code == 201
    up_json = r_up_ok.get_json()
    assert up_json["success"] is True
    assert "hash" in up_json
    assert len(up_json["hash"]) == 64  # SHA-256 length

    # Malicious/Invalid extension (.exe) rejected
    fake_exe = (io.BytesIO(b"MZ\x90\x00binary"), "malware.exe")
    r_up_bad = client.post("/upload-evidence", data={"file": fake_exe}, content_type="multipart/form-data")
    assert r_up_bad.status_code == 400
    assert "Unsupported file type" in r_up_bad.get_json()["error"]


def test_analyze_and_incident_flow(client):
    # Login
    client.post("/register", json={
        "username": "investigator",
        "password": "Password123",
        "confirm_password": "Password123"
    })
    client.post("/login", json={
        "username": "investigator",
        "password": "Password123"
    })

    # Empty message rejection
    r_empty = client.post("/analyze", json={"message": ""})
    assert r_empty.status_code == 400

    # Real analysis
    r_analyze = client.post("/analyze", json={
        "platform": "Instagram",
        "sender_username": "anon_stalker_9918",
        "sender_name": "",
        "profile_url": "",
        "message": "I am tracking your location and I will follow you everywhere."
    })
    assert r_analyze.status_code == 201
    res_data = r_analyze.get_json()
    assert res_data["success"] is True
    assert res_data["risk_level"] == "HIGH"
    incident_id = res_data["incident_id"]

    # Retrieve incidents list
    r_list = client.get("/incidents", headers={"Accept": "application/json"})
    assert r_list.status_code == 200
    incidents = r_list.get_json()
    assert len(incidents) >= 1
    assert incidents[0]["id"] == incident_id

    # Retrieve specific incident detail
    r_detail = client.get(f"/incidents/{incident_id}")
    assert r_detail.status_code == 200
    assert b"Incident Assessment Report" in r_detail.data


def test_security_headers(client):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin-when-cross-origin" in r.headers.get("Referrer-Policy")


def test_input_validation_hardening(client):
    # Login
    client.post("/register", json={"username": "validator", "password": "Password123", "confirm_password": "Password123"})
    client.post("/login", json={"username": "validator", "password": "Password123"})

    # Empty file upload
    empty_file = (io.BytesIO(b""), "empty.png")
    r_empty = client.post("/upload-evidence", data={"file": empty_file}, content_type="multipart/form-data")
    assert r_empty.status_code == 400
    assert "empty" in r_empty.get_json()["error"].lower()

    # Invalid profile URL scheme
    r_bad_url = client.post("/analyze", json={
        "message": "Sample message for URL testing",
        "profile_url": "javascript:alert('xss')"
    })
    assert r_bad_url.status_code == 400
    assert "http://" in r_bad_url.get_json()["error"]


def test_stats_scoping(client):
    # Login as admin
    client.post("/login", json={"username": "superadmin", "password": "AdminPass123!"})

    # Scope = global
    r_global = client.get("/stats?scope=global", headers={"Accept": "application/json"})
    assert r_global.status_code == 200
    d_global = r_global.get_json()
    assert "total_users" in d_global
    assert d_global["total_users"] >= 1

    # Scope = user
    r_user = client.get("/stats?scope=user", headers={"Accept": "application/json"})
    assert r_user.status_code == 200


def test_error_pages(client):
    # 404 page
    r_404 = client.get("/non-existent-route-xyz")
    assert r_404.status_code == 404
    assert b"HTTP 404" in r_404.data
    assert b"Page Not Found" in r_404.data

    # 403 page
    client.post("/register", json={"username": "nonadmin", "password": "Password123", "confirm_password": "Password123"})
    client.post("/login", json={"username": "nonadmin", "password": "Password123"})
    r_403 = client.get("/admin")
    assert r_403.status_code == 403
    assert b"HTTP 403" in r_403.data
    assert b"Access Forbidden" in r_403.data
