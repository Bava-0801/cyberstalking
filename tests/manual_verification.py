"""
TraceX Complete 15-Point Manual Test Plan Runner
Simulates every manual test case end-to-end against the Flask application.
"""

import os
import io
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database import initialize_database, create_user
from werkzeug.security import generate_password_hash


def run_manual_test_plan():
    print("=" * 70)
    print("TRACEX 15-POINT SYSTEMATIC VERIFICATION SUITE")
    print("=" * 70)

    # Initialize fresh test database
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(db_path)
    app.config["TESTING"] = True
    app.config["TRACEX_DB_PATH"] = db_path
    os.environ["TRACEX_DB_PATH"] = db_path

    # Create admin user for testing
    admin_pw = generate_password_hash("AdminPass123!")
    create_user("systemadmin", admin_pw, role="admin", db_path=db_path)

    client = app.test_client()

    # TEST 1: Open /
    print("\n[TEST 1] Open / (Landing page)")
    r1 = client.get("/")
    assert r1.status_code == 200 and b"Detect. Analyze. Protect." in r1.data
    print("   [PASS] Landing page loads successfully with correct brand heading.")

    # TEST 2: Register new account
    print("\n[TEST 2] Register new account")
    r2 = client.post("/register", json={
        "username": "demouser",
        "password": "UserPass123!",
        "confirm_password": "UserPass123!"
    })
    assert r2.status_code == 201 and r2.get_json()["success"] is True
    print("   [PASS] Account 'demouser' created successfully.")

    # TEST 3: Login
    print("\n[TEST 3] Login with created account")
    r3 = client.post("/login", json={
        "username": "demouser",
        "password": "UserPass123!"
    })
    assert r3.status_code == 200 and r3.get_json()["success"] is True
    r3_me = client.get("/me")
    assert r3_me.get_json()["authenticated"] is True
    print("   [PASS] User session established; authenticated as 'demouser'.")

    # TEST 4: Enter safe message
    print("\n[TEST 4] Enter safe message")
    r4 = client.post("/analyze", json={
        "platform": "Email",
        "sender_username": "jane_colleague",
        "sender_name": "Jane Doe",
        "profile_url": "https://company.internal/jane",
        "message": "Good morning! Can you review the presentation slides for today's meeting?"
    })
    assert r4.status_code == 201
    d4 = r4.get_json()
    assert d4["risk_level"] == "LOW"
    assert d4["risk_score"] <= 39
    print(f"   [PASS] Safe message evaluated as {d4['risk_level']} (Score: {d4['risk_score']}).")

    # TEST 5: Enter suspicious message
    print("\n[TEST 5] Enter suspicious message")
    r5 = client.post("/analyze", json={
        "platform": "Instagram",
        "sender_username": "curious_user_1",
        "sender_name": "",
        "profile_url": "",
        "message": "Why aren't you replying to my messages? Do you live alone in that apartment?"
    })
    assert r5.status_code == 201
    d5 = r5.get_json()
    assert d5["risk_level"] in ["MEDIUM", "HIGH"]
    print(f"   [PASS] Suspicious message evaluated as {d5['risk_level']} (Score: {d5['risk_score']}).")

    # TEST 6: Enter cyberstalking-style message
    print("\n[TEST 6] Enter demo cyberstalking message")
    demo_msg = "I am tracking your location and I will follow you everywhere."
    r6 = client.post("/analyze", json={
        "platform": "Instagram",
        "sender_username": "anon_stalker_99",
        "sender_name": "",
        "profile_url": "",
        "message": demo_msg
    })
    assert r6.status_code == 201
    d6 = r6.get_json()
    assert d6["risk_level"] == "HIGH"
    assert d6["risk_score"] >= 70
    assert any("TRACKING" in p or "LOCATION" in p or "SURVEILLANCE" in p for p in d6["detected_patterns"])
    print(f"   [PASS] Cyberstalking message evaluated as {d6['risk_level']} (Score: {d6['risk_score']}).")
    print(f"          Detected Patterns: {d6['detected_patterns']}")

    # TEST 7: Upload PNG
    print("\n[TEST 7] Upload PNG evidence")
    fake_png = (io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRscreenshot_bytes"), "screenshot.png")
    r7 = client.post("/upload-evidence", data={"file": fake_png}, content_type="multipart/form-data")
    assert r7.status_code == 201
    d7 = r7.get_json()
    assert d7["success"] is True and len(d7["hash"]) == 64
    png_filename = d7["filename"]
    print(f"   [PASS] PNG uploaded: {png_filename} (SHA-256: {d7['hash'][:16]}...)")

    # TEST 8: Upload PDF
    print("\n[TEST 8] Upload PDF evidence")
    fake_pdf = (io.BytesIO(b"%PDF-1.4\n%testpdfevidence"), "report.pdf")
    r8 = client.post("/upload-evidence", data={"file": fake_pdf}, content_type="multipart/form-data")
    assert r8.status_code == 201
    d8 = r8.get_json()
    assert d8["success"] is True and len(d8["hash"]) == 64
    print(f"   [PASS] PDF uploaded: {d8['filename']} (SHA-256: {d8['hash'][:16]}...)")

    # TEST 9: Upload EXE (Forbidden)
    print("\n[TEST 9] Upload EXE executable (Must be rejected)")
    fake_exe = (io.BytesIO(b"MZ\x90\x00executable_code"), "malware.exe")
    r9 = client.post("/upload-evidence", data={"file": fake_exe}, content_type="multipart/form-data")
    assert r9.status_code == 400
    assert "Unsupported file type" in r9.get_json()["error"]
    print("   [PASS] Malicious/Unsupported file type correctly blocked (HTTP 400).")

    # TEST 10: Upload file larger than 10 MB
    print("\n[TEST 10] Upload file larger than 10 MB (Must be rejected)")
    oversized = (io.BytesIO(b"0" * (10 * 1024 * 1024 + 1024)), "huge.png")
    r10 = client.post("/upload-evidence", data={"file": oversized}, content_type="multipart/form-data")
    assert r10.status_code == 413
    print("   [PASS] File exceeding 10 MB rejected (HTTP 413).")

    # TEST 11: Check incident history & details
    print("\n[TEST 11] Check incident history and incident details")
    r11 = client.get("/incidents", headers={"Accept": "application/json"})
    assert r11.status_code == 200
    inc_list = r11.get_json()
    assert len(inc_list) >= 3
    first_id = inc_list[0]["id"]
    r11_detail = client.get(f"/incidents/{first_id}")
    assert r11_detail.status_code == 200
    assert b"Incident Assessment Report" in r11_detail.data
    print(f"   [PASS] Incident history returned {len(inc_list)} real recorded incidents.")
    print(f"   [PASS] Incident #{first_id} detailed assessment view verified.")

    # TEST 12: Logout
    print("\n[TEST 12] Logout")
    r12 = client.post("/logout")
    assert r12.status_code == 200
    r12_me = client.get("/me")
    assert r12_me.get_json()["authenticated"] is False
    print("   [PASS] User session successfully cleared.")

    # TEST 13: Access dashboard without login
    print("\n[TEST 13] Access dashboard without login (Must redirect or 401)")
    r13 = client.get("/dashboard")
    assert r13.status_code in [302, 401]
    print(f"   [PASS] Unauthorized dashboard access redirected (Status {r13.status_code}).")

    # TEST 14: Login as normal user and open admin (Must be 403)
    print("\n[TEST 14] Login as normal user and access admin console")
    client.post("/login", json={"username": "demouser", "password": "UserPass123!"})
    r14 = client.get("/admin")
    assert r14.status_code == 403
    r14_api = client.get("/admin/users", headers={"Accept": "application/json"})
    assert r14_api.status_code == 403
    print("   [PASS] Administrative console forbidden for regular user (HTTP 403).")

    # TEST 15: Login as admin
    print("\n[TEST 15] Login as admin and access admin console")
    client.post("/logout")
    r15_login = client.post("/login", json={"username": "systemadmin", "password": "AdminPass123!"})
    assert r15_login.status_code == 200
    r15_admin = client.get("/admin")
    assert r15_admin.status_code == 200
    r15_users = client.get("/admin/users", headers={"Accept": "application/json"})
    assert r15_users.status_code == 200
    users = r15_users.get_json()
    assert len(users) >= 2
    r15_logs = client.get("/admin/audit-logs", headers={"Accept": "application/json"})
    assert r15_logs.status_code == 200
    logs = r15_logs.get_json()
    assert len(logs) >= 5
    print(f"   [PASS] Admin console operational. Users: {len(users)}, Audit Logs: {len(logs)}.")

    # Clean up
    if os.path.exists(db_path):
        os.remove(db_path)

    print("\n" + "=" * 70)
    print("ALL 15 MANUAL TEST CASES PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    run_manual_test_plan()
