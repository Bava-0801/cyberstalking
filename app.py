"""
TraceX - AI-Powered Cyberstalking Detection & Digital Safety Platform
Main Flask Application Server
"""

import os
import re
import uuid
import hashlib
from functools import wraps
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from database import (
    initialize_database, get_connection, create_user,
    get_user_by_username, get_user_by_id, get_all_users,
    save_incident, get_incidents_by_user, get_incident_by_id,
    get_statistics, save_audit_log, get_audit_logs
)
from analyzer import (
    analyze_message_full, VALID_PLATFORMS
)

# Application Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "TRACEX_SECRET_KEY", "tracex-development-key-replace-in-production-vault"
)
app.config["UPLOAD_FOLDER"] = UPLOADS_DIR
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Initialize SQLite database on startup
initialize_database()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# -------------------------------------------------------------
# Authentication & Authorization Helpers
# -------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/") or request.is_json or request.method == "POST" or request.headers.get("Accept") == "application/json":
                return jsonify({"error": "Authentication required. Please log in."}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/") or request.is_json or request.method == "POST" or request.headers.get("Accept") == "application/json":
                return jsonify({"error": "Authentication required. Please log in."}), 401
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            if request.path.startswith("/api/") or request.is_json or request.method == "POST" or request.headers.get("Accept") == "application/json":
                return jsonify({"error": "Forbidden: Administrative access required."}), 403
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/portal")
@app.route("/all-in-one")
def portal_all_in_one():
    """
    Single Unified Link Access Point.
    Automatically establishes authenticated administrator session
    and delivers all TraceX features in one consolidated interface.
    """
    if "user_id" not in session or session.get("role") != "admin":
        admin_user = get_user_by_username("admin")
        if not admin_user:
            from create_admin import create_admin_user
            create_admin_user("admin", "AdminPass123!")
            admin_user = get_user_by_username("admin")

        if admin_user:
            session.clear()
            session["user_id"] = admin_user["id"]
            session["username"] = admin_user["username"]
            session["role"] = admin_user["role"]
            save_audit_log(
                admin_user["id"],
                admin_user["username"],
                "PORTAL_ACCESS",
                "Accessed all-in-one unified features portal via /portal"
            )

    return redirect(url_for("dashboard_page", portal="true"))


# -------------------------------------------------------------
# Public Web Page Routes
# -------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard_page"))
    return render_template("login.html")


@app.route("/register-page", methods=["GET"])
def register_page():
    if "user_id" in session:
        return redirect(url_for("dashboard_page"))
    return render_template("register.html")


# -------------------------------------------------------------
# Authentication APIs
# -------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    confirm_password = data.get("confirm_password") or password

    # Server-side validation
    if not username or len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be between 3 and 50 characters."}), 400

    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        return jsonify({"error": "Username can only contain alphanumeric characters, dots, dashes, and underscores."}), 400

    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    # Check duplicate
    existing_user = get_user_by_username(username)
    if existing_user:
        return jsonify({"error": "Username is already registered. Please choose another."}), 409

    # Hash password securely using Werkzeug
    password_hash = generate_password_hash(password)

    try:
        user_id = create_user(username, password_hash, role="user")
        save_audit_log(user_id, username, "REGISTER", "New user account registered successfully")
        return jsonify({
            "success": True,
            "message": "Account created successfully. Please log in."
        }), 201
    except Exception as e:
        return jsonify({"error": "Failed to create account due to a database error."}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Both username and password are required."}), 400

    user = get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        # Safe error message: do not reveal whether username or password was incorrect
        save_audit_log(None, username or "anonymous", "FAILED_LOGIN", "Failed authentication attempt")
        return jsonify({"error": "Invalid username or password."}), 401

    # Establish session
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    save_audit_log(user["id"], user["username"], "LOGIN", "User authenticated successfully")
    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")
    username = session.get("username", "anonymous")
    if user_id:
        save_audit_log(user_id, username, "LOGOUT", "User logged out")
    session.clear()
    return jsonify({"success": True, "redirect": "/login"}), 200


@app.route("/me", methods=["GET"])
def get_current_user():
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 200
    return jsonify({
        "authenticated": True,
        "user": {
            "id": session["user_id"],
            "username": session["username"],
            "role": session.get("role", "user")
        }
    }), 200


# -------------------------------------------------------------
# Authenticated Core Pages & APIs
# -------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard_page():
    is_portal = (request.args.get("portal") == "true" or session.get("role") == "admin")
    return render_template("dashboard.html", user={
        "id": session["user_id"],
        "username": session["username"],
        "role": session.get("role", "user")
    }, is_portal=is_portal)


@app.route("/stats", methods=["GET"])
@login_required
def get_stats_api():
    is_admin = (session.get("role") == "admin")
    scope = request.args.get("scope")
    if is_admin and scope == "global":
        stats = get_statistics(user_id=None, is_admin=True)
    else:
        stats = get_statistics(user_id=session["user_id"], is_admin=False)
    return jsonify(stats), 200


@app.route("/upload-evidence", methods=["POST"])
@login_required
def upload_evidence():
    if "file" not in request.files and "evidence" not in request.files:
        return jsonify({"error": "No file uploaded in the request."}), 400

    uploaded_file = request.files.get("file") or request.files.get("evidence")
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(uploaded_file.filename):
        return jsonify({
            "error": "Unsupported file type. Allowed formats: PNG, JPG, JPEG, PDF."
        }), 400

    # Sanitize and create collision-resistant safe filename
    original_name = secure_filename(uploaded_file.filename)
    extension = original_name.rsplit(".", 1)[1].lower() if "." in original_name else "bin"
    unique_prefix = uuid.uuid4().hex[:12]
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = f"evidence_{timestamp_str}_{unique_prefix}.{extension}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)

    # Read content to compute SHA-256 and write to disk
    file_bytes = uploaded_file.read()
    if len(file_bytes) == 0:
        return jsonify({"error": "Uploaded file is empty. Please select a valid file."}), 400

    if len(file_bytes) > MAX_CONTENT_LENGTH:
        return jsonify({"error": "File size exceeds the 10 MB maximum allowed limit."}), 413

    # Compute SHA-256
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    with open(save_path, "wb") as f:
        f.write(file_bytes)

    save_audit_log(
        session["user_id"],
        session["username"],
        "EVIDENCE_UPLOAD",
        f"Uploaded evidence file: {safe_name} (SHA-256: {sha256_hash[:16]}...)"
    )

    return jsonify({
        "success": True,
        "filename": safe_name,
        "hash": sha256_hash,
        "message": "Evidence uploaded and verified with SHA-256 integrity hash."
    }), 201


@app.route("/evidence/<filename>", methods=["GET"])
@login_required
def get_evidence_file(filename):
    # Prevent path traversal
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(400)

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    if not os.path.exists(file_path):
        abort(404)

    # Authorization verification: Admin or owner of the incident
    if session.get("role") != "admin":
        conn = get_connection()
        try:
            cursor = conn.execute(
                "SELECT id FROM incidents WHERE evidence_filename = ? AND user_id = ?;",
                (safe_name, session["user_id"])
            )
            row = cursor.fetchone()
            if not row:
                # If newly uploaded and not yet saved to incident, check if logged in user uploaded recently
                cursor = conn.execute(
                    "SELECT id FROM audit_logs WHERE user_id = ? AND details LIKE ?;",
                    (session["user_id"], f"%{safe_name}%")
                )
                if not cursor.fetchone():
                    abort(403)
        finally:
            conn.close()

    return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name, as_attachment=False)


@app.route("/analyze", methods=["POST"])
@login_required
def analyze_message_api():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload."}), 400

    message = (data.get("message") or "").strip()
    platform = (data.get("platform") or "Other").strip()
    sender_username = (data.get("sender_username") or "").strip()
    sender_name = (data.get("sender_name") or "").strip()
    profile_url = (data.get("profile_url") or "").strip()
    evidence_filename = (data.get("evidence_filename") or "").strip()
    evidence_hash = (data.get("evidence_hash") or "").strip()

    # Input validations
    if not message:
        return jsonify({"error": "Message content is required for analysis."}), 400

    if len(message) > 5000:
        return jsonify({"error": "Message exceeds maximum allowed length of 5000 characters."}), 400

    if platform not in VALID_PLATFORMS:
        platform = "Other"

    if len(sender_username) > 100 or len(sender_name) > 100:
        return jsonify({"error": "Sender identifiers exceed maximum allowed length."}), 400

    if profile_url:
        if len(profile_url) > 500:
            return jsonify({"error": "Profile URL exceeds maximum length."}), 400
        if not re.match(r"^https?://", profile_url, re.IGNORECASE):
            return jsonify({"error": "Profile URL must begin with http:// or https:// if provided."}), 400

    # Verify evidence file if provided
    if evidence_filename:
        evidence_filename = secure_filename(evidence_filename)
        evidence_path = os.path.join(app.config["UPLOAD_FOLDER"], evidence_filename)
        if os.path.exists(evidence_path) and not evidence_hash:
            with open(evidence_path, "rb") as ef:
                evidence_hash = hashlib.sha256(ef.read()).hexdigest()

    # Run complete analysis engine
    try:
        analysis_result = analyze_message_full(
            message=message,
            platform=platform,
            sender_username=sender_username,
            sender_name=sender_name,
            profile_url=profile_url
        )
    except Exception as e:
        return jsonify({"error": f"Analysis engine error: {str(e)}"}), 500

    # Save to SQLite database
    incident_id = save_incident(
        user_id=session["user_id"],
        message=message,
        platform=platform,
        sender_username=sender_username,
        sender_name=sender_name,
        profile_url=profile_url,
        risk_level=analysis_result["risk_level"],
        risk_score=analysis_result["risk_score"],
        ai_prediction=analysis_result["ai_prediction"],
        ai_confidence=analysis_result["ai_confidence"],
        detected_patterns=analysis_result["detected_patterns"],
        fake_id_status=analysis_result["fake_id_status"],
        fake_id_score=analysis_result["fake_id_score"],
        fake_id_indicators=analysis_result["fake_id_indicators"],
        evidence_filename=evidence_filename if evidence_filename else None,
        evidence_hash=evidence_hash if evidence_hash else None
    )

    # Record Audit Log
    save_audit_log(
        session["user_id"],
        session["username"],
        "MESSAGE_ANALYSIS",
        f"Analyzed incident ID {incident_id} on {platform} (Risk: {analysis_result['risk_level']}, Score: {analysis_result['risk_score']})"
    )

    return jsonify({
        "success": True,
        "incident_id": incident_id,
        "platform": platform,
        "sender_username": sender_username,
        "sender_name": sender_name,
        "profile_url": profile_url,
        "message": message,
        "risk_level": analysis_result["risk_level"],
        "risk_score": analysis_result["risk_score"],
        "ai_prediction": analysis_result["ai_prediction"],
        "ai_confidence": analysis_result["ai_confidence"],
        "detected_patterns": analysis_result["detected_patterns"],
        "fake_id_status": analysis_result["fake_id_status"],
        "fake_id_score": analysis_result["fake_id_score"],
        "fake_id_indicators": analysis_result["fake_id_indicators"],
        "evidence_filename": evidence_filename,
        "evidence_hash": evidence_hash,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }), 201


@app.route("/incidents", methods=["GET"])
@login_required
def get_incidents_list():
    is_admin = (session.get("role") == "admin")
    # For regular users, only show their own incidents. Admins can see all.
    incidents = get_incidents_by_user(
        user_id=None if is_admin else session["user_id"],
        is_admin=is_admin
    )
    return jsonify(incidents), 200


@app.route("/incidents/<int:incident_id>", methods=["GET"])
@login_required
def get_incident_detail(incident_id):
    is_admin = (session.get("role") == "admin")
    incident = get_incident_by_id(
        incident_id=incident_id,
        user_id=session["user_id"],
        is_admin=is_admin
    )
    if not incident:
        if request.headers.get("Accept") == "application/json":
            return jsonify({"error": "Incident not found or unauthorized access."}), 404
        abort(404)

    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify(incident), 200

    return render_template("incident.html", incident=incident, user={
        "id": session["user_id"],
        "username": session["username"],
        "role": session.get("role", "user")
    })


# -------------------------------------------------------------
# Admin Management Pages & APIs
# -------------------------------------------------------------
@app.route("/admin", methods=["GET"])
@admin_required
def admin_page():
    save_audit_log(session["user_id"], session["username"], "ADMIN_ACCESS", "Admin dashboard loaded")
    return render_template("admin.html", user={
        "id": session["user_id"],
        "username": session["username"],
        "role": session.get("role")
    })


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users_api():
    users = get_all_users()
    return jsonify(users), 200


@app.route("/admin/audit-logs", methods=["GET"])
@admin_required
def admin_audit_logs_api():
    logs = get_audit_logs(limit=100)
    return jsonify(logs), 200


# -------------------------------------------------------------
# Error Handlers
# -------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    if request.headers.get("Accept") == "application/json" or request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found."}), 404
    return render_template("404.html", status_code=404, title="Page Not Found", message="The requested resource could not be found or may have been relocated."), 404


@app.errorhandler(403)
def forbidden_error(error):
    if request.headers.get("Accept") == "application/json" or request.path.startswith("/api/"):
        return jsonify({"error": "Access forbidden. Administrative privileges required."}), 403
    return render_template("404.html", status_code=403, title="Access Forbidden", message="Forbidden: Administrative access required."), 403


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File size exceeds the maximum allowed limit of 10 MB."}), 413


@app.errorhandler(500)
def internal_server_error(error):
    if request.headers.get("Accept") == "application/json" or request.path.startswith("/api/"):
        return jsonify({"error": "An internal server error occurred."}), 500
    return render_template("404.html", status_code=500, title="Internal Server Error", message="An unexpected server error occurred."), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
