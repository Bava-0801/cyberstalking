"""
TraceX Database Module
Handles SQLite schema initialization, connection management, and CRUD operations.
"""

import sqlite3
import os
import json
from datetime import datetime

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberstalking.db")


def get_connection(db_path=None):
    """
    Establish and return a connection to the SQLite database.
    Configures row_factory to sqlite3.Row and enables foreign key constraints.
    """
    path = db_path or os.environ.get("TRACEX_DB_PATH") or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def initialize_database(db_path=None):
    """
    Create necessary tables (users, incidents, audit_logs) if they do not exist.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    sender_username TEXT,
                    sender_name TEXT,
                    profile_url TEXT,
                    risk_level TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    ai_prediction TEXT NOT NULL,
                    ai_confidence REAL NOT NULL,
                    detected_patterns TEXT NOT NULL,
                    fake_id_status TEXT NOT NULL,
                    fake_id_score INTEGER NOT NULL,
                    fake_id_indicators TEXT NOT NULL,
                    evidence_filename TEXT,
                    evidence_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                );
            """)

            # Index for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_user_id ON incidents(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);")
    finally:
        conn.close()


def create_user(username, password_hash, role="user", db_path=None):
    """
    Insert a new user record.
    Returns the newly created user ID or raises sqlite3.IntegrityError on duplicate username.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);",
                (username.strip(), password_hash, role)
            )
            return cursor.lastrowid
    finally:
        conn.close()


def get_user_by_username(username, db_path=None):
    """
    Retrieve user by exact username.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?;",
            (username.strip(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id, db_path=None):
    """
    Retrieve user by ID.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?;",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_users(db_path=None):
    """
    Retrieve all registered users without password hashes (for admin view).
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC;"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def save_incident(user_id, message, platform, sender_username, sender_name, profile_url,
                  risk_level, risk_score, ai_prediction, ai_confidence, detected_patterns,
                  fake_id_status, fake_id_score, fake_id_indicators,
                  evidence_filename=None, evidence_hash=None, db_path=None):
    """
    Save an incident analysis record into the database.
    """
    # Normalize patterns and indicators into JSON string if passed as list
    if isinstance(detected_patterns, list):
        detected_patterns = json.dumps(detected_patterns)
    if isinstance(fake_id_indicators, list):
        fake_id_indicators = json.dumps(fake_id_indicators)

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO incidents (
                    user_id, message, platform, sender_username, sender_name, profile_url,
                    risk_level, risk_score, ai_prediction, ai_confidence, detected_patterns,
                    fake_id_status, fake_id_score, fake_id_indicators,
                    evidence_filename, evidence_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                user_id, message, platform, sender_username, sender_name, profile_url,
                risk_level, risk_score, ai_prediction, ai_confidence, detected_patterns,
                fake_id_status, fake_id_score, fake_id_indicators,
                evidence_filename, evidence_hash
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def get_incidents_by_user(user_id=None, is_admin=False, db_path=None):
    """
    Retrieve incident records. If user is admin and user_id is None, returns all incidents.
    Otherwise, returns incidents belonging to user_id.
    """
    conn = get_connection(db_path)
    try:
        if is_admin and user_id is None:
            cursor = conn.execute("""
                SELECT i.*, u.username as owner_username
                FROM incidents i
                LEFT JOIN users u ON i.user_id = u.id
                ORDER BY i.created_at DESC;
            """)
        else:
            cursor = conn.execute("""
                SELECT * FROM incidents
                WHERE user_id = ?
                ORDER BY created_at DESC;
            """, (user_id,))
        
        incidents = []
        for row in cursor.fetchall():
            item = dict(row)
            # Parse JSON fields if valid
            try:
                item["detected_patterns"] = json.loads(item["detected_patterns"])
            except Exception:
                pass
            try:
                item["fake_id_indicators"] = json.loads(item["fake_id_indicators"])
            except Exception:
                pass
            incidents.append(item)
        return incidents
    finally:
        conn.close()


def get_incident_by_id(incident_id, user_id=None, is_admin=False, db_path=None):
    """
    Retrieve a single incident by ID. Enforces ownership check unless is_admin is True.
    """
    conn = get_connection(db_path)
    try:
        if is_admin:
            cursor = conn.execute("""
                SELECT i.*, u.username as owner_username
                FROM incidents i
                LEFT JOIN users u ON i.user_id = u.id
                WHERE i.id = ?;
            """, (incident_id,))
        else:
            cursor = conn.execute("""
                SELECT * FROM incidents
                WHERE id = ? AND user_id = ?;
            """, (incident_id, user_id))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        item = dict(row)
        try:
            item["detected_patterns"] = json.loads(item["detected_patterns"])
        except Exception:
            pass
        try:
            item["fake_id_indicators"] = json.loads(item["fake_id_indicators"])
        except Exception:
            pass
        return item
    finally:
        conn.close()


def get_statistics(user_id=None, is_admin=False, db_path=None):
    """
    Calculate real statistics from the database.
    If is_admin is True and user_id is None, calculates global statistics.
    Otherwise calculates statistics scoped to user_id.
    """
    conn = get_connection(db_path)
    try:
        params = ()
        where_clause = ""
        if not is_admin or user_id is not None:
            where_clause = "WHERE user_id = ?"
            params = (user_id,)

        cursor = conn.execute(f"SELECT COUNT(*) FROM incidents {where_clause};", params)
        total_incidents = cursor.fetchone()[0]

        high_clause = f"WHERE risk_level = 'HIGH'" + (f" AND user_id = ?" if where_clause else "")
        cursor = conn.execute(f"SELECT COUNT(*) FROM incidents {high_clause};", params)
        high_risk = cursor.fetchone()[0]

        med_clause = f"WHERE risk_level = 'MEDIUM'" + (f" AND user_id = ?" if where_clause else "")
        cursor = conn.execute(f"SELECT COUNT(*) FROM incidents {med_clause};", params)
        medium_risk = cursor.fetchone()[0]

        low_clause = f"WHERE risk_level = 'LOW'" + (f" AND user_id = ?" if where_clause else "")
        cursor = conn.execute(f"SELECT COUNT(*) FROM incidents {low_clause};", params)
        low_risk = cursor.fetchone()[0]

        susp_clause = f"WHERE fake_id_status = 'SUSPICIOUS'" + (f" AND user_id = ?" if where_clause else "")
        cursor = conn.execute(f"SELECT COUNT(*) FROM incidents {susp_clause};", params)
        suspicious_flags = cursor.fetchone()[0]

        total_users = 0
        if is_admin:
            cursor = conn.execute("SELECT COUNT(*) FROM users;")
            total_users = cursor.fetchone()[0]

        return {
            "total_incidents": total_incidents,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "potential_identity_flags": suspicious_flags,
            "total_users": total_users
        }
    finally:
        conn.close()


def save_audit_log(user_id, username, action, details="", db_path=None):
    """
    Record an action into the audit_logs table.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO audit_logs (user_id, username, action, details)
                VALUES (?, ?, ?, ?);
            """, (user_id, username, action, details))
            return cursor.lastrowid
    finally:
        conn.close()


def get_audit_logs(limit=50, db_path=None):
    """
    Retrieve recent audit logs (for admin review).
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT id, user_id, username, action, details, created_at
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT ?;
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
