"""
TraceX Admin User Creation Utility
Creates an administrative user with secure password hashing.
Can run interactively or via CLI arguments for automated setups.
"""

import argparse
import getpass
import sys
from werkzeug.security import generate_password_hash
from database import initialize_database, get_connection, get_user_by_username, save_audit_log


def create_admin_user(username, password):
    if not username or len(username.strip()) < 3:
        print("[!] Error: Username must be at least 3 characters long.")
        return False
    if not password or len(password) < 8:
        print("[!] Error: Password must be at least 8 characters long.")
        return False

    username = username.strip()
    initialize_database()

    existing = get_user_by_username(username)
    admin_id = None
    is_update = False
    conn = get_connection()
    try:
        with conn:
            password_hash = generate_password_hash(password)
            if existing:
                conn.execute(
                    "UPDATE users SET password_hash = ?, role = 'admin' WHERE username = ?;",
                    (password_hash, username)
                )
                admin_id = existing["id"]
                is_update = True
            else:
                cursor = conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin');",
                    (username, password_hash)
                )
                admin_id = cursor.lastrowid
    finally:
        conn.close()

    if is_update:
        print(f"[*] User '{username}' already exists. Successfully upgraded/updated to admin role.")
        save_audit_log(admin_id, username, "ADMIN_UPDATED", "Admin password/role updated via create_admin.py")
    else:
        print(f"[+] Admin user '{username}' successfully created with ID {admin_id}.")
        save_audit_log(admin_id, username, "ADMIN_CREATED", "Admin account created via create_admin.py")
    return True


def main():
    parser = argparse.ArgumentParser(description="Create or update an admin user for TraceX.")
    parser.add_argument("--username", "-u", help="Admin username")
    parser.add_argument("--password", "-p", help="Admin password")
    args = parser.parse_args()

    username = args.username
    password = args.password

    if not username:
        try:
            username = input("Enter admin username: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not password:
        try:
            password = getpass.getpass("Enter admin password (min 8 chars): ")
            confirm = getpass.getpass("Confirm admin password: ")
            if password != confirm:
                print("[!] Error: Passwords do not match.")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    success = create_admin_user(username, password)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
