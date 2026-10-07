# TraceX — AI-Powered Cyberstalking Detection & Digital Safety Platform

> **Detect. Analyze. Protect.**  
> A cybersecurity platform built to analyze potentially suspicious online communications, detect coercive patterns, and assess digital safety risks.

---

## 1. Project Overview

**TraceX** is an AI-assisted cybersecurity web platform designed to help users evaluate suspicious incoming messages across social networks, messaging apps, and email. TraceX combines natural language processing (NLP), rule-based behavioral heuristics, sender identity indicator heuristics, and cryptographic evidence hashing to provide a clear, actionable threat assessment.

### Important Safety & Accuracy Rule
TraceX evaluates **risk indicators** and **behavioral patterns**. It does **NOT**:
- Claim to determine the real identity of an anonymous person
- "Reveal anonymous users" or "identify criminals"
- Prove that an account is legally fake or establish legal guilt

All assessments are categorized under:
- *Potential identity indicators*
- *Potentially deceptive or incomplete profile indicators*
- *Unverified sender information*
- *Behavioural risk assessment*
- *AI-assisted analysis*

---

## 2. Architecture & Application Flow

```
                     USER
                      │
                      ▼
                 HTML / CSS / JS
                      │
                      ▼
                FLASK BACKEND
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
    SQLite        ML MODEL        Evidence
 (cyberstalking.db)   │         (uploads/)
       │              ▼              │
       │        Risk Analysis     SHA-256
       │        & Behavioural        │
       │           Engine            │
       └──────────────┼──────────────┘
                      │
                      ▼
                JSON RESPONSE
                      │
                      ▼
               SECURITY DASHBOARD
```

### Complete End-to-End Workflow:
1. **User Registration / Login**: Secure session initiated; passwords hashed with PBKDF2/scrypt.
2. **Input Communication**: User specifies platform, sender handle, display name, profile URL, message body, and attaches optional screenshot/PDF.
3. **Evidence Ingestion**: Uploaded file is validated, saved with a unique UUID, and immediate SHA-256 cryptographic digest is calculated.
4. **AI/ML Model Inference**: Scikit-learn TF-IDF + Logistic Regression predicts probability distributions across `safe`, `suspicious`, and `cyberstalking`.
5. **Behavioural Pattern Engine**: Rule-based screening for location monitoring, surveillance/tracking, repeated contact, threats/intimidation, personal data targeting, and harassment pressure.
6. **Potential Identity Indicators**: Evaluates deceptive handle patterns, unverified platforms, and missing profile references.
7. **Consolidated Risk Scoring**: Calibrated 0–100 score classified into **LOW** (0–39), **MEDIUM** (40–69), and **HIGH** (70–100).
8. **Audit Trail & Storage**: Incident record saved to SQLite and action logged into the audit trail.
9. **Dashboard Visualization**: Incident details and updated risk statistics appear in real time.

---

## 3. Technology Stack

- **Frontend**: HTML5, Vanilla CSS3 (custom dark cybersecurity design system), Vanilla JavaScript (modern `fetch()` API, XSS-safe DOM manipulation, zero frontend framework bloat).
- **Backend**: Python 3.14+, Flask 3.1+, Werkzeug.
- **Database**: SQLite 3 with foreign key enforcement (`PRAGMA foreign_keys = ON`) and parameterized queries.
- **AI/ML**: Scikit-learn, Pandas, Joblib (TF-IDF Vectorizer with unigrams/bigrams + Logistic Regression classifier with balanced class weights).
- **Security & Integrity**: Werkzeug password hashing, role-based access control (RBAC), secure file uploads, SHA-256 evidence integrity hashing, and audit logging.
- **Testing**: Pytest.
- **Deployment**: Gunicorn WSGI server ready.

---

## 4. Project Directory Structure

```
TraceX/
│
├── app.py                     # Main Flask application and REST API routes
├── database.py                # SQLite connection, schema, and parameterized CRUD
├── train_model.py             # Model training pipeline (TF-IDF + Logistic Regression)
├── analyzer.py                # ML inference, behavioural rules, and risk scoring
├── create_admin.py            # CLI utility to create or update administrator accounts
├── dataset.csv                # Prototype dataset (safe, suspicious, cyberstalking)
├── requirements.txt           # Python package dependencies
├── .gitignore                 # Version control exclusions
├── README.md                  # Comprehensive platform documentation
│
├── model/
│   └── cyberstalking_model.pkl # Trained serialized model artifact
│
├── templates/
│   ├── index.html             # Landing page with feature showcase and workflow
│   ├── login.html             # Secure user login interface
│   ├── register.html          # New account registration
│   ├── dashboard.html         # Cybersecurity dashboard & analyzer
│   ├── incident.html          # Individual incident assessment report
│   ├── admin.html             # Administrative operations console
│   └── 404.html               # Custom error page
│
├── static/
│   ├── css/
│   │   └── style.css          # Design system & dark cybersecurity theme
│   └── js/
│       ├── main.js            # Shared utilities, toast alerts, session actions
│       ├── auth.js            # Client authentication & form handling
│       ├── dashboard.js       # Dashboard stats, analyzer, and incident history
│       └── admin.js           # Admin users and audit log viewers
│
├── uploads/                   # Stored evidence files (with .gitkeep)
│
└── tests/
    ├── test_database.py       # Database schema and CRUD tests
    ├── test_analyze.py        # ML, behavioural rules, and scoring tests
    └── test_auth.py           # Authentication, RBAC, and file security tests
```

---

## 5. Installation & Setup Guide

### Step 1: Clone or Navigate to Directory
```bash
cd TraceX
```

### Step 2: Create and Activate Virtual Environment
On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Packages
```bash
pip install -r requirements.txt
```

### Step 4: Train the ML Model
```bash
python train_model.py
```
This trains the TF-IDF vectorizer and Logistic Regression classifier on `dataset.csv` and generates `model/cyberstalking_model.pkl`.

### Step 5: Initialize Admin Account (Optional)
```bash
python create_admin.py --username admin --password "StrongAdminPass123!"
```
Or run interactively:
```bash
python create_admin.py
```

### Step 6: Run Flask Development Server
```bash
python app.py
```
Access the application at `http://127.0.0.1:5000`.

---

## 6. Running with Gunicorn (Production)

TraceX is WSGI compliant. To serve via Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## 7. Automated Test Suite

Execute the full automated test suite using `pytest`:
```bash
python -m pytest tests/ -v
```

All 19 test cases verify:
- Database table creation, user registration, and duplicate constraint enforcement
- Password hashing verification with Werkzeug
- Behavioural threat detection across all 6 categories
- Potential identity indicators evaluation
- Risk scoring bounds (0–100) and classification (LOW, MEDIUM, HIGH)
- Demonstration cyberstalking message evaluation
- Role-based access control (403 for unauthorized non-admins)
- Evidence upload safety (PNG/JPG/PDF allowed, `.exe` blocked, max size enforced)
- SHA-256 evidence digest verification

---

## 8. API Specification

### Public Routes
- `GET /` — Landing page with product overview and security matrix
- `GET /login` — User sign-in interface
- `GET /register-page` — User registration interface
- `POST /register` — Register a new account (`{ "username", "password", "confirm_password" }`)
- `POST /login` — Authenticate user and initiate session (`{ "username", "password" }`)
- `POST /logout` — Terminate session and record audit log

### Authenticated Routes (Requires Login)
- `GET /dashboard` — Main cybersecurity dashboard
- `GET /me` — Returns current authenticated user object
- `GET /stats` — Returns real-time database counts (Total, High, Medium, Low, Flags)
- `POST /analyze` — Submits message and metadata for full AI & behavioural evaluation
- `POST /upload-evidence` — Uploads screenshot/PDF (max 10 MB) and computes SHA-256 hash
- `GET /evidence/<filename>` — Accesses evidence file (restricted to owner or admin)
- `GET /incidents` — Lists recorded incidents (scoped to user, or global if admin)
- `GET /incidents/<id>` — Detailed incident report and verification view

### Administrative Routes (Requires Admin Role)
- `GET /admin` — Administrative operations console
- `GET /admin/users` — Directory of registered accounts (omits password hashes)
- `GET /admin/audit-logs` — Immutable system audit log trail

---

## 9. Security Features

1. **Cryptographic Password Hashing**: Passwords hashed using Werkzeug (`scrypt`/`pbkdf2:sha256`) with unique salts.
2. **Role-Based Access Control (RBAC)**: Enforced via `@login_required` and `@admin_required` decorators.
3. **Session Hardening**: Signed server sessions with `HttpOnly` and `SameSite=Lax` cookie flags.
4. **SQL Injection Defense**: Strict parameterized queries (`?`) across all SQLite statements; no user string concatenation.
5. **Path Traversal Protection**: Uploaded files sanitized via `secure_filename()` with collision-resistant UUID prefixes and isolated from templates.
6. **File Type & Size Restrictions**: Whitelist restricted to `.png`, `.jpg`, `.jpeg`, and `.pdf`; maximum size capped at 10 MB.
7. **SHA-256 Evidence Fingerprint**: Cryptographic hashing of evidence upon receipt creates a verifiable file integrity reference.
8. **XSS Mitigation**: Strict DOM manipulation with `textContent` preventing malicious script injection from message text or usernames.
9. **Tamper-Evident Audit Logging**: Timestamped logging for `REGISTER`, `LOGIN`, `FAILED_LOGIN`, `LOGOUT`, `MESSAGE_ANALYSIS`, `EVIDENCE_UPLOAD`, and `ADMIN_ACCESS`.

---

## 10. AI Model Limitations Notice

> **Model Notice**: This is a proof-of-concept model trained on a small prototype dataset (90 samples). Larger and more diverse datasets are required before production deployment.
> 
> The model does not claim 100% accuracy, law-enforcement evidentiary finality, or automated legal culpability. It is designed as an awareness and triaging assistant for digital safety.

---

## 11. Off-Chain Blockchain Architecture

TraceX utilizes a **blockchain-ready evidence integrity architecture**:
1. Uploaded evidence stays securely in protected local/cloud off-chain storage.
2. A SHA-256 cryptographic digest is computed immediately upon arrival.
3. The cryptographic digest is stored in the database record.
4. This hash can be anchored into a distributed blockchain transaction for tamper-evident public verification without revealing sensitive private messages or personal data on-chain.

---

## 12. Future Enhancements

- Multi-Factor Authentication (MFA / TOTP)
- Optical Character Recognition (OCR) for automated text extraction from screenshots
- Digital image tampering and EXIF metadata analysis
- Multilingual transformer-based NLP (e.g. RoBERTa / BERT)
- Public ledger anchoring (Ethereum / Polygon / Hyperledger)
- End-to-end encrypted evidence vaults
- Direct export of structured incident reports in PDF format for legal review
