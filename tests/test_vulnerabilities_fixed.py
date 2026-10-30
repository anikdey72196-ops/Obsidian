import os
import pytest
from app import app as flask_app
from extensions import db
from models import User, Expense, LoginAttempt


@pytest.fixture
def auth_client():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}

    with flask_app.app_context():
        db.create_all()

    with flask_app.test_client() as client:
        yield client

    with flask_app.app_context():
        db.drop_all()


def test_vulnerability_4_admin_query_key_rejected(auth_client):
    """Vulnerability 4 Fix: Admin ?key= in URL must NOT authorize admin access."""
    os.environ['ADMIN_SECRET_KEY'] = 'super-secret-admin-pass'
    os.environ['ADMIN_USERNAME'] = 'admin_user'

    # Register and login as regular user
    auth_client.post("/register", data={"username": "regular_user", "password": "Password123!"})
    auth_client.post("/login", data={"username": "regular_user", "password": "Password123!"})

    # Passing key in query string URL should fail (redirect to home with access denied)
    response = auth_client.get("/admin?key=super-secret-admin-pass", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/home"

    # Passing key via secure HTTP header X-Admin-Key should succeed
    response_header = auth_client.get("/admin", headers={"X-Admin-Key": "super-secret-admin-pass"})
    assert response_header.status_code == 200


def test_vulnerability_5_ip_spoofing_cannot_bypass_rate_limit(auth_client):
    """Vulnerability 5 Fix: X-Forwarded-For fake-ip cannot bypass login rate limiting."""
    # Attempt 5 failed logins with different fake X-Forwarded-For headers
    for i in range(5):
        auth_client.post("/login", data={"username": "user", "password": "wrong"}, headers={"X-Forwarded-For": f"10.0.0.{i+1}"})

    # The 6th attempt should be rate limited (redirect back to login with rate limit flash)
    response = auth_client.post("/login", data={"username": "user", "password": "wrong"}, headers={"X-Forwarded-For": "10.0.0.99"}, follow_redirects=True)
    assert b"Too many failed login attempts" in response.data


def test_vulnerability_6_rate_limiter_backed_by_db(auth_client):
    """Vulnerability 6 Fix: Rate limiter persists attempts in the database for multi-worker support."""
    with flask_app.app_context():
        initial_count = LoginAttempt.query.count()

    # Fail a login
    auth_client.post("/login", data={"username": "user", "password": "badpassword"})

    with flask_app.app_context():
        # A LoginAttempt record must be created in the shared database table
        assert LoginAttempt.query.count() == initial_count + 1


def test_vulnerability_7_csp_no_unsafe_inline(auth_client):
    """Vulnerability 7 Fix: CSP script-src must NOT contain 'unsafe-inline' and must use a nonce."""
    response = auth_client.get("/")
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp

    # Extract script-src directive
    directives = dict(item.strip().split(" ", 1) for item in csp.strip(";").split(";") if item.strip())
    script_src = directives.get("script-src", "")

    # Must NOT have 'unsafe-inline' in script-src
    assert "'unsafe-inline'" not in script_src
    # Must have 'nonce-' in script-src
    assert "'nonce-" in script_src


def test_vulnerability_8_category_allow_list(auth_client):
    """Vulnerability 8 Fix: Web add-expense form must reject invalid categories."""
    auth_client.post("/register", data={"username": "cat_user", "password": "Password123!"})
    auth_client.post("/login", data={"username": "cat_user", "password": "Password123!"})

    # Submit an expense with an arbitrary/malicious category
    response = auth_client.post("/addexpense", data={
        "amount": "100.00",
        "category": "<script>alert('xss')</script>",
        "date": "2026-10-30",
        "description": "Exploit attempt"
    }, follow_redirects=True)

    assert b"Invalid category" in response.data

    with flask_app.app_context():
        exp = Expense.query.filter_by(description="Exploit attempt").first()
        assert exp is None

    # Submit with a valid category
    response_valid = auth_client.post("/addexpense", data={
        "amount": "50.00",
        "category": "Food & Dining",
        "date": "2026-10-30",
        "description": "Valid lunch"
    }, follow_redirects=True)

    assert b"Expense added successfully!" in response_valid.data


def test_vulnerability_9_ai_blueprint_csrf_protection(auth_client):
    """Vulnerability 9 Fix: AI Blueprint must NOT be CSRF exempt."""
    # Enable CSRF to verify that /ai/chat is protected by CSRF
    flask_app.config['WTF_CSRF_ENABLED'] = True

    try:
        # Register and login to create a valid session
        # Temporarily bypass CSRF for login setup
        flask_app.config['WTF_CSRF_ENABLED'] = False
        auth_client.post("/register", data={"username": "ai_user", "password": "Password123!"})
        auth_client.post("/login", data={"username": "ai_user", "password": "Password123!"})
        flask_app.config['WTF_CSRF_ENABLED'] = True

        # A POST to /ai/chat without CSRF token should be rejected with 400 Bad Request by CSRFProtect
        response = auth_client.post("/ai/chat", json={"message": "Hello AI"}, headers={})
        assert response.status_code == 400
        assert b"CSRF token" in response.data or b"Bad Request" in response.data
    finally:
        flask_app.config['WTF_CSRF_ENABLED'] = False
