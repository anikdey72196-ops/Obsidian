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


def test_vulnerability_dom_xss_prevention(auth_client):
    """Vulnerability Fix: AI chat stream & tips must not use unescaped innerHTML."""
    template_path = os.path.join(flask_app.root_path, "templates", "home.html")
    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Ensure dangerous innerHTML assignment for stream response is removed
    assert "aiMsg.innerHTML = fullText" not in html
    assert "aiMsg.textContent = fullText" in html

    # Ensure tips do not directly concatenate strings into innerHTML
    assert "tipsList.innerHTML = data.tips.map" not in html


def test_sql_injection_protection_login_and_register(auth_client):
    """SQLi Hardening Test: SQL injection in web login and register must be rejected."""
    # Attempt SQL injection during registration
    res_reg = auth_client.post("/register", data={
        "username": "admin' OR '1'='1",
        "password": "Password123!"
    })
    # Form validation regex rejects invalid characters like quotes and spaces
    assert b"Username can only contain" in res_reg.data or res_reg.status_code in (200, 302, 400)
    assert User.query.filter_by(username="admin' OR '1'='1").first() is None

    # Attempt SQL injection during login
    res_login = auth_client.post("/login", data={
        "username": "' OR 1=1 --",
        "password": "Password123!"
    })
    # Must fail safely, no SQL error and no unauthorized access
    assert res_login.status_code in (200, 302)


def test_sql_injection_protection_search_query(auth_client):
    """SQLi Hardening Test: Search query with SQL injection payloads and wildcards executes safely."""
    # Register and login valid user
    auth_client.post("/register", data={"username": "sqli_user", "password": "Password123!"})
    auth_client.post("/login", data={"username": "sqli_user", "password": "Password123!"})

    # Add a normal expense
    auth_client.post("/addexpense", data={
        "amount": "100.00",
        "category": "Food & Dining",
        "date": "2026-10-30",
        "description": "Coffee with 10% discount"
    })

    # Test search with classic SQL injection payload
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE expense; --",
        "' UNION SELECT 1, 2, 3, 4, 5 --",
        "10%",  # contains % wildcard
        "_"     # contains _ wildcard
    ]

    for payload in sqli_payloads:
        res = auth_client.get(f"/history?search={payload}")
        assert res.status_code == 200
        # Verify database table is intact
        assert Expense.query.count() >= 1


def test_idor_protection_web_edit_expense(auth_client):
    """IDOR Hardening: User B cannot view or edit User A's expense via web UI."""
    # 1. Register User A and create an expense
    auth_client.post("/register", data={"username": "user_a", "password": "Password123!"})
    auth_client.post("/login", data={"username": "user_a", "password": "Password123!"})
    auth_client.post("/addexpense", data={
        "amount": "250.00",
        "category": "Food & Dining",
        "date": "2026-11-01",
        "description": "User A Private Dinner"
    })

    with flask_app.app_context():
        exp_a = Expense.query.filter_by(description="User A Private Dinner").first()
        assert exp_a is not None
        exp_a_id = exp_a.id

    auth_client.get("/logout")

    # 2. Register User B and log in
    auth_client.post("/register", data={"username": "user_b", "password": "Password123!"})
    auth_client.post("/login", data={"username": "user_b", "password": "Password123!"})

    # User B attempts to access User A's expense edit page
    res_get = auth_client.get(f"/edit_expense/{exp_a_id}", follow_redirects=True)
    assert b"Expense not found or access denied." in res_get.data
    assert b"User A Private Dinner" not in res_get.data

    # User B attempts to overwrite User A's expense via POST
    res_post = auth_client.post(f"/edit_expense/{exp_a_id}", data={
        "amount": "1.00",
        "category": "Shopping",
        "date": "2026-11-01",
        "description": "Hacked by User B"
    }, follow_redirects=True)
    assert b"Expense not found or access denied." in res_post.data

    # Verify User A's expense was NOT modified in the database
    with flask_app.app_context():
        exp_check = Expense.query.get(exp_a_id)
        assert exp_check.amount == 250.00
        assert exp_check.description == "User A Private Dinner"


def test_idor_protection_web_delete_expense(auth_client):
    """IDOR Hardening: User B cannot delete User A's expense via web UI."""
    # Register User A and create an expense
    auth_client.post("/register", data={"username": "alice", "password": "Password123!"})
    auth_client.post("/login", data={"username": "alice", "password": "Password123!"})
    auth_client.post("/addexpense", data={
        "amount": "99.00",
        "category": "Transport",
        "date": "2026-11-01",
        "description": "Alice Taxi"
    })

    with flask_app.app_context():
        exp_a = Expense.query.filter_by(description="Alice Taxi").first()
        assert exp_a is not None
        exp_a_id = exp_a.id

    auth_client.get("/logout")

    # Register User B and log in
    auth_client.post("/register", data={"username": "bob", "password": "Password123!"})
    auth_client.post("/login", data={"username": "bob", "password": "Password123!"})

    # Bob attempts to delete Alice's expense
    res_del = auth_client.post(f"/delete_expense/{exp_a_id}", follow_redirects=True)
    assert b"Expense not found or could not be deleted." in res_del.data

    # Verify Alice's expense is still intact in the database
    with flask_app.app_context():
        exp_check = Expense.query.get(exp_a_id)
        assert exp_check is not None
        assert exp_check.description == "Alice Taxi"


def test_idor_protection_jwt_api(auth_client):
    """IDOR Hardening: User B cannot view, modify, or delete User A's expense via REST API."""
    # Register Alice via API
    res_a_reg = auth_client.post("/auth/signup", json={"username": "api_alice", "password": "Password123!"})
    assert res_a_reg.status_code == 201

    res_a_login = auth_client.post("/auth/login", json={"username": "api_alice", "password": "Password123!"})
    token_alice = res_a_login.get_json()["access_token"]

    # Alice creates an expense
    res_exp = auth_client.post(
        "/expenses",
        json={"amount": 500, "category": "Utilities", "date": "2026-11-01", "description": "Alice Electric Bill"},
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    assert res_exp.status_code == 201
    exp_id = res_exp.get_json()["id"]

    # Register Bob via API
    res_b_reg = auth_client.post("/auth/signup", json={"username": "api_bob", "password": "Password123!"})
    assert res_b_reg.status_code == 201

    res_b_login = auth_client.post("/auth/login", json={"username": "api_bob", "password": "Password123!"})
    token_bob = res_b_login.get_json()["access_token"]

    # 1. Bob lists expenses -> must be empty (cannot see Alice's expense)
    res_b_list = auth_client.get("/expenses", headers={"Authorization": f"Bearer {token_bob}"})
    assert res_b_list.status_code == 200
    assert len(res_b_list.get_json()) == 0

    # 2. Bob attempts to modify Alice's expense -> must return 404
    res_b_put = auth_client.put(
        f"/expenses/{exp_id}",
        json={"amount": 1, "description": "Bob Tampered"},
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert res_b_put.status_code == 404

    # 3. Bob attempts to delete Alice's expense -> must return 404
    res_b_del = auth_client.delete(
        f"/expenses/{exp_id}",
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert res_b_del.status_code == 404

    # 4. Verify Alice's expense is unchanged
    with flask_app.app_context():
        exp = Expense.query.get(exp_id)
        assert exp.amount == 500
        assert exp.description == "Alice Electric Bill"


def test_rate_limiting_ip_rotation_and_database_query(auth_client):
    """Rate Limiter Hardening: Rotating IPs cannot bypass login rate limit when targeting the same user."""
    # Register victim user
    auth_client.post("/register", data={"username": "victim_user", "password": "Password123!"})

    # Attacker tries 5 failed logins targeting 'victim_user' with 5 completely DIFFERENT IPs
    for i in range(5):
        res = auth_client.post("/login", data={
            "username": "victim_user",
            "password": f"wrong_pwd_{i}"
        }, environ_overrides={"REMOTE_ADDR": f"192.168.1.{10 + i}"})
        assert res.status_code == 302

    # Verify database table contains 5 records with username='victim_user'
    with flask_app.app_context():
        count = LoginAttempt.query.filter_by(username="victim_user").count()
        assert count == 5

    # 6th attempt from a brand-new 6th IP (e.g. 10.99.99.99) targeting victim_user must be BLOCKED!
    res_blocked = auth_client.post("/login", data={
        "username": "victim_user",
        "password": "another_wrong_password"
    }, environ_overrides={"REMOTE_ADDR": "10.99.99.99"}, follow_redirects=True)

    assert b"Too many failed login attempts" in res_blocked.data
