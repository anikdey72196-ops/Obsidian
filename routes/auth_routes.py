import time
import logging
from imports import (
    Blueprint, render_template, redirect, session, request, url_for, flash,
    generate_password_hash, check_password_hash, db, User, RegistrationForm, LoginForm
)
from services.rate_limiter import (
    is_rate_limited, record_failed_attempt, clear_attempts, DBLoginAttempts
)

logger = logging.getLogger(__name__)
auth_web_bp = Blueprint('auth_web', __name__)
login_attempts = DBLoginAttempts()


def get_client_ip():
    # Only trust request.remote_addr to prevent X-Forwarded-For spoofing attacks.
    return request.remote_addr or "127.0.0.1"


@auth_web_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for('auth_web.register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('auth_web.login'))
        except Exception:
            db.session.rollback()
            logger.exception("DB error creating user '%s'", form.username.data)
            flash("Could not create your account. Please try again later.", "danger")
            return redirect(url_for('auth_web.register'))

    return render_template("register.html", form=form)


@auth_web_bp.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip()

    if request.method == 'POST' and is_rate_limited(ip):
        flash("Too many failed login attempts. Please try again in 5 minutes.", "danger")
        return redirect(url_for('auth_web.login'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session.clear()
            session['user_id'] = user.id
            session['user'] = user.username
            session.permanent = True
            clear_attempts(ip)  # clear on successful login
            flash("Logged in successfully!", "success")
            return redirect(url_for('expense_web.home'))
        else:
            logger.warning("Failed login attempt from IP %s for username '%s'", ip, form.username.data)
            record_failed_attempt(ip)
            flash("Invalid username or password.", "danger")
            return redirect(url_for('auth_web.login'))

    return render_template("login.html", form=form)


@auth_web_bp.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for('index'))
