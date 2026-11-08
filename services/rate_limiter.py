import time
import datetime
import logging
from flask import has_app_context
from sqlalchemy import or_
from extensions import db
from models import LoginAttempt

logger = logging.getLogger(__name__)

_RATE_LIMIT_MAX = 5
_RATE_LIMIT_WINDOW = 300  # 5 minutes window

# In-memory fallbacks: separate tracking for IP and username
_in_memory_ip_attempts = {}
_in_memory_user_attempts = {}


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def get_failed_attempts_count(ip: str, username: str = None, window_seconds: int = _RATE_LIMIT_WINDOW) -> int:
    """Get the highest recent failed attempt count between this IP and this username.
    Executes database queries filtered by timestamp cutoff.
    """
    now_ts = time.time()
    ip_count = 0
    user_count = 0

    if not has_app_context():
        ip_attempts = [t for t in _in_memory_ip_attempts.get(ip, []) if now_ts - t < window_seconds]
        ip_count = len(ip_attempts)
        if username:
            user_attempts = [t for t in _in_memory_user_attempts.get(username, []) if now_ts - t < window_seconds]
            user_count = len(user_attempts)
        return max(ip_count, user_count)

    try:
        cutoff = _utc_now() - datetime.timedelta(seconds=window_seconds)
        # Database query for IP
        ip_count = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.attempted_at >= cutoff
        ).count()

        # Database query for Username (anti-IP-rotation protection)
        if username and hasattr(LoginAttempt, 'username'):
            user_count = LoginAttempt.query.filter(
                LoginAttempt.username == username,
                LoginAttempt.attempted_at >= cutoff
            ).count()

        return max(ip_count, user_count)
    except Exception as e:
        logger.debug("Database count check failed in rate limiter (%s), using in-memory fallback", e)
        ip_attempts = [t for t in _in_memory_ip_attempts.get(ip, []) if now_ts - t < window_seconds]
        ip_count = len(ip_attempts)
        if username:
            user_attempts = [t for t in _in_memory_user_attempts.get(username, []) if now_ts - t < window_seconds]
            user_count = len(user_attempts)
        return max(ip_count, user_count)


def is_rate_limited(ip: str, username: str = None, max_attempts: int = _RATE_LIMIT_MAX, window_seconds: int = _RATE_LIMIT_WINDOW) -> bool:
    """Check if EITHER the IP OR the target username has exceeded max allowed failed attempts.
    
    Security: This prevents:
    1. Single-IP brute force across many accounts (Credential Stuffing).
    2. Distributed / rotating-IP brute force against a single victim account (Botnet / Proxy spraying).
    """
    count = get_failed_attempts_count(ip, username=username, window_seconds=window_seconds)
    return count >= max_attempts


def record_failed_attempt(ip: str, username: str = None) -> None:
    """Record a failed login attempt for both IP and username in the database."""
    now_dt = _utc_now()
    now_ts = time.time()

    # Always update in-memory fallback
    ip_attempts = [t for t in _in_memory_ip_attempts.get(ip, []) if now_ts - t < _RATE_LIMIT_WINDOW]
    ip_attempts.append(now_ts)
    _in_memory_ip_attempts[ip] = ip_attempts

    if username:
        user_attempts = [t for t in _in_memory_user_attempts.get(username, []) if now_ts - t < _RATE_LIMIT_WINDOW]
        user_attempts.append(now_ts)
        _in_memory_user_attempts[username] = user_attempts

    if not has_app_context():
        return

    try:
        kwargs = {'ip_address': ip, 'attempted_at': now_dt}
        if username and hasattr(LoginAttempt, 'username'):
            kwargs['username'] = username[:80]

        attempt = LoginAttempt(**kwargs)
        db.session.add(attempt)
        db.session.commit()

        # Opportunistically prune attempts older than 10 minutes to prevent table bloating
        cleanup_cutoff = now_dt - datetime.timedelta(seconds=600)
        LoginAttempt.query.filter(LoginAttempt.attempted_at < cleanup_cutoff).delete()
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.debug("Database write failed in rate limiter (%s)", e)


def clear_attempts(ip: str = None, username: str = None) -> None:
    """Clear failed login attempts for a specific IP and/or username."""
    if ip:
        _in_memory_ip_attempts.pop(ip, None)
    if username:
        _in_memory_user_attempts.pop(username, None)
    if not ip and not username:
        _in_memory_ip_attempts.clear()
        _in_memory_user_attempts.clear()

    if not has_app_context():
        return

    try:
        query = LoginAttempt.query
        conditions = []
        if ip:
            conditions.append(LoginAttempt.ip_address == ip)
        if username and hasattr(LoginAttempt, 'username'):
            conditions.append(LoginAttempt.username == username)

        if conditions:
            query.filter(or_(*conditions)).delete(synchronize_session=False)
        else:
            query.delete()
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.debug("Database clear failed in rate limiter (%s)", e)


class DBLoginAttempts:
    """Dict-like compatibility proxy for tests and legacy references to login_attempts."""
    def clear(self):
        clear_attempts()

    def get(self, ip, default=None):
        count = get_failed_attempts_count(ip)
        if count > 0:
            return (count, time.time())
        return default

    def pop(self, ip, default=None):
        clear_attempts(ip=ip)
        return default

    def __len__(self):
        if not has_app_context():
            return len(_in_memory_ip_attempts)
        try:
            return LoginAttempt.query.count()
        except Exception:
            return len(_in_memory_ip_attempts)

    def __contains__(self, ip):
        if not has_app_context():
            return ip in _in_memory_ip_attempts
        try:
            cutoff = _utc_now() - datetime.timedelta(seconds=_RATE_LIMIT_WINDOW)
            return LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.attempted_at >= cutoff
            ).count() > 0
        except Exception:
            return ip in _in_memory_ip_attempts

    def __setitem__(self, ip, val):
        record_failed_attempt(ip)

    def __getitem__(self, ip):
        return self.get(ip)
