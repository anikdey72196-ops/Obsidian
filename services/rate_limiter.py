import time
import datetime
import logging
from flask import has_app_context
from extensions import db
from models import LoginAttempt

logger = logging.getLogger(__name__)

_RATE_LIMIT_MAX = 5
_RATE_LIMIT_WINDOW = 300  # 5 minutes window

# In-memory fallback if database table is not yet created, app context is missing, or DB is temporarily unavailable
_in_memory_fallback = {}


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def is_rate_limited(ip: str, max_attempts: int = _RATE_LIMIT_MAX, window_seconds: int = _RATE_LIMIT_WINDOW) -> bool:
    """Check if the given IP has exceeded allowed failed login attempts within window_seconds.
    Uses the persistent database table so rate limits are shared across all Gunicorn worker processes.
    """
    if not has_app_context():
        now = time.time()
        attempts = [t for t in _in_memory_fallback.get(ip, []) if now - t < window_seconds]
        _in_memory_fallback[ip] = attempts
        return len(attempts) >= max_attempts

    try:
        cutoff = _utc_now() - datetime.timedelta(seconds=window_seconds)
        count = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.attempted_at >= cutoff
        ).count()
        return count >= max_attempts
    except Exception as e:
        logger.debug("Database check failed in rate limiter (%s), using in-memory fallback", e)
        now = time.time()
        attempts = [t for t in _in_memory_fallback.get(ip, []) if now - t < window_seconds]
        _in_memory_fallback[ip] = attempts
        return len(attempts) >= max_attempts


def record_failed_attempt(ip: str) -> None:
    """Record a failed login attempt for the given IP in the database."""
    now_dt = _utc_now()
    now_ts = time.time()

    if not has_app_context():
        attempts = [t for t in _in_memory_fallback.get(ip, []) if now_ts - t < _RATE_LIMIT_WINDOW]
        attempts.append(now_ts)
        _in_memory_fallback[ip] = attempts
        return

    try:
        attempt = LoginAttempt(ip_address=ip, attempted_at=now_dt)
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
        logger.debug("Database write failed in rate limiter (%s), using in-memory fallback", e)
        attempts = [t for t in _in_memory_fallback.get(ip, []) if now_ts - t < _RATE_LIMIT_WINDOW]
        attempts.append(now_ts)
        _in_memory_fallback[ip] = attempts


def clear_attempts(ip: str = None) -> None:
    """Clear failed login attempts for a specific IP or all IPs."""
    if not has_app_context():
        if ip:
            _in_memory_fallback.pop(ip, None)
        else:
            _in_memory_fallback.clear()
        return

    try:
        if ip:
            LoginAttempt.query.filter_by(ip_address=ip).delete()
            _in_memory_fallback.pop(ip, None)
        else:
            LoginAttempt.query.delete()
            _in_memory_fallback.clear()
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.debug("Database clear failed in rate limiter (%s)", e)
        if ip:
            _in_memory_fallback.pop(ip, None)
        else:
            _in_memory_fallback.clear()


class DBLoginAttempts:
    """Dict-like compatibility proxy for tests and legacy references to login_attempts."""
    def clear(self):
        clear_attempts()

    def get(self, ip, default=None):
        if not has_app_context():
            return _in_memory_fallback.get(ip, default)
        try:
            cutoff = _utc_now() - datetime.timedelta(seconds=_RATE_LIMIT_WINDOW)
            count = LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.attempted_at >= cutoff
            ).count()
            if count > 0:
                return (count, time.time())
            return default
        except Exception:
            return _in_memory_fallback.get(ip, default)

    def pop(self, ip, default=None):
        clear_attempts(ip)
        return default

    def __len__(self):
        if not has_app_context():
            return len(_in_memory_fallback)
        try:
            return LoginAttempt.query.count()
        except Exception:
            return len(_in_memory_fallback)

    def __contains__(self, ip):
        if not has_app_context():
            return ip in _in_memory_fallback
        try:
            cutoff = _utc_now() - datetime.timedelta(seconds=_RATE_LIMIT_WINDOW)
            return LoginAttempt.query.filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.attempted_at >= cutoff
            ).count() > 0
        except Exception:
            return ip in _in_memory_fallback

    def __setitem__(self, ip, val):
        record_failed_attempt(ip)

    def __getitem__(self, ip):
        return self.get(ip)
