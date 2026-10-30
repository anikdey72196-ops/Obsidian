import os
import hmac
import logging
from imports import Blueprint, render_template, redirect, session, request, url_for, flash, User, Expense

logger = logging.getLogger(__name__)
admin_web_bp = Blueprint('admin_web', __name__)

MAX_ADMIN_EXPENSE_DISPLAY = 500


def _is_admin_authorized():
    """Check if the current session user is the configured admin.
    Uses hmac.compare_digest for constant-time comparison to prevent timing attacks.
    Returns True if authorized, False otherwise.
    """
    if not session.get('user_id'):
        return False

    admin_user = os.environ.get('ADMIN_USERNAME', '').strip()
    admin_key = os.environ.get('ADMIN_SECRET_KEY', '').strip()

    # Must have at least one credential configured
    if not admin_user and not admin_key:
        logger.warning("ADMIN_USERNAME and ADMIN_SECRET_KEY are not set. Admin panel is disabled.")
        return False

    current_user = session.get('user', '')

    if admin_user and current_user:
        is_user_match = hmac.compare_digest(
            current_user.encode('utf-8'), admin_user.encode('utf-8')
        )
        if is_user_match:
            return True

    # Security: Do NOT accept secrets in URL query parameters (?key=...)
    # Query parameters are logged in proxy/access logs and visible in browser history.
    # Accept admin secret key strictly via HTTP header (X-Admin-Key or Authorization Bearer) only.
    admin_header_key = request.headers.get('X-Admin-Key', '').strip()
    if not admin_header_key:
        auth_header = request.headers.get('Authorization', '').strip()
        if auth_header.startswith('Bearer '):
            admin_header_key = auth_header[7:].strip()

    if admin_key and admin_header_key:
        is_key_match = hmac.compare_digest(
            admin_header_key.encode('utf-8'), admin_key.encode('utf-8')
        )
        if is_key_match:
            return True

    return False


@admin_web_bp.route('/admin')
def admin_panel():
    if not _is_admin_authorized():
        logger.warning("Unauthorized admin panel access attempt by user_id=%s", session.get('user_id'))
        flash("Access Denied: Administrator permissions required.", "danger")
        return redirect(url_for('expense_web.home'))

    try:
        users = User.query.order_by(User.id.asc()).all()
        user_data = []
        total_system_expenses = 0

        for u in users:
            user_expenses = (
                Expense.query
                .filter_by(user_id=u.id)
                .order_by(Expense.date.desc())
                .limit(MAX_ADMIN_EXPENSE_DISPLAY)
                .all()
            )
            exp_list = []
            user_total = 0.0
            for exp in user_expenses:
                user_total += exp.amount
                exp_list.append({
                    'id': exp.id,
                    'category': exp.category,
                    'amount': round(exp.amount, 2),
                    'date': exp.date.strftime('%Y-%m-%d') if exp.date else '--',
                    'description': exp.description or 'No description'
                })

            total_system_expenses += len(exp_list)
            user_data.append({
                'id': u.id,
                'username': u.username,
                'total_spent': round(user_total, 2),
                'expense_count': len(exp_list),
                'expenses': exp_list
            })

        return render_template(
            'admin.html',
            user_data=user_data,
            total_users=len(users),
            total_expenses=total_system_expenses
        )
    except Exception:
        logger.exception("Error rendering admin panel")
        flash("An internal error occurred while loading the admin panel.", "danger")
        return redirect(url_for('expense_web.home'))
