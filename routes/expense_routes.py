import os
from datetime import datetime, date, timedelta
from imports import (
    Blueprint, render_template, redirect, session, request, url_for, flash,
    db, User, Expense
)

expense_web_bp = Blueprint('expense_web', __name__)

GOOD_CATEGORIES = {'Education', 'Health', 'Utilities', 'Software', 'Personal Care', 'Investment'}
BAD_CATEGORIES = {'Shopping', 'Entertainment', 'Party/junk food'}

VALID_CATEGORIES = {
    'Food & Dining', 'Transport', 'Shopping', 'Utilities', 'Health',
    'Entertainment', 'Education', 'Software', 'Personal Care', 'Investment', 'Other'
}

CATEGORY_META = {
    'Food & Dining': {'icon': 'restaurant', 'color_class': 'text-violet-400', 'bg_class': 'bg-violet-400/10'},
    'Transport': {'icon': 'commute', 'color_class': 'text-emerald-400', 'bg_class': 'bg-emerald-400/10'},
    'Shopping': {'icon': 'shopping_bag', 'color_class': 'text-pink-400', 'bg_class': 'bg-pink-400/10'},
    'Utilities': {'icon': 'bolt', 'color_class': 'text-primary', 'bg_class': 'bg-primary/20'},
    'Health': {'icon': 'medical_services', 'color_class': 'text-red-400', 'bg_class': 'bg-red-400/10'},
    'Entertainment': {'icon': 'movie', 'color_class': 'text-yellow-400', 'bg_class': 'bg-yellow-400/10'},
    'Education': {'icon': 'school', 'color_class': 'text-blue-400', 'bg_class': 'bg-blue-400/10'},
    'Investment': {'icon': 'trending_up', 'color_class': 'text-emerald-400', 'bg_class': 'bg-emerald-400/10'},
    'Personal Care': {'icon': 'spa', 'color_class': 'text-purple-400', 'bg_class': 'bg-purple-400/10'},
    'Other': {'icon': 'category', 'color_class': 'text-slate-400', 'bg_class': 'bg-slate-400/10'},
}

DEFAULT_META = {'icon': 'receipt', 'color_class': 'text-violet-400', 'bg_class': 'bg-violet-400/10'}


def _format_expenses(expense_list):
    formatted = []
    for exp in expense_list:
        meta = CATEGORY_META.get(exp.category, DEFAULT_META)
        formatted.append({
            'id': exp.id,
            'category': exp.category,
            'amount': f"{exp.amount:,.2f}",
            'raw_amount': exp.amount,
            'description': exp.description or 'No description',
            'date': exp.date.strftime('%Y-%m-%d') if exp.date else '',
            'icon': meta['icon'],
            'color_class': meta['color_class'],
            'bg_class': meta['bg_class'],
        })
    return formatted


@expense_web_bp.route('/home')
def home():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('auth_web.login'))

    user_id = session['user_id']
    username = session.get('user', 'User')

    today = date.today()
    first_of_month = today.replace(day=1)

    all_user_expenses = Expense.query.filter_by(user_id=user_id).all()
    this_month_expenses = [e for e in all_user_expenses if e.date and e.date >= first_of_month]

    monthly_spent = sum(e.amount for e in this_month_expenses)

    days_elapsed = max((today - first_of_month).days + 1, 1)
    daily_avg = monthly_spent / days_elapsed

    last_month_end = first_of_month - timedelta(days=1)
    last_month_start = last_month_end.replace(day=1)
    last_month_expenses = [e for e in all_user_expenses if e.date and last_month_start <= e.date <= last_month_end]
    last_month_total = sum(e.amount for e in last_month_expenses)

    if last_month_total > 0:
        mo_change_pct = round(((monthly_spent - last_month_total) / last_month_total) * 100, 1)
    else:
        mo_change_pct = 0.0

    today_expenses = [e for e in all_user_expenses if e.date == today]
    good_deductions = sum(e.amount for e in today_expenses if e.category in GOOD_CATEGORIES)
    bad_deductions = sum(e.amount for e in today_expenses if e.category in BAD_CATEGORIES) * 2
    today_score = max(0, int(100 - (good_deductions + bad_deductions)))

    recent_db = Expense.query.filter_by(user_id=user_id).order_by(Expense.date.desc()).limit(5).all()
    recent_transactions = _format_expenses(recent_db)

    day_names = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT']
    six_days_ago = today - timedelta(days=6)
    daily_totals = {today - timedelta(days=i): 0.0 for i in range(7)}

    for exp in all_user_expenses:
        if exp.date and six_days_ago <= exp.date <= today:
            daily_totals[exp.date] = daily_totals.get(exp.date, 0.0) + exp.amount

    chart_labels = []
    chart_data = []
    for d in sorted(daily_totals.keys()):
        day_idx = (d.weekday() + 1) % 7
        chart_labels.append(day_names[day_idx])
        chart_data.append(round(daily_totals[d], 2))

    monthly_chart_labels = []
    monthly_chart_data = []
    for i in range(5, -1, -1):
        m_date = (today.replace(day=1) - timedelta(days=i*28)).replace(day=1)
        m_end = (m_date.replace(month=m_date.month % 12 + 1, day=1) - timedelta(days=1)) if m_date.month < 12 else m_date.replace(day=31)
        m_total = sum(e.amount for e in all_user_expenses if e.date and m_date <= e.date <= m_end)
        monthly_chart_labels.append(m_date.strftime('%b'))
        monthly_chart_data.append(round(m_total, 2))

    cat_totals = {}
    for exp in this_month_expenses:
        cat_totals[exp.category] = cat_totals.get(exp.category, 0.0) + exp.amount

    sorted_cats = sorted(cat_totals.items(), key=lambda x: x[1], reverse=True)[:5]
    cat_labels = [c[0] for c in sorted_cats]
    cat_data = [round(c[1], 2) for c in sorted_cats]

    stats = {
        'total_balance': f"{monthly_spent:,.2f}",
        'monthly_spent': f"{monthly_spent:,.2f}",
        'raw_monthly_spent': monthly_spent,
        'daily_avg': f"{daily_avg:,.2f}",
        'last_month_total': f"{last_month_total:,.2f}",
        'mo_change_pct': mo_change_pct,
        'today_score': today_score,
        'overall_score': min(10, max(1, int(today_score / 10))),
        'chart_data': {'labels': chart_labels, 'data': chart_data},
        'monthly_chart_data': {'labels': monthly_chart_labels, 'data': monthly_chart_data},
        'category_chart_data': {'labels': cat_labels, 'data': cat_data},
    }

    return render_template("home.html", username=username, stats=stats, recent_transactions=recent_transactions)


@expense_web_bp.route('/history')
def history():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('auth_web.login'))

    user_id = session['user_id']
    query = Expense.query.filter_by(user_id=user_id)

    filter_type = request.args.get('filter', 'all')
    category_filter = request.args.get('category', 'all')
    sort_order = request.args.get('sort', 'date_desc')
    search_query = request.args.get('search', '').strip()
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')

    today = date.today()
    if filter_type == 'past_week':
        query = query.filter(Expense.date >= today - timedelta(days=7))
    elif filter_type == 'past_month':
        query = query.filter(Expense.date >= today - timedelta(days=30))
    elif filter_type == 'past_3_months':
        query = query.filter(Expense.date >= today - timedelta(days=90))
    elif filter_type == 'custom':
        if start_date_str:
            try:
                s_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                query = query.filter(Expense.date >= s_date)
            except ValueError:
                pass
        if end_date_str:
            try:
                e_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                query = query.filter(Expense.date <= e_date)
            except ValueError:
                pass

    if category_filter and category_filter != 'all':
        query = query.filter(Expense.category == category_filter)

    if search_query:
        # Sanitize LIKE wildcard characters (%, _, \) to prevent wildcard injection & DoS
        clean_search = search_query[:100].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = query.filter(Expense.description.ilike(f'%{clean_search}%', escape='\\'))

    if sort_order == 'date_asc':
        query = query.order_by(Expense.date.asc())
    elif sort_order == 'amount_desc':
        query = query.order_by(Expense.amount.desc())
    elif sort_order == 'amount_asc':
        query = query.order_by(Expense.amount.asc())
    else:
        query = query.order_by(Expense.date.desc())

    expenses = query.all()

    total_amount = sum(e.amount for e in expenses)
    count = len(expenses)
    avg_amount = (total_amount / count) if count > 0 else 0

    all_user_expenses = Expense.query.filter_by(user_id=user_id).all()
    categories = sorted(list({e.category for e in all_user_expenses if e.category}))

    stats = {
        'total_amount': f"{total_amount:,.2f}",
        'count': count,
        'avg_amount': f"{avg_amount:,.2f}"
    }

    return render_template(
        "history.html",
        expenses=expenses,
        stats=stats,
        categories=categories,
        filter_type=filter_type,
        category_filter=category_filter,
        sort_order=sort_order,
        search_query=search_query,
        start_date=start_date_str,
        end_date=end_date_str
    )


@expense_web_bp.route('/addexpense', methods=['GET', 'POST'])
def add_expense():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('auth_web.login'))

    if request.method == 'POST':
        category = request.form.get('category')
        amount_str = request.form.get('amount')
        date_str = request.form.get('date')
        description = request.form.get('description')

        if not category or not amount_str or not date_str:
            flash("Category, Amount, and Date are required.", "danger")
            return redirect(url_for('expense_web.add_expense'))

        if category not in VALID_CATEGORIES:
            flash(f"Invalid category. Please select a valid category from the list.", "danger")
            return redirect(url_for('expense_web.add_expense'))

        try:
            amount = float(amount_str)
            if amount <= 0 or amount > 1000000 or str(amount_str).lower() in ('inf', '-inf', 'nan', '1e10', 'infinity'):
                flash("Amount must be a positive number.", "danger")
                return redirect(url_for('expense_web.add_expense'))
        except ValueError:
            flash("Invalid amount.", "danger")
            return redirect(url_for('expense_web.add_expense'))

        try:
            exp_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('expense_web.add_expense'))

        new_expense = Expense(
            user_id=session['user_id'],
            amount=amount,
            category=category,
            date=exp_date,
            description=description
        )

        db.session.add(new_expense)
        db.session.commit()
        flash("Expense added successfully!", "success")
        return redirect(url_for('expense_web.home'))

    return render_template("add_expense.html")


@expense_web_bp.route('/edit_expense/<int:id>', methods=['GET', 'POST'])
def edit_expense(id):
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('auth_web.login'))

    expense = Expense.query.filter_by(id=id, user_id=session['user_id']).first()

    if not expense:
        flash("Expense not found or access denied.", "danger")
        return redirect(url_for('expense_web.home'))

    if request.method == 'POST':
        category = request.form.get('category')
        amount_str = request.form.get('amount')
        date_str = request.form.get('date')
        description = request.form.get('description')

        if category:
            if category not in VALID_CATEGORIES:
                flash("Invalid category. Please select a valid category from the list.", "danger")
                return redirect(url_for('expense_web.edit_expense', id=id))
            expense.category = category
        if amount_str:
            try:
                amt = float(amount_str)
                if amt > 0:
                    expense.amount = amt
            except ValueError:
                pass
        if date_str:
            try:
                expense.date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                pass

        expense.description = description
        db.session.commit()

        flash("Expense updated successfully!", "success")
        return redirect(url_for('expense_web.home'))

    return render_template("edit.html", expense=expense.to_dict())


@expense_web_bp.route('/delete_expense/<int:id>', methods=['POST'])
def delete_expense(id):
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('auth_web.login'))

    expense = Expense.query.filter_by(id=id, user_id=session['user_id']).first()
    if expense:
        db.session.delete(expense)
        db.session.commit()
        flash("Expense deleted successfully!", "success")
    else:
        flash("Expense not found or could not be deleted.", "danger")

    return redirect(url_for('expense_web.home'))
