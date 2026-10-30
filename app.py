import os
import urllib.parse
from imports import Flask, render_template, redirect, session, url_for, flash, NullPool, CSRFProtect
from extensions import db, jwt

# Import Modular Blueprints & Services
from auth import auth_bp, login_attempts as auth_login_attempts
from expenses import expenses_bp
from ai_service import ai_bp
from routes.auth_routes import auth_web_bp, login_attempts as app_login_attempts
from routes.expense_routes import expense_web_bp
from routes.admin_routes import admin_web_bp

login_attempts = app_login_attempts

app = Flask(__name__)
secret_key = os.environ.get('FLASK_SECRET_KEY')
if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY Error")
app.secret_key=secret_key

DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD_RAW = os.environ.get('DB_PASSWORD', '')
DB_PASSWORD = urllib.parse.quote_plus(DB_PASSWORD_RAW)
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_NAME = os.environ.get('DB_NAME', 'expense_tracker')
DB_PORT = os.environ.get('DB_PORT', '3306')

is_vercel = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None
is_render = os.environ.get('RENDER') == 'true' or os.environ.get('RENDER_SERVICE_ID') is not None

if os.environ.get('PYTEST_CURRENT_TEST'):
    db_uri = 'sqlite:///:memory:'
elif os.environ.get('DATABASE_URL') and 'dpg-xxx' not in os.environ.get('DATABASE_URL'):
    db_uri = os.environ.get('DATABASE_URL')
    if db_uri.startswith("postgres://"):
        db_uri = db_uri.replace("postgres://", "postgresql://", 1)
elif (is_vercel or is_render) and (os.environ.get('DB_HOST', 'localhost') in ('localhost', '127.0.0.1') or 'dpg-xxx' in os.environ.get('DATABASE_URL', '')):
    db_uri = 'sqlite:////tmp/expense_tracker.db'
else:
    db_uri = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

engine_options = {
    'poolclass': NullPool,
}

if not db_uri.startswith('sqlite') and DB_HOST not in ('localhost', '127.0.0.1'):
    connect_args = {'connect_timeout': 5}
    if os.environ.get('DB_USE_SSL', 'false').lower() == 'true':
        ca_path = '/etc/pki/tls/certs/ca-bundle.crt'
        if not os.path.exists(ca_path):
            import certifi
            ca_path = certifi.where()
        connect_args['ssl'] = {'ca': ca_path}
    engine_options['connect_args'] = connect_args

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)
db.init_app(app)

# Register API & Feature Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(expenses_bp)
app.register_blueprint(ai_bp)
csrf.exempt(ai_bp)

# Register Modular Web Routes
app.register_blueprint(auth_web_bp)
app.register_blueprint(expense_web_bp)
app.register_blueprint(admin_web_bp)

# Backward-compatibility Endpoint Aliases
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('expense_web.home'))
    return render_template('index.html')

# Endpoint aliases for url_for('login'), url_for('home'), etc.
app.add_url_rule('/login', endpoint='login', view_func=app.view_functions['auth_web.login'], methods=['GET', 'POST'])
app.add_url_rule('/register', endpoint='register', view_func=app.view_functions['auth_web.register'], methods=['GET', 'POST'])
app.add_url_rule('/logout', endpoint='logout', view_func=app.view_functions['auth_web.logout'])

app.add_url_rule('/home', endpoint='home', view_func=app.view_functions['expense_web.home'])
app.add_url_rule('/history', endpoint='history', view_func=app.view_functions['expense_web.history'])
app.add_url_rule('/addexpense', endpoint='add_expense', view_func=app.view_functions['expense_web.add_expense'], methods=['GET', 'POST'])
app.add_url_rule('/addexpense', endpoint='addexpense', view_func=app.view_functions['expense_web.add_expense'], methods=['GET', 'POST'])
app.add_url_rule('/edit_expense/<int:id>', endpoint='edit_expense', view_func=app.view_functions['expense_web.edit_expense'], methods=['GET', 'POST'])
app.add_url_rule('/delete_expense/<int:id>', endpoint='delete_expense', view_func=app.view_functions['expense_web.delete_expense'], methods=['POST'])

app.add_url_rule('/admin', endpoint='admin_panel', view_func=app.view_functions['admin_web.admin_panel'])


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Allow Tailwind CDN, Chart.js CDN, Three.js CDN, and Google Fonts
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


with app.app_context():
    if not os.environ.get('PYTEST_CURRENT_TEST') and not app.config.get('TESTING'):
        try:
            db.create_all()
        except Exception as e:
            print(f"Error during db.create_all(): {e}")


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(debug=debug_mode)