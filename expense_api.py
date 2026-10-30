from imports import Flask, timedelta, os, urllib, load_dotenv, db, jwt
from auth import auth_bp
from expenses import expenses_bp

def create_app():
    app = Flask(__name__)
    
    # Configure MySQL database
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD_RAW = os.environ.get('DB_PASSWORD', '')
    DB_PASSWORD = urllib.parse.quote_plus(DB_PASSWORD_RAW)
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_NAME = os.environ.get('DB_NAME', 'expense_tracker')
    DB_PORT = os.environ.get('DB_PORT', '3306') # <-- Add this line

    if os.environ.get('PYTEST_CURRENT_TEST'):
        db_uri = 'sqlite:///:memory:'
    else:
        db_uri = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    if DB_HOST != 'localhost' and DB_HOST != '127.0.0.1' and not os.environ.get('PYTEST_CURRENT_TEST'):
        import ssl
        ca_path = '/etc/pki/tls/certs/ca-bundle.crt'
        if not os.path.exists(ca_path):
            import certifi
            ca_path = certifi.where()
        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'ssl': ctx}}
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Configure JWT
    jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
    if not jwt_secret_key:
        raise RuntimeError("JWT_SECRET_KEY environment variable set nahi hai! Production mein yeh required hai.")
    app.config['JWT_SECRET_KEY'] = jwt_secret_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(expenses_bp)

    # Create the database tables
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    debug_mode = os.environ.get('FLASK_DEBUG', 'FALSE').lower() in ('true' , '1')
    app.run(debug=debug_mode, port=5000)
