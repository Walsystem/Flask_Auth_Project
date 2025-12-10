import os, sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_me')
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'site.db')

# Mail config
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True if os.environ.get('MAIL_USE_TLS', '1') == '1' else False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
mail = Mail(app)

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            password TEXT
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_first_request
def setup():
    init_db()

def find_user_by_email(email):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE email = ?', (email,))
    return cur.fetchone()

def create_user(email, name=None, password=None):
    db = get_db()
    cur = db.cursor()
    cur.execute('INSERT INTO users (email, name, password) VALUES (?, ?, ?)', (email, name, password))
    db.commit()
    return cur.lastrowid

# Simple session management using Flask session
from flask import session
def login_user_row(user_row):
    session['user_id'] = user_row['id']
    session['user_email'] = user_row['email']
    session['user_name'] = user_row['name']

def logout_user_session():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)

def current_user():
    if 'user_id' in session:
        return {'id': session.get('user_id'), 'email': session.get('user_email'), 'name': session.get('user_name')}
    return None

from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html', user=current_user())

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        if find_user_by_email(email):
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        create_user(email, name, hashed)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = find_user_by_email(email)
        if user and user['password'] and check_password_hash(user['password'], password):
            login_user_row(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('profile'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html', user=current_user())

@app.route('/auth/google')
def auth_google():
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def auth_google_callback():
    token = oauth.google.authorize_access_token()
    try:
        userinfo = oauth.google.parse_id_token(token)
    except Exception:
        userinfo = None
    if not userinfo:
        flash('Failed to obtain user info from Google.', 'danger')
        return redirect(url_for('login'))
    email = userinfo.get('email')
    name = userinfo.get('name') or email
    user = find_user_by_email(email)
    if not user:
        create_user(email, name, None)
        user = find_user_by_email(email)
    login_user_row(user)
    flash('Logged in with Google.', 'success')
    return redirect(url_for('profile'))

@app.route('/forgot', methods=['GET','POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email')
        user = find_user_by_email(email)
        # Always show same message to avoid account enumeration
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            link = url_for('reset_with_token', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Please click the link to reset your password: {link}\n\nIf you did not request this, ignore this email.'
            mail.send(msg)
        flash('If that email is registered, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot.html', user=current_user())

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The token has expired. Please request a new password reset.', 'danger')
        return redirect(url_for('forgot'))
    except BadSignature:
        flash('Invalid token.', 'danger')
        return redirect(url_for('forgot'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed = generate_password_hash(new_password)
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE email = ?', (hashed, email))
        db.commit()
        flash('Your password has been updated. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset.html', token=token, user=current_user())

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user())

@app.route('/logout')
def logout():
    logout_user_session()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
