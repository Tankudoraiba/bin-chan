import os
import re
import uuid
import base64
import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from functools import wraps
from flask import Flask, request, render_template, url_for, jsonify, g, session, send_from_directory
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configurations
app.config['DATABASE'] = os.environ.get('DATABASE_URL', 'db.sqlite3')
app.config['RATE_LIMIT'] = 50
app.config['RATE_LIMIT_DURATION'] = 1  # minutes
app.config['COOLDOWN_PERIOD'] = 5  # minutes
app.config['session Cookie_httponly'] = True
app.config['session Cookie_secure'] = True  # If using HTTPS

db_initialized = False
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
rate_limit_data = defaultdict(
    lambda: {"timestamps": [], "last_limit_hit": None})

# Database Operations
def get_db():
    """
    Get a database connection.
    
    Returns:
        sqlite3 connection object
    """
    try:
        if 'db' not in g:
            db_path = app.config['DATABASE']
            logger.debug(f"Attempting to connect to database at: {os.path.abspath(db_path)}")
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
        return g.db
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

def close_db(exception=None):
    """
    Close the database connection.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initialize the database and create necessary tables if they don't exist.
    """
    try:
        db_path = app.config['DATABASE']
        logger.debug(f"Initializing database at: {os.path.abspath(db_path)}")
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
        
        # Use the app's connection method
        db = get_db()
        cursor = db.cursor()

        logger.info("Database connection established.")

        # Enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys = ON;")
        logger.info("Foreign key constraints enabled.")

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='texts';")
        if not cursor.fetchone():
            logger.info("Creating 'texts' table...")
            cursor.execute('''CREATE TABLE texts (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                expiry TEXT,
                is_encrypted INTEGER DEFAULT 0
            );''')
            db.commit()
            logger.info("Table 'texts' created successfully.")
        else:
            logger.info("Table 'texts' already exists.")

        # Verify table creation
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='texts';")
        if cursor.fetchone():
            logger.info("Database initialized successfully.")
        else:
            logger.error("Table creation failed - table not found after creation attempt!")
            raise RuntimeError("Table creation verification failed")

    except sqlite3.Error as e:
        logger.error(f"SQLite error during database initialization: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {e}")
        raise

def store_text(url_name, text, expiry_time, is_encrypted=False):
    """
    Store text in the database, with optional encryption if a password is provided.
    
    Parameters:
        url_name (str): The identifier for the text.
        text (str): The text to store.
        expiry_time (str): The expiration time for the text in '%Y-%m-%d %H:%M:%S.%f' format.
        is_encrypted (bool, optional): Whether the text is encrypted. Defaults to False.
    """
    db = get_db()
    db.execute('INSERT INTO texts (id, content, expiry, is_encrypted) VALUES (?, ?, ?, ?)',
               (url_name, text, expiry_time, int(is_encrypted)))
    db.commit()

def fetch_text(url_name, password=None):
    """
    Fetch text from the database if it exists and has not expired.
    If the text is encrypted, decrypt it using the provided password.
    
    Parameters:
        url_name (str): The identifier for the text.
        password (str, optional): The password for decryption if the text is encrypted.
    
    Returns:
        tuple or dict: If the text is found and not expired, returns (text, expiry_time).
        If the text is encrypted and no password is provided, or if the password is invalid, 
        returns a dict with an 'error' key.
        If the text is not found or has expired, returns None.
    """
    db = get_db()
    row = db.execute(
        'SELECT content, expiry, is_encrypted FROM texts WHERE id = ?', (url_name,)).fetchone()
    if row:
        expiry_time = datetime.strptime(row['expiry'], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) < expiry_time:
            content = row['content']
            if row['is_encrypted']:
                if not password:
                    return {"error": "Password required!"}
                try:
                    return decrypt_text(content, password), expiry_time
                except:
                    return {"error": "Invalid password!"}
            return content, expiry_time
    return None

def delete_expired_texts():
    """
    Delete expired texts from the database.
    """
    with app.app_context():
        db = get_db()
        db.execute('DELETE FROM texts WHERE expiry < ?', (datetime.now(timezone.utc),))
        db.commit()

# Encryption Functions
def encrypt_text(text, password):
    """
    Encrypt text using a password.
    
    Parameters:
        text (str): The text to encrypt.
        password (str): The password to use for encryption.
    
    Returns:
        str: The encrypted text.
    """
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, password):
    """
    Decrypt text using a password.
    
    Parameters:
        encrypted_text (str): The encrypted text to decrypt.
        password (str): The password to use for decryption.
    
    Returns:
        str: The decrypted text.
    """
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text.encode()).decode()

def derive_key_from_password(password):
    """
    Derive a cryptographic key from a password.
    
    Parameters:
        password (str): The password to derive the key from.
    
    Returns:
        bytes: The derived key.
    """
    key = hashlib.sha256(password.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(key)

# Rate Limiting
def is_rate_limited(ip):
    """
    Check if the user with the given IP address is rate-limited.
    
    Parameters:
        ip (str): The IP address of the user.
    
    Returns:
        bool: True if the user is rate-limited, False otherwise.
    """
    now = datetime.now()
    data = rate_limit_data[ip]
    timestamps = data["timestamps"]

    while timestamps and timestamps[0] < now - timedelta(minutes=app.config['RATE_LIMIT_DURATION']):
        timestamps.pop(0)

    if data["last_limit_hit"] and now < data["last_limit_hit"] + timedelta(minutes=app.config['COOLDOWN_PERIOD']):
        return True

    if len(timestamps) >= app.config['RATE_LIMIT']:
        data["last_limit_hit"] = now
        return True

    timestamps.append(now)
    return False

def rate_limit(func):
    """
    Rate limit decorator to limit the number of requests from a single IP address.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        if is_rate_limited(ip):
            return jsonify({"error": "Too many requests. Please try again later"}), 429
        return func(*args, **kwargs)
    return wrapper

# Helper Functions
def get_expiry_time(expiry_option):
    """
    Get the expiry time based on the expiry option.
    
    Parameters:
        expiry_option (str): The expiry option (e.g., '10m', '1h', etc.).
    
    Returns:
        datetime: The expiry time.
    """
    expiry_mapping = {
        '10m': timedelta(minutes=10),
        '1h': timedelta(hours=1),
        '3h': timedelta(hours=3),
        '24h': timedelta(days=1),
        '7d': timedelta(days=7)
    }
    return datetime.now() + expiry_mapping.get(expiry_option, timedelta(minutes=10))

def validate_password(session, request):
    """
    Validate the password from the session or request form.
    
    Parameters:
        session (flask.session): The Flask session object.
        request (flask.request): The Flask request object.
    
    Returns:
        str: The validated password.
    """
    password = request.form.get('password', '').strip()
    if 'password' in session:
        password = session.pop('password')
    return password

# Scheduler Setup
scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_expired_texts, trigger="interval", minutes=1)
scheduler.start()

# Request Handlers
@app.before_request
def ensure_db_initialized():
    """
    Ensure the database is initialized before each request if needed.
    """
    global db_initialized
    if not db_initialized:
        with app.app_context():
            logger.debug("Running late database initialization...")
            init_db()
        db_initialized = True

@app.route('/', methods=['GET', 'POST'])
@rate_limit
def index():
    if request.method == 'POST':
        text = request.form['text']
        url_name = request.form.get('url_name', '').strip()
        expiry_option = request.form.get('expiry_option')
        password = request.form.get('password', '').strip()

        if not text or len(text) > 6000:
            return jsonify({"error": "Invalid text!"}), 400

        if url_name and (not re.match("^[a-zA-Z0-9_-]*$", url_name) or len(url_name) > 40):
            return jsonify({"error": "Invalid URL name!"}), 400

        if not url_name:
            url_name = str(uuid.uuid4())[:8]

        if fetch_text(url_name):
            return jsonify({"error": "URL name already taken!"}), 400

        expiry_time = get_expiry_time(expiry_option).strftime('%Y-%m-%d %H:%M:%S.%f')

        is_encrypted = False
        if password:
            text = encrypt_text(text, password)
            is_encrypted = True
            session['password'] = password

        store_text(url_name, text, expiry_time, is_encrypted)

        return jsonify({"url": url_for('show_text', url_name=url_name)}), 200

    return render_template('index.html')

@app.route('/<url_name>', methods=['GET', 'POST'])
@rate_limit
def show_text(url_name):
    password = validate_password(session, request)
    result = fetch_text(url_name, password)

    if isinstance(result, dict) and 'error' in result:
        if result['error'] == "Password required!":
            return render_template('password_prompt.html', url_name=url_name)
        else:
            return render_template('password_prompt.html', url_name=url_name, error=result['error'])

    if result:
        text, expiry_time = result
        remaining_time = (expiry_time - datetime.now(timezone.utc)).total_seconds()
        return render_template('shared_text.html', text=text, url_name=url_name, remaining_time=remaining_time)
    else:
        return render_template('404.html'), 200

@app.route('/text/<url_name>', methods=['GET'])
@rate_limit
def get_text(url_name):
    password = request.headers.get('pswd')
    result = fetch_text(url_name, password)

    if isinstance(result, dict):
        return jsonify(result), 403 if 'password' in result.get('error', '').lower() else 404

    if result:
        text, expiry_time = result
        return text, 200, {'Content-Type': 'text/plain'}

    return "Text not found or expired", 404

@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static/files', 'robots.txt', mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static/files', 'sitemap.xml', mimetype='text/plain')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Exception: {e}")
    return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
