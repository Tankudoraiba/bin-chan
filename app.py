import os
import re
import uuid
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

from flask import Flask, request, render_template, url_for, jsonify, g, session
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import create_engine, Column, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configurations
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL', 'postgresql+asyncpg://username:password@localhost/mydatabase')
app.config['RATE_LIMIT'] = 50
app.config['RATE_LIMIT_DURATION'] = 1  # minutes
app.config['COOLDOWN_PERIOD'] = 5  # minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # If using HTTPS

logging.basicConfig(level=logging.WARNING)
rate_limit_data = defaultdict(lambda: {"timestamps": [], "last_limit_hit": None})

# Database setup
Base = declarative_base()
engine = create_engine(app.config['DATABASE_URL'])
SessionFactory = sessionmaker(bind=engine)
db_session = scoped_session(SessionFactory)

# Define the Text model
class Text(Base):
    __tablename__ = 'texts'
    
    id = Column(String(40), primary_key=True)
    content = Column(Text, nullable=False)
    expiry = Column(DateTime, nullable=False)
    is_encrypted = Column(Boolean, default=False)

# Initialize the database schema
def init_db():
    Base.metadata.create_all(engine)

# Store text in the database
def store_text(url_name, text, expiry_time, is_encrypted=False):
    new_text = Text(id=url_name, content=text, expiry=expiry_time, is_encrypted=is_encrypted)
    db_session.add(new_text)
    db_session.commit()

# Fetch text from the database, handle optional decryption
def fetch_text(url_name, password=None):
    text_entry = db_session.query(Text).filter_by(id=url_name).first()
    
    if text_entry:
        if datetime.now() < text_entry.expiry:
            content = text_entry.content
            if text_entry.is_encrypted:
                if not password:
                    return {"error": "Password required"}
                try:
                    return decrypt_text(content, password)
                except Exception:
                    return {"error": "Invalid password"}
            return content
    return None

# Encryption and decryption functions (same as before)
def encrypt_text(text, password):
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, password):
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text.encode()).decode()

def derive_key_from_password(password):
    key = hashlib.sha256(password.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(key)

# Delete expired texts from the database
def delete_expired_texts():
    now = datetime.now()
    try:
        deleted_count = db_session.query(Text).filter(Text.expiry < now).delete()
        db_session.commit()
        print(f"Deleted {deleted_count} expired texts.")
    except SQLAlchemyError as e:
        db_session.rollback()  # Rollback in case of error
        print(f"Error occurred: {str(e)}")

# Get expiry time based on the expiry option
def get_expiry_time(expiry_option):
    expiry_mapping = {
        '10m': timedelta(minutes=10),
        '1h': timedelta(hours=1),
        '3h': timedelta(hours=3),
        '24h': timedelta(days=1),
        '7d': timedelta(days=7)
    }
    return datetime.now() + expiry_mapping.get(expiry_option, timedelta(minutes=10))

# Validate password from session or request form
def validate_password(session, request):
    password = request.form.get('password', '').strip()
    if 'password' in session:
        password = session.pop('password')
    return password

# Initialize and start the scheduler for cleaning up expired texts
scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_expired_texts, trigger="interval", minutes=1)
scheduler.start()

# Rate limiting functions (same as before)
def is_rate_limited(ip):
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

# Rate limit decorator
def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        if is_rate_limited(ip):
            return jsonify({"error": "Too many requests. Please try again later."}), 429
        return func(*args, **kwargs)
    return wrapper

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

        expiry_time = get_expiry_time(expiry_option)

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
    text = fetch_text(url_name, password)

    if isinstance(text, dict) and 'error' in text:
        if text['error'] == "Password required":
            return render_template('password_prompt.html', url_name=url_name)
        else:
            return render_template('password_prompt.html', url_name=url_name, error=text['error'])

    if text:
        return render_template('shared_text.html', text=text)
    else:
        return render_template('404.html'), 404

@app.route('/text/<url_name>', methods=['GET'])
@rate_limit
def get_text(url_name):
    password = request.headers.get('pswd')
    result = fetch_text(url_name, password)

    if isinstance(result, dict):
        return result['error'], 403 if 'password' in result['error'].lower() else 404

    if result:
        return result, 200, {'Content-Type': 'text/plain'}
    return "Text not found or expired", 404

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Exception: {e}")
    return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
