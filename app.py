from flask import Flask, request, redirect, render_template, url_for, abort, jsonify, g
import sqlite3
import uuid
from datetime import datetime, timedelta
import re
from collections import defaultdict
from apscheduler.schedulers.background import BackgroundScheduler
import logging

app = Flask(__name__)

# Load configurations
app.config['DATABASE'] = 'db.sqlite3'
app.config['RATE_LIMIT'] = 10          # Max requests allowed per time window
app.config['RATE_LIMIT_DURATION'] = 1  # Duration in minutes for the limit window
app.config['COOLDOWN_PERIOD'] = 3      # Cooldown period in minutes after exceeding limit

# Initialize logging
logging.basicConfig(level=logging.ERROR)

# Create a new structure to hold rate-limiting info
rate_limit_data = defaultdict(lambda: {"timestamps": [], "last_limit_hit": None})

# Helper function to get a database connection
def get_db():
    """ Get a database connection. """
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row  # Optional: return rows as dict-like objects
    return g.db

# Close the database connection at the end of each request
@app.teardown_appcontext
def close_db(exception=None):
    """ Close the database connection after each request. """
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Initialize the database with a table for storing text entries
def init_db():
    """ Initialize the database schema. """
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS texts (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            expiry TIMESTAMP
        );
    ''')
    db.commit()

# Insert text into the database with an expiry time
def store_text(url_name, text, expiry_time):
    """ Store text in the database. """
    db = get_db()
    db.execute('INSERT INTO texts (id, content, expiry) VALUES (?, ?, ?)', (url_name, text, expiry_time))
    db.commit()

# Fetch text by id (url_name)
def fetch_text(url_name):
    """ Fetch text from the database by its URL name. """
    db = get_db()
    cur = db.execute('SELECT content, expiry FROM texts WHERE id = ?', (url_name,))
    row = cur.fetchone()
    if row:
        expiry_time = datetime.strptime(row['expiry'], '%Y-%m-%d %H:%M:%S.%f')
        if datetime.now() < expiry_time:  # Use UTC for consistency
            return row['content']
    return None

# Delete expired texts
def delete_expired_texts():
    """ Delete expired texts from the database. """
    with app.app_context():  # Ensure this function runs within the app context
        db = get_db()
        db.execute('DELETE FROM texts WHERE expiry < ?', (datetime.now(),))
        db.commit()

# Initialize and start the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_expired_texts, trigger="interval", minutes=1)
scheduler.start()

# Check if the user is rate limited
def is_rate_limited(ip):
    """ Check if the user is rate-limited. """
    now = datetime.now()
    data = rate_limit_data[ip]
    timestamps = data["timestamps"]
    
    # Remove timestamps older than the RATE_LIMIT_DURATION
    while timestamps and timestamps[0] < now - timedelta(minutes=app.config['RATE_LIMIT_DURATION']):
        timestamps.pop(0)
    
    # Check if we are in the cooldown period
    if data["last_limit_hit"] and now < data["last_limit_hit"] + timedelta(minutes=app.config['COOLDOWN_PERIOD']):
        return True  # User is still in cooldown period

    # Check if the request count exceeds the limit
    if len(timestamps) >= app.config['RATE_LIMIT']:
        data["last_limit_hit"] = now  # Set the time when limit was exceeded
        return True
    
    # Add current timestamp for the new request
    timestamps.append(now)
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    """ Handle the index route. """
    if request.method == 'POST':
        text = request.form['text']
        url_name = request.form.get('url_name', '').strip()
        expiry_option = request.form.get('expiry_option')  # Get the expiry option

        # Validate text and URL name
        if not text or len(text) > 6000:
            return jsonify({"error": "Invalid text!"}), 400

        if url_name and not re.match("^[a-zA-Z0-9_-]*$", url_name):
            return jsonify({"error": "Invalid URL name!"}), 400

        # Rate limiting check
        ip = request.remote_addr
        if is_rate_limited(ip):
            return jsonify({"error": "Too many requests. Please try again later."}), 429

        # Generate unique URL if not provided
        if not url_name:
            url_name = str(uuid.uuid4())[:8]

        if fetch_text(url_name):
            return jsonify({"error": "URL name already taken!"}), 400

        # Determine expiry time based on user selection
        expiry_mapping = {
            '10m': timedelta(minutes=10),
            '1h': timedelta(hours=1),
            '3h': timedelta(hours=3),
            '24h': timedelta(days=1),
            '7d': timedelta(days=7)
        }
        expiry_time = datetime.now() + expiry_mapping.get(expiry_option, timedelta(minutes=10))

        store_text(url_name, text, expiry_time)

        return jsonify({"url": url_for('show_text', url_name=url_name)}), 200
    
    return render_template('index.html')

@app.route('/<url_name>')
def show_text(url_name):
    """ Display the shared text. """
    text = fetch_text(url_name)
    
    if text:
        return render_template('shared_text.html', text=text)
    else:
        return render_template('404.html'), 404

@app.route('/text/<url_name>', methods=['GET'])
def get_text(url_name):
    """ Get text as plain text. """
    text = fetch_text(url_name)

    if text:
        return text, 200, {'Content-Type': 'text/plain'}
    else:
        return "Text not found or expired", 404
    
@app.errorhandler(Exception)
def handle_exception(e):
    """ Handle exceptions and log them. """
    logging.error(f"Exception: {e}")
    return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
