from flask import Flask, request, redirect, render_template, url_for, abort, jsonify
import sqlite3
import uuid
from datetime import datetime, timedelta
import re
from collections import defaultdict

app = Flask(__name__)

DATABASE = 'db.sqlite3'
RATE_LIMIT = 5  # Limit to 5 requests per minute per IP
request_counts = defaultdict(list)

# Initialize the database with a table for storing text entries
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS texts (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                expiry TIMESTAMP
            );
        ''')
        conn.commit()

# Insert text into the database with an expiry time
def store_text(url_name, text, expiry_time):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('INSERT INTO texts (id, content, expiry) VALUES (?, ?, ?)', (url_name, text, expiry_time))
        conn.commit()

# Fetch text by id (url_name)
def fetch_text(url_name):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.execute('SELECT content, expiry FROM texts WHERE id = ?', (url_name,))
        row = cur.fetchone()
        if row:
            expiry_time = datetime.strptime(row[1], '%Y-%m-%d %H:%M:%S.%f')
            if datetime.now() < expiry_time:
                return row[0]
            else:
                return None
        else:
            return None

# Delete expired texts
def delete_expired_texts():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DELETE FROM texts WHERE expiry < ?', (datetime.now(),))
        conn.commit()

# Simple rate limiting based on IP address
def is_rate_limited(ip):
    now = datetime.now()
    timestamps = request_counts[ip]
    
    # Remove timestamps older than 1 minute
    while timestamps and timestamps[0] < now - timedelta(minutes=1):
        timestamps.pop(0)
    
    # Check if the request count exceeds the limit
    if len(timestamps) >= RATE_LIMIT:
        return True
    
    # Add current timestamp for the new request
    timestamps.append(now)
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        text = request.form['text']
        url_name = request.form.get('url_name', '').strip()

        # Validate text and URL name
        if not text or len(text) > 1000:
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

        expiry_time = datetime.now() + timedelta(hours=1)
        store_text(url_name, text, expiry_time)

        return jsonify({"url": url_for('show_text', url_name=url_name)}), 200
    
    return render_template('index.html')

@app.route('/<url_name>')
def show_text(url_name):
    delete_expired_texts()  # Clean up expired texts
    text = fetch_text(url_name)
    
    if text:
        return render_template('shared_text.html', text=text)
    else:
        abort(404)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
