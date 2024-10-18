from flask import Flask, request, redirect, render_template, url_for, abort, jsonify
import sqlite3
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)

DATABASE = 'db.sqlite3'

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
            # Parse the expiry time including microseconds
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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        text = request.form['text']
        url_name = request.form.get('url_name', '').strip()  # Use provided URL name or generate if empty

        # If no custom URL is provided, generate a unique one
        if not url_name:
            url_name = str(uuid.uuid4())[:8]

        # Check if the URL already exists
        if fetch_text(url_name):
            return jsonify({"error": "URL name already taken!"}), 400

        expiry_time = datetime.now() + timedelta(hours=1)  # Set expiration time to 1 hour
        store_text(url_name, text, expiry_time)

        # Redirect to the shared text page
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
    init_db()  # Initialize the database when the app starts
    app.run(debug=True)

