# Use an official Python runtime as a parent image
FROM python:3.11-alpine

# Set environment variables to run Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV DATABASE_URL=/app/db.sqlite3  # Ensure consistent DB path

# Set the working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt ./

# Install dependencies and SQLite
RUN apk update && apk add --no-cache sqlite vim
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files into the container
COPY . .

# Ensure the database is initialized
RUN python -c "from app import init_db, app; app.app_context().push(); init_db()"

# Expose the port
EXPOSE 1972

# Command to start the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=1972"]
