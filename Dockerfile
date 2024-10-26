# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Create a non-root user 'binchan' and switch to it
RUN adduser --disabled-password --gecos '' binchan

# Set environment variables to run Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set the working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY --chown=binchan:binchan requirements.txt ./  # Set ownership

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files into the container with correct ownership
COPY --chown=binchan:binchan . .  # Set ownership

# Create the directory for the SQLite database
RUN mkdir -p /var/db && chown -R binchan:binchan /var/db

# Expose the port
EXPOSE 1972

# Health check
HEALTHCHECK CMD curl --fail http://localhost:1972/health || exit 1

# Switch to 'binchan' user
USER binchan

# Command to start the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=1972"]
