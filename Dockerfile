# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables to run Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set the working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt ./

# Install dependencies and vim
RUN apt update && apt install -y vim && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files into the container with correct ownership
COPY . .

# Expose the port
EXPOSE 1972

# Command to start the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=1972"]
