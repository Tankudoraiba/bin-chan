# Use an official Python runtime as a parent image
FROM python:3.13-alpine

# Set environment variables to run Flask in production
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0
ENV TZ=UTC

# Set the working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt ./

# Install dependencies and utilities (vim and curl)
RUN apk update && apk add --no-cache vim curl tzdata \
    && cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone

# Install Python dependencies and gunicorn
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application files into the container with correct ownership
COPY . .

# Expose the port
EXPOSE 1972

# Basic HTTP healthcheck using curl
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:1972/ || exit 1

# Command to start the application with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:1972", "--workers", "2", "--threads", "4", "app:app"]
