# Use stable Python version with Alpine for better compatibility
FROM python:3.12-alpine3.20

# Set working directory
WORKDIR /app

# Install RUNTIME dependencies first.
# These are needed by the compiled python packages and will stay in the image.
RUN apk add --no-cache \
    libxml2 \
    xmlsec \
    libxslt \
    openssl \
    pkgconfig

# Copy requirements file BEFORE installing to leverage Docker layer caching
COPY requirements.txt .

# Install build-time dependencies, build the python packages,
# and then remove the build-time dependencies, all in one layer.
# This keeps the final image slim.
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        gcc \
        musl-dev \
        libffi-dev \
        openssl-dev \
        libxml2-dev \
        libxslt-dev \
        xmlsec-dev \
        pkgconfig \
        cmake \
        make \
    && pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# Copy the rest of the application files
COPY app.py .
COPY auth.py .
COPY templates/ templates/
COPY static/ static/

# Expose the port the app actually runs on (as defined in app.py and docker-compose.yml)
EXPOSE 5001

# Run the app with gunicorn using gevent workers for WebSocket support
# -w 1: Single worker to maintain shared state for background thread
# -k gevent: Async worker class for WebSocket/Socket.IO support
# --worker-connections 1000: Max concurrent connections per worker
# --timeout 300: 5 minute timeout for long-running requests
# --bind 0.0.0.0:5001: Listen on all interfaces within container
CMD ["gunicorn", "-w", "1", "-k", "gevent", "--worker-connections", "1000", "--timeout", "300", "--bind", "0.0.0.0:5001", "app:app"]
