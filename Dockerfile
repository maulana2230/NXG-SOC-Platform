# IP Reputation Investigator - production container image
# Build:  docker compose build
# Run:    docker compose up -d

FROM python:3.11-slim

# Security hardening: no bytecode cache, unbuffered logs, no pip version check noise
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Least-privilege: dedicated non-root user/group (CIS Docker Benchmark 4.1)
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /usr/sbin/nologin appuser

WORKDIR /app

# Install dependencies in their own layer so code changes don't bust the pip cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Application code only -- config.json is intentionally NOT copied here.
# API keys must never be baked into an image layer; they are bind-mounted
# at runtime instead (see docker-compose.yml).
COPY app.py .
COPY static/ ./static/

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 5000

# Liveness check against the app's own health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/health',timeout=3).status==200 else 1)"

# Gunicorn (not the Flask dev server) for production: bounded workers/threads,
# request timeout to bound slow upstream threat-intel calls.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
