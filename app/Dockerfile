FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DB_PATH=/data/tasks.db

WORKDIR /app

# Dependencies first so Docker can cache this layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as an unprivileged user with a dedicated writable data directory.
RUN useradd --system --uid 10001 --no-create-home appuser \
    && mkdir /data \
    && chown appuser /data
USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# --worker-tmp-dir /dev/shm: gunicorn writes heartbeat files; with a read-only
# root filesystem it needs a writable in-memory location instead of /tmp.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-tmp-dir", "/dev/shm", "app:create_app()"]
