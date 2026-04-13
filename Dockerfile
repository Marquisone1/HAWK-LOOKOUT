# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Python dependency install (cached layer)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Non-root user — containers should never run as root
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --gid ${APP_GID} appgroup \
 && useradd --uid ${APP_UID} --gid appgroup --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ app/
COPY wsgi.py .

# Create the data directory and set ownership
RUN mkdir -p /data && chown appuser:appgroup /data && chmod 770 /data

USER appuser

EXPOSE 3000

# Single worker ensures in-memory rate limiting state is shared correctly.
# Increase -w only if you add a Redis-backed rate limiter.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:3000", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
