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

# gosu is used by the entrypoint to drop from root to appuser after fixing
# /data ownership on the bind-mounted volume.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ app/
COPY wsgi.py .

# Entrypoint fixes /data ownership at runtime then drops to appuser
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create the data directory — ownership is fixed at runtime by the entrypoint
# because a bind-mount replaces this directory with the host directory.
RUN mkdir -p /data

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Single worker ensures in-memory rate limiting state is shared correctly.
# Increase -w only if you add a Redis-backed rate limiter.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:3000", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
