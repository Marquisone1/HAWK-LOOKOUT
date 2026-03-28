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
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ app/
COPY wsgi.py .

# Create the data directory and set ownership
RUN mkdir -p /data && chown appuser:appgroup /data

USER appuser

EXPOSE 8000

# 2 sync workers is plenty for a single-user WHOIS tool.
# Increase -w if you expect concurrent users.
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
