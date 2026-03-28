# HAWK LOOKOUT — WHOIS Recon Tool

A Flask-based WHOIS lookup tool for IP addresses and domains, hardened for production deployment behind Nginx using Docker.

## Quick Start (Server)

```bash
# 1. Clone and enter the repo
git clone https://github.com/Marquisone1/WHO hawk-lookout
cd hawk-lookout

# 2. Start — no configuration needed
docker compose up -d
```

Admin credentials are **auto-generated and printed to the container log on first boot**:

```bash
docker compose logs whois | grep -A5 "FIRST BOOT"
```

Optionally set your WhoisFreak API key in the Settings page after logging in, or create a `.env` from `.env.example`.

The web UI is available at `http://localhost:8000` (or your domain over HTTPS via Nginx).

## Updating

```bash
./scripts/update.sh
```

This pulls the latest code from `main`, rebuilds the image, and restarts the container in place. Your data in `./data/` is untouched.

## Structure

```
docker-app/
├── app/                  Python package
│   ├── __init__.py       Application factory (security config lives here)
│   ├── api.py            REST API routes (/lookup, /history) — CSRF exempt
│   ├── auth.py           API key + session decorators, rate limiter
│   ├── config.py         Flask config (reads .env)
│   ├── models.py         SQLAlchemy models
│   ├── routes.py         Web routes (/login, /settings, /) — CSRF protected
│   ├── services.py       WhoisFreak API client
│   └── templates/        Jinja2 templates
├── data/                 Docker volume mount — SQLite lives here
├── nginx/
│   └── whois.conf        Nginx site config snippet
├── scripts/
│   └── update.sh         One-command update: git pull + docker compose up
├── Dockerfile            Multi-stage, non-root image
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── wsgi.py               Gunicorn entry point
```

## Security Hardening Applied

| Area | Fix |
|------|-----|
| CSRF | Flask-WTF protects all web forms (`/login`, `/settings`) |
| Security headers | Flask-Talisman: CSP, X-Frame-Options DENY, nosniff, Referrer-Policy |
| Rate limiting | 30 req/min on API, 10 req/min on `/login` (brute-force protection) |
| Proxy spoofing | `ProxyFix(x_for=1)` — rate limiter uses real IP, not spoofable header |
| Session fixation | Session is cleared and regenerated on successful login |
| Default password | Startup aborts if `ADMIN_PASSWORD` is not set — no hardcoded fallback |
| Password policy | Minimum 12 characters enforced |
| Container | Non-root user (`appuser`), `no-new-privileges` security option |
| Data exposure | "Default credentials" hint removed from login page |

## Pentest Commands

After deploying, run these to validate the hardening:

```bash
# Missing security headers check
curl -sI https://your-domain.com | grep -E "content-security|x-frame|x-content-type"

# CSRF protection — should return 400
curl -s -X POST https://your-domain.com/login \
     -d "username=admin&password=yourpassword" | grep -i error

# Login rate limit — should return 429 after 10 rapid attempts
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://your-domain.com/login \
       -d "username=x&password=x" -H "Content-Type: application/x-www-form-urlencoded"
done

# API rate limit — should return 429 after 30 rapid requests
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code}\n" https://your-domain.com/health
done

# SQLMap on lookup endpoint
sqlmap -u "https://your-domain.com/lookup" --method POST \
  -H "X-API-Key: <your_key>" \
  --data='{"target":"8.8.8.8"}' --content-type="application/json" --level=3

# Nikto scan
nikto -h https://your-domain.com -output nikto-report.txt

# OWASP ZAP baseline
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://your-domain.com -r zap-report.html
```
