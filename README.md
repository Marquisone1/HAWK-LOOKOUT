# 🦅 HAWK LOOKOUT v2.1

**Minimal WHOIS reconnaissance tool for IPs and domains — now with free fallback services.**  
Self-hosted, Docker-ready, login-protected, with a REST API and a clean dark/light web UI.

> **⚠️ This is a fun vibe-coded side project — not enterprise software.**  
> Built for learning, tinkering, and home-lab threat hunting. No SLA, no warranty,
> no billion-dollar compliance certifications. Ship fast, break nothing important. 🚀

---

## What's New in v2.1

### Risk Intelligence Page
- **Comprehensive Risk Analysis** — Unified threat analysis with integrated risk scoring from multiple threat feeds
- **Lookup History Display** — Visual history as indexed boxes showing all previous lookups with timestamps in local timezone
- **Risk Score Display** — Prominent risk severity indicator (0-100 scale) with color-coded threat levels
- **ClickFix Minimum Enforcement** — ClickFix findings automatically trigger minimum risk score of 80
- **Local Time Display** — All timestamps converted to user's local timezone for better readability
- **Comprehensive Field Display** — All lookup result fields visible with recursive object formatting
- **Re-Scan Newest** — Latest re-scans automatically show newest results first

### Bug Fixes
- Fixed duplicate function definition blocking history loading
- Enhanced logging for risk intelligence pipeline debugging
- Improved API fallback logic for history retrieval
- CSRF token enforcement has been removed for now; a redesigned implementation is planned for a future release.

---

## What's New in v2.0

### Major Features
- **Fallback Services** — When WhoisFreak API is unavailable or depleted, automatically fallback to free services: IP-API for geolocation/threat intel, dnspython for comprehensive DNS records—no API key needed.
- **Admin Fallback Toggle** — New admin panel setting to manually switch between WhoisFreak API and free fallback services (useful for rate-limit testing or offline scenarios).
- **Enhanced DNS Intelligence** — 12+ DNS record types (A, AAAA, MX, NS, SOA, TXT, SPF, DMARC, CAA, TLSA), plus SSL/TLS certificate extraction and HTTP security header inspection.
- **Comprehensive IP Geolocation** — Location (continent, country, region, city, timezone), network details (ISP, ASN, connection type), threat analysis (proxy, VPN, Tor, hosting detection), and reverse DNS lookup.
- **Source Tracking** — All lookups now include a `source` field in the database and API response, showing which service was used ("WhoisFreak", "IP-API", or "DNS").
- **Expandable DNS Records** — Long DNS records (SPF, DMARC, CAA, TLSA, TXT) automatically truncate in card view with a "Show full record" dropdown for detailed inspection.

### Bug Fixes & Improvements
- Removed deprecated RDAP service (socket-based WHOIS fallback)
- Fixed toggle switch UI responsiveness and event delegation
- Added proper fallback routing based on target type (domain→DNS, IP→IP-API)
- Improved error handling for failed service lookups
- Database migration support for new fields (`prefer_fallback`, `source`)

### v1.2
- **URLhaus Integration** — Live malware host checks via the [abuse.ch URLhaus API](https://urlhaus-api.abuse.ch/). Shows malware URL count, online/offline status, threat tags, and recent malware URLs.
- **Security Patch (v1.1.1)** — Session role revalidation, constant-time API key comparison, admin-only backup routes, username length caps, POST logout.

### v1.1

- **Multi-User Support** — Admin and Analyst roles. Admins can create/delete users and manage API keys. Analysts get their own scoped lookup history.
- **Interactive Dashboard** — Visual analytics with lookup trends (bar chart), IP vs domain breakdown (donut), top targets, and threat feed health status.
- **Improved ClickFix Feed** — Retry logic with exponential backoff, feed health metadata, and a live status indicator on the dashboard.
- **14-Day Backup Retention** — Automatic daily backups now prune after 14 days (previously 30).
- **Admin Panel** — Full user CRUD at `/admin` — create analysts, toggle roles, delete accounts.
- **Per-User History** — Analysts only see their own lookups; admins see everything.

---

## Features

- **WHOIS Lookups** — IP addresses and domain names via the WhoisFreak API
- **Blacklist Checks** — Spamhaus ZEN/DBL, SpamCop, SORBS, SURBL, ClickFix threat feed, and URLhaus malware host intel
- **Lookup History** — Every query stored per-user; accessible from the UI or API
- **Multi-User** — Admin + Analyst roles with scoped access
- **Dashboard & Analytics** — Lookup trends, type breakdown, top targets, feed health
- **Web UI** — Login-protected dashboard with dark/light theme
- **REST API** — API-key authenticated; all endpoints documented below
- **Rate Limiting** — 30 req/min on the API, 10 req/min on login and settings
- **Security hardened** — security headers (CSP, HSTS, X-Frame DENY), session fixation prevention, non-root Docker container

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/) + [Docker Compose](https://docs.docker.com/compose/install/)
- A free [WhoisFreak API key](https://whoisfreakapi.com/) for WHOIS lookups
- A free [URLhaus Auth-Key](https://auth.abuse.ch/) for malware host checks (optional — scans still work without it)
- A domain + TLS certificate for production (Nginx config included)

---

## Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/Marquisone1/HAWK-LOOKOUT hawk-lookout
cd hawk-lookout

# 2. (Optional) set your WhoisFreak key upfront
cp .env.example .env
# Edit .env and set WHOISFREAK_API_KEY=your_key_here
# Optional: set WHOIS_HOST_PORT=8080 for a custom host port
# Optional (Ubuntu): set APP_UID/APP_GID to your server user ids (often 1000)

# 3. Start
docker compose up -d
```

On first boot, admin credentials are written to a secure file inside the container:

```bash
docker exec hawk-lookout cat /data/first_boot_credentials.txt
```

> **Delete this file after reading it** and change your password in Settings immediately.

The web UI is available at **http://localhost:${WHOIS_HOST_PORT:-3000}** (or your domain over HTTPS).

---

## Configuration

All settings are optional — the app works out of the box without any `.env` file.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | Flask session secret. Auto-generated and persisted to `/data/secret_key` if not set. |
| `WHOISFREAK_API_KEY` | _(empty)_ | Your [WhoisFreak](https://whoisfreakapi.com/) API key. Optional — if not set, the app will use free fallback services (IP-API + dnspython). Can also be set via Settings after login. |
| `WHOIS_HOST_PORT` | `3000` | Host port published by Docker (`127.0.0.1:<port>:3000`). Set this to run on a custom local port. |
| `APP_UID` | `1000` | Build-time UID for container user. Set to your host user id to avoid bind-mount permission issues on `./data`. |
| `APP_GID` | `1000` | Build-time GID for container group. Set to your host group id for `./data` write compatibility. |
| `FLASK_ENV` | `production` | Set to `development` for local dev (disables HTTPS enforcement and secure cookies). |
| `FLASK_PORT` | `8000` | Internal port for `flask run` (local dev only). Docker uses port `3000`. |

Copy `.env.example` to `.env` and fill in the values you need.

---

## Production Deployment (Nginx + HTTPS)

1. **Copy the Nginx config** to your server:
   ```bash
   sudo cp nginx/whois.conf /etc/nginx/sites-available/hawk-lookout
   sudo ln -s /etc/nginx/sites-available/hawk-lookout /etc/nginx/sites-enabled/
   ```

2. **Replace every `your-domain.com`** in the config with your actual domain:
   ```bash
   sudo sed -i 's/your-domain.com/example.com/g' /etc/nginx/sites-available/hawk-lookout
   ```

3. **Obtain a TLS certificate** (Certbot):
   ```bash
   sudo certbot certonly --standalone -d example.com
   ```

4. **Set `FLASK_ENV=production`** in your `.env` (enables HTTPS enforcement + HSTS).

5. **Start the stack**:
   ```bash
   docker compose up -d
   sudo nginx -t && sudo systemctl reload nginx
   ```

### Pre-launch checklist

- [ ] `your-domain.com` replaced in `nginx/whois.conf`
- [ ] TLS certificate obtained and paths updated in config
- [ ] `FLASK_ENV=production` set in `.env`
- [ ] First-boot credentials file read (`docker exec hawk-lookout cat /data/first_boot_credentials.txt`) and deleted
- [ ] Password changed from auto-generated default in Settings

---

## REST API

All endpoints (except `/health`) require the header:
```
X-API-Key: <your_api_key>
```

Your API key is shown on the Settings page.

### `GET /health`
Health check — no auth required.
```bash
curl https://example.com/health
# {"status": "ok"}
```

### `POST /lookup`
WHOIS lookup for an IP or domain.
```bash
curl -X POST https://example.com/lookup \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'
```
**Response:** `200` with WHOIS data · `400` bad target · `401` invalid key · `429` rate limited · `502` upstream error

### `GET /blacklist?target=<value>`
Check an IP or domain against threat blacklists.
```bash
curl "https://example.com/blacklist?target=8.8.8.8" -H "X-API-Key: your_key"
```
**Response:**
```json
{
  "target": "8.8.8.8",
  "type": "ip",
  "dnsbl": [
    { "list": "Spamhaus ZEN", "listed": false },
    { "list": "SpamCop",      "listed": false },
    { "list": "SORBS",        "listed": false }
  ],
  "clickfix": false,
  "urlhaus": null
}
```
When URLhaus finds malware URLs for the host, `urlhaus` contains `url_count`, `urls_online`, `tags`, `recent_urls`, and a link to the full URLhaus report.

### `GET /history`
Retrieve lookup history. Query params: `limit` (1–500, default 50), `offset` (default 0).
```bash
curl "https://example.com/history?limit=20" -H "X-API-Key: your_key"
```

### `DELETE /history/<id>`
Delete a single history entry.
```bash
curl -X DELETE https://example.com/history/42 -H "X-API-Key: your_key"
# {"deleted": 42}
```

---

## Updating

```bash
./scripts/update.sh
```

Pulls the latest code from `main`, rebuilds the image, and restarts the container. Data in `./data/` is untouched.

---

## Backup

```bash
docker compose exec whois sqlite3 /data/database.db ".backup '/data/database.bak.db'"
docker cp $(docker compose ps -q whois):/data/database.bak.db ./backup-$(date +%Y%m%d).db
```

---

## Security

| Area | Implementation |
|---|---|
| API key exposure | Never sent to the browser — web UI uses session authentication |
| Session cookies | `HttpOnly`, `SameSite=Lax`, `Secure=True` in production |
| CSRF | Temporarily removed in the current release; a new implementation is planned for a future release |
| Security headers | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`, Referrer-Policy |
| HTTPS / HSTS | `force_https=True` + HSTS (1 year) in production; nginx HTTP→HTTPS redirect |
| Rate limiting | 30 req/min on API, 10 req/min on login and settings |
| Proxy spoofing | `ProxyFix(x_for=1)` — rate limits use real client IP |
| Session fixation | Session regenerated on every successful login |
| Password strength | Min 12 chars + uppercase + lowercase + digit + special char |
| Cache control | `Cache-Control: no-store` on all HTML responses |
| Container | Non-root user (`appuser`), `no-new-privileges` |
| First-boot credentials | Written to `/data/first_boot_credentials.txt` (chmod 600), not to stdout/logs |

### Verify your deployment

```bash
# Security headers present
curl -sI https://example.com | grep -Ei "strict-transport|content-security|x-frame|x-content-type"

# Login rate limit — 11th attempt should return 429
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://example.com/login \
    -H "Content-Type: application/x-www-form-urlencoded" -d "username=x&password=x"
done

# API rate limit — 31st request should return 429
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code}\n" https://example.com/health
done
```

---

## Project Structure

```
hawk-lookout/
├── app/
│   ├── __init__.py       Application factory — security config, Talisman
│   ├── api.py            REST API routes (/lookup, /blacklist, /history)
│   ├── auth.py           API key auth, rate limiter, password validator
│   ├── config.py         Flask config (reads .env)
│   ├── models.py         SQLAlchemy models (User, SiteUser, LookupHistory)
│   ├── routes.py         Web routes (/login, /settings, /) + session-auth proxy
│   ├── services.py       WhoisFreak API client + blacklist checker + URLhaus
│   └── templates/        Jinja2 HTML templates
├── data/                 Docker volume — SQLite database lives here
├── nginx/
│   └── whois.conf        Nginx reverse-proxy + TLS config (update domain before use)
├── scripts/
│   └── update.sh         One-command update: git pull + docker compose up
├── Dockerfile            Multi-stage, non-root container image
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── wsgi.py               Gunicorn entry point
```

---

## License

MIT — free to use, modify, and distribute.
