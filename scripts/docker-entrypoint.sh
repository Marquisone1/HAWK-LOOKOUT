#!/bin/sh
# Entrypoint: make /data writable for SQLite, then drop to appuser when possible.
set -e

mkdir -p /data

# Bind mounts can preserve host ownership; chown may fail on some platforms.
if ! chown -R appuser:appgroup /data 2>/dev/null; then
	echo "[entrypoint] warning: could not chown /data (bind-mount permission model)"
fi

# Ensure the DB file exists before SQLAlchemy initializes.
touch /data/database.db

# Keep restrictive defaults, but allow group write so uid/gid mapping works.
chmod 775 /data || true
chmod 664 /data/database.db || true

# Verify appuser can write to /data and DB file; if not, run as root so
# first boot succeeds instead of crashing with sqlite OperationalError.
if gosu appuser sh -c 'test -w /data && test -w /data/database.db'; then
	exec gosu appuser "$@"
fi

echo "[entrypoint] warning: /data is not writable by appuser; starting as root"
exec "$@"
