#!/usr/bin/env bash
# backup.sh — Create a timestamped SQLite backup of the Hawk Lookout database.
#
# Usage (from the project root on the host):
#   ./scripts/backup.sh              # saves to ./data/backups/
#   ./scripts/backup.sh /my/path     # saves to /my/path/
#
# The script uses SQLite's online backup API (.backup) so the copy is safe
# even while the container is running and the database is in use.
#
# To run automatically, add a cron job on the host:
#   0 3 * * * /path/to/hawk-lookout/scripts/backup.sh >> /var/log/hawk-backup.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTAINER_NAME="hawk-lookout"
DB_PATH="/data/database.db"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILENAME="database-${TIMESTAMP}.db"

# Destination directory: first argument or ./data/backups/
BACKUP_DIR="${1:-${PROJECT_DIR}/data/backups}"
mkdir -p "$BACKUP_DIR"

BACKUP_DEST="${BACKUP_DIR}/${BACKUP_FILENAME}"

echo "[backup] Starting backup at $(date)"
echo "[backup] Container : ${CONTAINER_NAME}"
echo "[backup] Source    : ${DB_PATH}"
echo "[backup] Dest      : ${BACKUP_DEST}"

# Run the SQLite online backup inside the container, writing to a temp path
# inside /data, then copy it out to the host.
TEMP_CONTAINER_PATH="/data/backups/${BACKUP_FILENAME}"

docker exec "$CONTAINER_NAME" sh -c "
  mkdir -p /data/backups
  sqlite3 '${DB_PATH}' \".backup '${TEMP_CONTAINER_PATH}'\"
"

# Copy from container to host destination
docker cp "${CONTAINER_NAME}:${TEMP_CONTAINER_PATH}" "${BACKUP_DEST}"

# Remove the temp file inside the container
docker exec "$CONTAINER_NAME" rm -f "$TEMP_CONTAINER_PATH"

# Report size
SIZE=$(du -sh "$BACKUP_DEST" | cut -f1)
echo "[backup] Done. Backup saved: ${BACKUP_DEST} (${SIZE})"

# Prune backups older than 30 days
PRUNED=$(find "$BACKUP_DIR" -name "database-*.db" -mtime +30 -print -delete | wc -l)
if [ "$PRUNED" -gt 0 ]; then
  echo "[backup] Pruned ${PRUNED} backup(s) older than 30 days."
fi
