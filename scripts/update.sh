#!/usr/bin/env bash
# update.sh — Pull latest code and rebuild the container with zero-downtime.
# Run this on the server: ./scripts/update.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "==> Pulling latest code..."
git pull origin main

echo "==> Building and restarting container..."
docker compose up --build -d

echo "==> Removing dangling images..."
docker image prune -f

echo "==> Done. Container status:"
docker compose ps
