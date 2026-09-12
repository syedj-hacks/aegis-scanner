#!/usr/bin/env bash
# One-click local run for Aegis Shield (Linux / macOS).
# Builds and starts everything with Docker, then prints the URL to open.
set -euo pipefail
cd "$(dirname "$0")"

# Pick whichever Docker Compose is installed: the v2 plugin (`docker compose`)
# or the older standalone binary (`docker-compose`).
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "Docker is not installed or not running."
    echo "Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and start it, then run this again."
    exit 1
fi

# First run: create .env from the template so config/secrets aren't hardcoded.
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example."
    echo "  -> Before going live, edit .env and change JWT_SECRET and ADMIN_PASSWORD."
fi

APP_PORT="$(grep -E '^APP_PORT=' .env | cut -d= -f2 || true)"
APP_PORT="${APP_PORT:-8000}"

echo "Building and starting Aegis Shield (first build can take several minutes)..."
$COMPOSE up --build -d

# Wait for the app to report healthy before printing the URL.
printf "Waiting for Aegis Shield to become healthy"
for _ in $(seq 1 60); do
    if curl -fs "http://localhost:${APP_PORT}/health" >/dev/null 2>&1; then
        echo ""
        echo "────────────────────────────────────────────"
        echo "  Aegis Shield is running."
        echo "  Open:  http://localhost:${APP_PORT}"
        echo "────────────────────────────────────────────"
        echo "  Sign in with the admin e-mail/password from your .env file."
        echo "  Stop it with:  $COMPOSE down"
        exit 0
    fi
    printf "."
    sleep 3
done

echo ""
echo "The app did not report healthy in time. Recent logs:"
$COMPOSE logs --tail=40 app || true
exit 1
