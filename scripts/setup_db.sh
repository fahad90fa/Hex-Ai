#!/bin/bash
set -e
echo "[nexus] starting infrastructure..."
docker-compose up -d
echo "[nexus] waiting for postgres..."
until docker-compose exec -T postgres pg_isready -U nexus; do sleep 2; done
echo "[nexus] running alembic migrations..."
cd backend && alembic upgrade head
echo "[nexus] setup complete"
