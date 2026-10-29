#!/bin/sh
set -e
# Apply migrations, optionally load the fictional demo dataset, then serve.
alembic upgrade head
if [ "${CIIP_SEED_DEMO:-false}" = "true" ]; then
  python -m app.seed
fi
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
