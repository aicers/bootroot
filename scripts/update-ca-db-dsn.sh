#!/usr/bin/env bash
set -euo pipefail

CA_CONFIG_PATH="${CA_CONFIG_PATH:-secrets/config/ca.json}"
POSTGRES_USER="${POSTGRES_USER:-step}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-step-pass}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-stepca}"
POSTGRES_SSLMODE="${POSTGRES_SSLMODE:-disable}"

DSN="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=${POSTGRES_SSLMODE}"

python3 - <<PY
import json
from pathlib import Path

path = Path("${CA_CONFIG_PATH}")
data = json.loads(path.read_text(encoding="utf-8"))

db = data.setdefault("db", {})
db["type"] = "postgresql"
db["dataSource"] = "${DSN}"
db.pop("badgerFileLoadingMode", None)

path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

echo "Updated ${CA_CONFIG_PATH} with PostgreSQL DSN."
