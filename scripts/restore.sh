#!/usr/bin/env bash
# BurnerBox encrypted database restore
#
# Decrypts and restores a pg_dump backup encrypted with age.
# Requires: pg_restore, age (https://github.com/FiloSottile/age)
#
# Usage:
#   export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
#   export BACKUP_PASSPHRASE="your-secret-passphrase"
#   ./restore.sh burnerbox_backup_20260101_120000.age
#
# SECURITY: This will DROP and recreate all tables in the target database.
# Only use on a fresh or intentionally wiped database.

set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL is not set" >&2
    exit 1
fi

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
    echo "ERROR: BACKUP_PASSPHRASE is not set" >&2
    exit 1
fi

BACKUP_FILE="${1:-}"
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file.age>" >&2
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE" >&2
    exit 1
fi

# Check required tools
for cmd in pg_restore age; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed" >&2
        exit 1
    fi
done

echo "WARNING: This will DROP and recreate all tables in the target database."
echo "Target: $DATABASE_URL"
read -p "Are you sure? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

TEMP_DUMP=$(mktemp)
trap 'rm -f "$TEMP_DUMP"' EXIT

echo "Decrypting backup..."
echo -n "$BACKUP_PASSPHRASE" | age -d -o "$TEMP_DUMP" "$BACKUP_FILE"

echo "Restoring database..."
pg_restore \
    "$DATABASE_URL" \
    --clean \
    --if-exists \
    --no-owner \
    --no-privileges \
    --verbose \
    "$TEMP_DUMP" 2>/dev/null || true

rm -f "$TEMP_DUMP"
trap - EXIT

echo "Restore complete."
echo "Verify with: psql \$DATABASE_URL -c 'SELECT COUNT(*) FROM organizations;'"
