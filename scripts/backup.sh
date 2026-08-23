#!/usr/bin/env bash
# BurnerBox encrypted database backup
#
# Dumps the PostgreSQL database to an age-encrypted file.
# Requires: pg_dump, age (https://github.com/FiloSottile/age)
#
# Usage:
#   export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
#   export BACKUP_PASSPHRASE="your-secret-passphrase"
#   ./backup.sh
#
# Output: burnerbox_backup_YYYYMMDD_HHMMSS.age
#
# SECURITY: The encrypted backup can only be decrypted with the passphrase.
# Store the passphrase in a separate secrets manager from the backup file.

set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL is not set" >&2
    exit 1
fi

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
    echo "ERROR: BACKUP_PASSPHRASE is not set" >&2
    exit 1
fi

# Check required tools
for cmd in pg_dump age; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed" >&2
        exit 1
    fi
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="burnerbox_backup_${TIMESTAMP}.age"

echo "Starting encrypted backup..."

# Dump to a temporary file, then encrypt with age
TEMP_DUMP=$(mktemp)
trap 'rm -f "$TEMP_DUMP"' EXIT

pg_dump "$DATABASE_URL" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    --verbose \
    > "$TEMP_DUMP" 2>/dev/null

# Encrypt with age using the passphrase
echo -n "$BACKUP_PASSPHRASE" | age -p -o "$OUTPUT_FILE" "$TEMP_DUMP"

# Clean up temp file
rm -f "$TEMP_DUMP"
trap - EXIT

# Get file size
FILESIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat --format=%s "$OUTPUT_FILE" 2>/dev/null || echo "unknown")

echo "Backup complete: $OUTPUT_FILE ($FILESIZE bytes)"
echo ""
echo "IMPORTANT: Store the passphrase securely and separately from this file."
echo "To restore: ./restore.sh $OUTPUT_FILE"
