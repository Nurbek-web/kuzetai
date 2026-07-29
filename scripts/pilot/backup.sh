#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  echo "backup refused: $*" >&2
  exit 1
}

require_identifier() {
  [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$ ]] || fail "$1 is invalid"
}

site_id=${PILOT_SITE_ID:-}
target=${PILOT_BACKUP_TARGET:-}
endpoint=${PILOT_KZ_OBJECT_ENDPOINT:-}
bucket=${PILOT_EVIDENCE_BUCKET:-}
prefix=${PILOT_EVIDENCE_PREFIX:-}
config_manifest=${PILOT_CONFIG_MANIFEST:-}
model_manifest=${PILOT_MODEL_MANIFEST:-}
max_evidence_bytes=${PILOT_BACKUP_MAX_EVIDENCE_BYTES:-10737418240}
max_evidence_objects=${PILOT_BACKUP_MAX_EVIDENCE_OBJECTS:-10000}
max_database_bytes=${PILOT_BACKUP_MAX_DATABASE_BYTES:-10737418240}
max_manifest_bytes=${PILOT_BACKUP_MAX_MANIFEST_BYTES:-16777216}
max_runs=${PILOT_BACKUP_MAX_RUNS:-32}

require_identifier "site identity" "$site_id"
[[ "$target" = /* && "$target" != "/" && -d "$target" && ! -L "$target" ]] \
  || fail "target must be a dedicated existing directory"
physical_target=$(cd "$target" && pwd -P)
[[ "$physical_target" = "$target" ]] || fail "target path must not traverse symlinks"
marker="$target/.kuzet-pilot-backup-target.v1"
[[ -f "$marker" && ! -L "$marker" ]] || fail "target marker is missing"
[[ -f "$marker.sig" && ! -L "$marker.sig" ]] || fail "target marker signature is missing"
expected_marker=$(printf 'schema=kuzet-pilot-backup-target.v1\nsite_id=%s\ncountry=KZ\nencrypted=true\n' "$site_id")
[[ "$(<"$marker")" = "$expected_marker" ]] || fail "target marker is invalid"
[[ "$endpoint" =~ ^https://[^/?#]+$ ]] || fail "Kazakhstan object endpoint must be bare HTTPS"
[[ "$bucket" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{2,62}$ ]] || fail "evidence bucket is invalid"
[[ "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$ && "$prefix" != *".."* ]] \
  || fail "evidence prefix is invalid"
[[ "$max_evidence_bytes" =~ ^[1-9][0-9]*$ && "$max_evidence_bytes" -le 107374182400 ]] \
  || fail "evidence byte bound is invalid"
[[ "$max_evidence_objects" =~ ^[1-9][0-9]*$ && "$max_evidence_objects" -le 100000 ]] \
  || fail "evidence object bound is invalid"
[[ "$max_database_bytes" =~ ^[1-9][0-9]*$ && "$max_database_bytes" -le 107374182400 ]] \
  || fail "database byte bound is invalid"
[[ "$max_manifest_bytes" =~ ^[1-9][0-9]*$ && "$max_manifest_bytes" -le 67108864 ]] \
  || fail "manifest byte bound is invalid"
[[ "$max_runs" =~ ^[1-9][0-9]*$ && "$max_runs" -le 365 ]] \
  || fail "backup run bound is invalid"
[[ "$config_manifest" = /* && -f "$config_manifest" && ! -L "$config_manifest" ]] \
  || fail "config manifest is unavailable"
[[ "$model_manifest" = /* && -f "$model_manifest" && ! -L "$model_manifest" ]] \
  || fail "model manifest is unavailable"
config_manifest_bytes=$(wc -c < "$config_manifest" | tr -d ' ')
model_manifest_bytes=$(wc -c < "$model_manifest" | tr -d ' ')
[[ "$config_manifest_bytes" =~ ^[1-9][0-9]*$ && "$config_manifest_bytes" -le "$max_manifest_bytes" ]] \
  || fail "config manifest exceeds the finite size bound"
[[ "$model_manifest_bytes" =~ ^[1-9][0-9]*$ && "$model_manifest_bytes" -le "$max_manifest_bytes" ]] \
  || fail "model manifest exceeds the finite size bound"

run_count=$(find "$target" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' | wc -l | tr -d ' ')
(( run_count < max_runs )) || fail "finite backup target run limit reached"

for secret_name in pg_service.conf pgpass backup_age_recipient backup_signing_private_key aws_credentials kz_storage_attestation_public_key; do
  [[ -f "/run/secrets/$secret_name" && ! -L "/run/secrets/$secret_name" ]] \
    || fail "required Docker secret is unavailable"
done
for tool in age aws openssl pg_dump psql python3 sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "required backup tool is unavailable"
done
openssl dgst -sha256 -verify /run/secrets/kz_storage_attestation_public_key -signature "$marker.sig" "$marker" >/dev/null \
  || fail "backup target attestation signature is invalid"

export PGSERVICEFILE=/run/secrets/pg_service.conf
export PGPASSFILE=/run/secrets/pgpass
export AWS_SHARED_CREDENTIALS_FILE=/run/secrets/aws_credentials
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
stage=$(mktemp -d "$target/.backup-staging.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir -m 0700 "$stage/evidence"
cp "$config_manifest" "$stage/config-manifest"
cp "$model_manifest" "$stage/model-manifest"
staged_config_bytes=$(wc -c < "$stage/config-manifest" | tr -d ' ')
staged_model_bytes=$(wc -c < "$stage/model-manifest" | tr -d ' ')
[[ "$staged_config_bytes" =~ ^[1-9][0-9]*$ && "$staged_config_bytes" -le "$max_manifest_bytes" ]] \
  || fail "copied config manifest exceeds the finite size bound"
[[ "$staged_model_bytes" =~ ^[1-9][0-9]*$ && "$staged_model_bytes" -le "$max_manifest_bytes" ]] \
  || fail "copied model manifest exceeds the finite size bound"

site_prefix="${prefix%/}/$site_id"
aws --endpoint-url "$endpoint" s3api list-objects-v2 \
  --bucket "$bucket" \
  --prefix "$site_prefix/" \
  --page-size 1000 \
  --query '{Contents: Contents}' \
  --output json > "$stage/object-inventory.json"
inventory_bytes=$(python3 - "$stage/object-inventory.json" "$stage/inventory.tsv" "$site_prefix/" "$max_evidence_bytes" "$max_evidence_objects" <<'PY'
import json
import re
import sys

inventory_path, canonical_path, prefix, byte_limit, object_limit = sys.argv[1:]
with open(inventory_path, encoding="utf-8") as source:
    inventory = json.load(source)
if inventory.get("IsTruncated") is True or inventory.get("NextContinuationToken"):
    raise SystemExit("object inventory pagination was incomplete")
contents = inventory.get("Contents", [])
if not isinstance(contents, list) or len(contents) > int(object_limit):
    raise SystemExit("object inventory exceeds configured bound")
total = 0
rows = {}
for item in contents:
    key = item.get("Key")
    size = item.get("Size")
    suffix = key.removeprefix(prefix) if isinstance(key, str) else ""
    parts = suffix.split("/")
    if (
        not isinstance(key, str)
        or not key.startswith(prefix)
        or not suffix
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}", suffix)
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > 32
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or suffix in rows
    ):
        raise SystemExit("object inventory is not canonical and site scoped")
    if suffix in {"evidence-files.sha256", ".kuzet-pilot-restored-evidence.v1"}:
        raise SystemExit("object inventory uses a reserved evidence key")
    rows[suffix] = size
    total += size
    if total > int(byte_limit):
        raise SystemExit("object inventory exceeds configured byte bound")
with open(canonical_path, "w", encoding="utf-8") as output:
    for suffix, size in sorted(rows.items()):
        output.write(f"{size}\t{suffix}\n")
print(total)
PY
)

source_database=$(psql "service=kuzet_backup" -X -A -t -c 'SELECT current_database()')
schema_revision=$(psql "service=kuzet_backup" -X -A -t -c 'SELECT version_num FROM alembic_version')
database_bytes=$(psql "service=kuzet_backup" -X -A -t -c 'SELECT pg_database_size(current_database())')
require_identifier "source database" "$source_database"
require_identifier "schema revision" "$schema_revision"
[[ "$database_bytes" =~ ^[1-9][0-9]{0,11}$ && "$database_bytes" -le "$max_database_bytes" ]] \
  || fail "database size exceeds the configured backup bound"
pg_dump \
  --dbname=service=kuzet_backup \
  --format=custom \
  --no-owner \
  --no-acl \
  --file="$stage/database.dump"
database_dump_bytes=$(wc -c < "$stage/database.dump" | tr -d ' ')
[[ "$database_dump_bytes" =~ ^[1-9][0-9]{0,11}$ && "$database_dump_bytes" -le "$max_database_bytes" ]] \
  || fail "database dump exceeds the configured backup bound"
aws --endpoint-url "$endpoint" s3 sync \
  "s3://$bucket/$site_prefix/" "$stage/evidence/" \
  --no-progress --only-show-errors

downloaded_bytes=$(python3 - "$stage/evidence" "$stage/inventory.tsv" "$max_evidence_bytes" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
inventory_path = pathlib.Path(sys.argv[2])
limit = int(sys.argv[3])
total = 0
actual = {}
for path in root.rglob("*"):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
        raise SystemExit("downloaded evidence contains an unsafe entry")
    if path.resolve(strict=True).is_relative_to(root) is False:
        raise SystemExit("downloaded evidence escaped staging")
    if stat.S_ISREG(metadata.st_mode):
        relative = path.relative_to(root).as_posix()
        actual[relative] = metadata.st_size
        total += metadata.st_size
        if total > limit:
            raise SystemExit("downloaded evidence exceeds configured bound")
expected = {}
for line in inventory_path.read_text(encoding="utf-8").splitlines():
    size, relative = line.split("\t", 1)
    expected[relative] = int(size)
if actual != expected:
    raise SystemExit("downloaded evidence file set does not match inventory")
print(total)
PY
)
[[ "$downloaded_bytes" = "$inventory_bytes" ]] || fail "downloaded evidence does not match inventory"
(
  cd "$stage/evidence"
  find . -type f ! -name evidence-files.sha256 -print | LC_ALL=C sort | while IFS= read -r evidence_file; do
    sha256sum "$evidence_file"
  done > evidence-files.sha256
)
tar -C "$stage/evidence" -cf "$stage/evidence.tar" .
max_evidence_archive_bytes=$((max_evidence_bytes + max_evidence_objects * 4096 + 16777216))
evidence_archive_bytes=$(wc -c < "$stage/evidence.tar" | tr -d ' ')
[[ "$evidence_archive_bytes" =~ ^[1-9][0-9]*$ && "$evidence_archive_bytes" -le "$max_evidence_archive_bytes" ]] \
  || fail "evidence archive exceeds the configured backup bound"
config_sha256=$(sha256sum "$stage/config-manifest" | awk '{print $1}')
model_sha256=$(sha256sum "$stage/model-manifest" | awk '{print $1}')
cat >"$stage/manifest.txt" <<EOF
schema=kuzet-pilot-backup.v1
site_id=$site_id
source_database=$source_database
schema_revision=$schema_revision
created_at=$timestamp
country=KZ
evidence_prefix=$site_prefix
evidence_bytes=$inventory_bytes
config_sha256=$config_sha256
model_sha256=$model_sha256
EOF
cat >"$stage/backup-receipt.txt" <<EOF
schema=kuzet-pilot-backup-receipt.v1
site_id=$site_id
created_at=$timestamp
status=pending_fresh_target_restore
EOF

for artifact in database.dump evidence.tar manifest.txt backup-receipt.txt config-manifest model-manifest; do
  age --recipients-file /run/secrets/backup_age_recipient \
    --output "$stage/$artifact.age" "$stage/$artifact"
done
max_database_ciphertext_bytes=$((max_database_bytes + 1048576))
max_manifest_ciphertext_bytes=$((max_manifest_bytes + 1048576))
max_evidence_ciphertext_bytes=$((max_evidence_archive_bytes + 1048576))
database_ciphertext_bytes=$(wc -c < "$stage/database.dump.age" | tr -d ' ')
config_ciphertext_bytes=$(wc -c < "$stage/config-manifest.age" | tr -d ' ')
model_ciphertext_bytes=$(wc -c < "$stage/model-manifest.age" | tr -d ' ')
evidence_ciphertext_bytes=$(wc -c < "$stage/evidence.tar.age" | tr -d ' ')
backup_manifest_ciphertext_bytes=$(wc -c < "$stage/manifest.txt.age" | tr -d ' ')
backup_receipt_ciphertext_bytes=$(wc -c < "$stage/backup-receipt.txt.age" | tr -d ' ')
[[ "$database_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$database_ciphertext_bytes" -le "$max_database_ciphertext_bytes" ]] \
  || fail "encrypted database dump exceeds the configured backup bound"
[[ "$config_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$config_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" \
  && "$model_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$model_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" ]] \
  || fail "encrypted configuration/model manifest exceeds the configured backup bound"
[[ "$evidence_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$evidence_ciphertext_bytes" -le "$max_evidence_ciphertext_bytes" ]] \
  || fail "encrypted evidence archive exceeds the configured backup bound"
[[ "$backup_manifest_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$backup_manifest_ciphertext_bytes" -le 1048576 \
  && "$backup_receipt_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$backup_receipt_ciphertext_bytes" -le 1048576 ]] \
  || fail "encrypted backup metadata exceeds the finite size bound"
(
  cd "$stage"
  sha256sum \
    database.dump.age \
    evidence.tar.age \
    manifest.txt.age \
    backup-receipt.txt.age \
    config-manifest.age \
    model-manifest.age > checksums.sha256
)
openssl dgst -sha256 \
  -sign /run/secrets/backup_signing_private_key \
  -out "$stage/checksums.sha256.sig" \
  "$stage/checksums.sha256"

destination="$target/backup-$timestamp"
[[ ! -e "$destination" && ! -e "$destination.incomplete" ]] || fail "backup run already exists"
mkdir -m 0700 "$destination.incomplete"
mv "$stage/"*.age "$stage/checksums.sha256" "$stage/checksums.sha256.sig" "$destination.incomplete/"
mv "$destination.incomplete" "$destination"
echo "backup created; acceptance remains pending until a fresh-target restore receipt exists"
