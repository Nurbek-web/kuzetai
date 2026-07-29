#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  echo "backup refused: $*" >&2
  exit 1
}

field() {
  local key=$1
  local file=$2
  awk -F= -v key="$key" '$1 == key {value=substr($0, length(key) + 2); count++} END {if (count == 1) print value}' "$file"
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
max_attestation_seconds=${PILOT_STORAGE_ATTESTATION_MAX_SECONDS:-86400}
snapshot_helper=${PILOT_BACKUP_SNAPSHOT_HELPER:-/app/scripts/pilot/backup_snapshot.py}

require_identifier "site identity" "$site_id"
[[ "$target" = /* && "$target" != "/" && -d "$target" && ! -L "$target" ]] \
  || fail "target must be a dedicated existing directory"
physical_target=$(cd "$target" && pwd -P)
[[ "$physical_target" = "$target" ]] || fail "target path must not traverse symlinks"
marker="$target/.kuzet-pilot-backup-target.v1"
[[ -f "$marker" && ! -L "$marker" ]] || fail "target marker is missing"
[[ -f "$marker.sig" && ! -L "$marker.sig" ]] || fail "target marker signature is missing"
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
[[ "$max_attestation_seconds" =~ ^[1-9][0-9]*$ && "$max_attestation_seconds" -le 604800 ]] \
  || fail "storage attestation lifetime bound is invalid"
[[ "$config_manifest" = /* && -f "$config_manifest" && ! -L "$config_manifest" ]] \
  || fail "config manifest is unavailable"
[[ "$model_manifest" = /* && -f "$model_manifest" && ! -L "$model_manifest" ]] \
  || fail "model manifest is unavailable"
[[ "$snapshot_helper" = /* && -f "$snapshot_helper" && ! -L "$snapshot_helper" ]] \
  || fail "database snapshot helper is unavailable"
config_manifest_bytes=$(wc -c < "$config_manifest" | tr -d ' ')
model_manifest_bytes=$(wc -c < "$model_manifest" | tr -d ' ')
[[ "$config_manifest_bytes" =~ ^[1-9][0-9]*$ && "$config_manifest_bytes" -le "$max_manifest_bytes" ]] \
  || fail "config manifest exceeds the finite size bound"
[[ "$model_manifest_bytes" =~ ^[1-9][0-9]*$ && "$model_manifest_bytes" -le "$max_manifest_bytes" ]] \
  || fail "model manifest exceeds the finite size bound"

run_count=$(find "$target" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' | wc -l | tr -d ' ')
(( run_count < max_runs )) || fail "finite backup target run limit reached"

for secret_name in pg_service.conf pgpass backup_age_recipient backup_signing_private_key aws_credentials kz_storage_attestation_public_key kz_storage_verifier_record; do
  [[ -f "/run/secrets/$secret_name" && ! -L "/run/secrets/$secret_name" ]] \
    || fail "required Docker secret is unavailable"
done
for tool in age aws findmnt openssl pg_dump psql python3 sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "required backup tool is unavailable"
done
openssl dgst -sha256 -verify /run/secrets/kz_storage_attestation_public_key -signature "$marker.sig" "$marker" >/dev/null \
  || fail "backup target attestation signature is invalid"
verifier_record_bytes=$(wc -c < /run/secrets/kz_storage_verifier_record | tr -d ' ')
[[ "$verifier_record_bytes" =~ ^[1-9][0-9]*$ && "$verifier_record_bytes" -le 1048576 ]] \
  || fail "storage verifier record size is invalid"
verifier_record_sha256=$(sha256sum /run/secrets/kz_storage_verifier_record | awk '{print $1}')
read -r live_mount live_volume_uuid extra_mount_field < <(
  findmnt -n -T "$physical_target" -o TARGET,UUID
)
[[ -n "$live_mount" && -n "$live_volume_uuid" && -z "${extra_mount_field:-}" ]] \
  || fail "backup target live mount identity is unavailable"
[[ "$live_mount" = /* && -d "$live_mount" && ! -L "$live_mount" ]] \
  || fail "backup target live mount is invalid"
physical_mount=$(cd "$live_mount" && pwd -P)
attested_at=$(field attested_at_epoch "$marker")
valid_until=$(field valid_until_epoch "$marker")
now_epoch=$(date -u +%s)
[[ "$(field schema "$marker")" = "kuzet-pilot-backup-target.v1" \
  && "$(field site_id "$marker")" = "$site_id" \
  && "$(field country "$marker")" = "KZ" \
  && "$(field target_path "$marker")" = "$physical_target" \
  && "$(field mount_path "$marker")" = "$physical_mount" \
  && "$(field volume_uuid "$marker")" = "$live_volume_uuid" \
  && "$(field encryption "$marker")" =~ ^(luks2|fscrypt)$ \
  && "$(field verifier_record_sha256 "$marker")" = "$verifier_record_sha256" \
  && "$attested_at" =~ ^[0-9]{1,10}$ && "$valid_until" =~ ^[0-9]{1,10}$ \
  && "$attested_at" -le "$now_epoch" && "$now_epoch" -lt "$valid_until" \
  && "$valid_until" -gt "$attested_at" \
  && $((valid_until - attested_at)) -le "$max_attestation_seconds" ]] \
  || fail "backup target signed attestation is invalid or expired"

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

site_prefix="${prefix%/}"
[[ "${site_prefix##*/}" = "$site_id" ]] \
  || fail "evidence prefix must terminate in the backup site identity"
python3 "$snapshot_helper" \
  --service kuzet_backup \
  --site-id "$site_id" \
  --max-database-bytes "$max_database_bytes" \
  --max-evidence-objects "$max_evidence_objects" \
  --max-manifest-bytes "$max_manifest_bytes" \
  --dump "$stage/database.dump" \
  --metadata "$stage/snapshot-metadata.txt" \
  --evidence-manifest "$stage/database-evidence.tsv"
source_database=$(field source_database "$stage/snapshot-metadata.txt")
schema_revision=$(field schema_revision "$stage/snapshot-metadata.txt")
database_bytes=$(field database_bytes "$stage/snapshot-metadata.txt")
require_identifier "source database" "$source_database"
require_identifier "schema revision" "$schema_revision"
[[ "$database_bytes" =~ ^[1-9][0-9]{0,11}$ && "$database_bytes" -le "$max_database_bytes" ]] \
  || fail "database size exceeds the configured backup bound"
database_dump_bytes=$(wc -c < "$stage/database.dump" | tr -d ' ')
[[ "$database_dump_bytes" =~ ^[1-9][0-9]{0,11}$ && "$database_dump_bytes" -le "$max_database_bytes" ]] \
  || fail "database dump exceeds the configured backup bound"
database_evidence_bytes=$(wc -c < "$stage/database-evidence.tsv" | tr -d ' ')
[[ "$database_evidence_bytes" =~ ^[0-9]+$ && "$database_evidence_bytes" -le "$max_manifest_bytes" ]] \
  || fail "database evidence manifest exceeds the configured bound"

aws --endpoint-url "$endpoint" s3api list-objects-v2 \
  --bucket "$bucket" \
  --prefix "$site_prefix/" \
  --page-size 1000 \
  --max-items "$((max_evidence_objects + 1))" \
  --output json > "$stage/object-inventory.json"
inventory_bytes=$(python3 - "$stage/object-inventory.json" "$stage/inventory.tsv" "$site_prefix/" "$max_evidence_bytes" "$max_evidence_objects" <<'PY'
import json
import re
import sys

inventory_path, canonical_path, prefix, byte_limit, object_limit = sys.argv[1:]
with open(inventory_path, encoding="utf-8") as source:
    inventory = json.load(source)
if (
    inventory.get("IsTruncated") is True
    or inventory.get("NextContinuationToken")
    or inventory.get("NextToken")
):
    raise SystemExit("object inventory pagination was incomplete")
contents = inventory.get("Contents", [])
if not isinstance(contents, list) or len(contents) > int(object_limit):
    raise SystemExit("object inventory exceeds configured bound")
total = 0
rows = {}
for item in contents:
    key = item.get("Key")
    size = item.get("Size")
    etag = item.get("ETag")
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
        or not isinstance(etag, str)
        or not re.fullmatch(r'"[A-Fa-f0-9]{32}(?:-[1-9][0-9]*)?"', etag)
        or suffix in rows
    ):
        raise SystemExit("object inventory is not canonical and site scoped")
    if suffix in {"evidence-files.sha256", ".kuzet-pilot-restored-evidence.v1"}:
        raise SystemExit("object inventory uses a reserved evidence key")
    rows[suffix] = (size, etag)
    total += size
    if total > int(byte_limit):
        raise SystemExit("object inventory exceeds configured byte bound")
with open(canonical_path, "w", encoding="utf-8") as output:
    for suffix, (size, etag) in sorted(rows.items()):
        output.write(f"{size}\t{etag}\t{suffix}\n")
print(total)
PY
)

downloaded_running_bytes=0
while IFS=$'\t' read -r expected_size expected_etag suffix; do
  [[ "$expected_size" =~ ^[0-9]+$ && -n "$expected_etag" && -n "$suffix" ]] \
    || fail "canonical object inventory is invalid"
  destination="$stage/evidence/$suffix"
  mkdir -p -- "$(dirname "$destination")"
  if (( expected_size == 0 )); then
    aws --endpoint-url "$endpoint" s3api head-object \
      --bucket "$bucket" \
      --key "$site_prefix/$suffix" \
      --if-match "$expected_etag" > "$stage/get-object-result.json"
    : > "$destination"
  else
    aws --endpoint-url "$endpoint" s3api get-object \
      --bucket "$bucket" \
      --key "$site_prefix/$suffix" \
      --if-match "$expected_etag" \
      --range "bytes=0-$expected_size" \
      --checksum-mode ENABLED \
      "$destination" > "$stage/get-object-result.json"
  fi
  result_bytes=$(wc -c < "$stage/get-object-result.json" | tr -d ' ')
  [[ "$result_bytes" =~ ^[0-9]+$ && "$result_bytes" -le 65536 ]] \
    || fail "object download response exceeds finite bound"
  actual_size=$(wc -c < "$destination" | tr -d ' ')
  [[ "$actual_size" = "$expected_size" ]] \
    || fail "downloaded evidence object size changed after inventory"
  downloaded_running_bytes=$((downloaded_running_bytes + actual_size))
  (( downloaded_running_bytes <= max_evidence_bytes )) \
    || fail "downloaded evidence exceeds configured bound"
done < "$stage/inventory.tsv"

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
    size, _etag, relative = line.split("\t", 2)
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
python3 - "$stage/database-evidence.tsv" "$stage/evidence/evidence-files.sha256" <<'PY'
import pathlib
import sys

def rows(path):
    result = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        digest, key = line.split(maxsplit=1)
        key = key.removeprefix("*").removeprefix("./")
        if key in result:
            raise SystemExit("evidence manifest contains duplicate keys")
        result[key] = digest
    return result

if rows(sys.argv[1]) != rows(sys.argv[2]):
    raise SystemExit("database evidence manifest does not match downloaded evidence")
PY
tar -C "$stage/evidence" -cf "$stage/evidence.tar" .
max_evidence_archive_bytes=$((max_evidence_bytes + max_evidence_objects * 4096 + 16777216))
evidence_archive_bytes=$(wc -c < "$stage/evidence.tar" | tr -d ' ')
[[ "$evidence_archive_bytes" =~ ^[1-9][0-9]*$ && "$evidence_archive_bytes" -le "$max_evidence_archive_bytes" ]] \
  || fail "evidence archive exceeds the configured backup bound"
config_sha256=$(sha256sum "$stage/config-manifest" | awk '{print $1}')
model_sha256=$(sha256sum "$stage/model-manifest" | awk '{print $1}')
database_evidence_sha256=$(sha256sum "$stage/database-evidence.tsv" | awk '{print $1}')
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
database_evidence_sha256=$database_evidence_sha256
EOF
cat >"$stage/backup-receipt.txt" <<EOF
schema=kuzet-pilot-backup-receipt.v1
site_id=$site_id
created_at=$timestamp
status=pending_fresh_target_restore
EOF

for artifact in database.dump database-evidence.tsv evidence.tar manifest.txt backup-receipt.txt config-manifest model-manifest; do
  age --recipients-file /run/secrets/backup_age_recipient \
    --output "$stage/$artifact.age" "$stage/$artifact"
done
max_database_ciphertext_bytes=$((max_database_bytes + 1048576))
max_manifest_ciphertext_bytes=$((max_manifest_bytes + 1048576))
max_evidence_ciphertext_bytes=$((max_evidence_archive_bytes + 1048576))
database_ciphertext_bytes=$(wc -c < "$stage/database.dump.age" | tr -d ' ')
config_ciphertext_bytes=$(wc -c < "$stage/config-manifest.age" | tr -d ' ')
model_ciphertext_bytes=$(wc -c < "$stage/model-manifest.age" | tr -d ' ')
database_evidence_ciphertext_bytes=$(wc -c < "$stage/database-evidence.tsv.age" | tr -d ' ')
evidence_ciphertext_bytes=$(wc -c < "$stage/evidence.tar.age" | tr -d ' ')
backup_manifest_ciphertext_bytes=$(wc -c < "$stage/manifest.txt.age" | tr -d ' ')
backup_receipt_ciphertext_bytes=$(wc -c < "$stage/backup-receipt.txt.age" | tr -d ' ')
[[ "$database_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$database_ciphertext_bytes" -le "$max_database_ciphertext_bytes" ]] \
  || fail "encrypted database dump exceeds the configured backup bound"
[[ "$config_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$config_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" \
  && "$model_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$model_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" \
  && "$database_evidence_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$database_evidence_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" ]] \
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
    database-evidence.tsv.age \
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
