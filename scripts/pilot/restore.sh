#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  echo "restore refused: $*" >&2
  exit 1
}

field() {
  local key=$1
  local file=$2
  awk -F= -v key="$key" '$1 == key {value=substr($0, length(key) + 2); count++} END {if (count == 1) print value}' "$file"
}

site_id=${PILOT_SITE_ID:-}
source_dir=${PILOT_RESTORE_SOURCE:-}
target_database=${PILOT_RESTORE_DATABASE_NAME:-}
evidence_target=${PILOT_RESTORE_EVIDENCE_TARGET:-}
receipt_target=${PILOT_RESTORE_RECEIPT_TARGET:-}
expected_schema=${PILOT_EXPECTED_SCHEMA_REVISION:-}
expected_config_sha256=${PILOT_EXPECTED_CONFIG_SHA256:-}
expected_model_sha256=${PILOT_EXPECTED_MODEL_SHA256:-}
max_evidence_bytes=${PILOT_RESTORE_MAX_EVIDENCE_BYTES:-10737418240}
max_evidence_objects=${PILOT_RESTORE_MAX_EVIDENCE_OBJECTS:-10000}
max_database_bytes=${PILOT_RESTORE_MAX_DATABASE_BYTES:-10737418240}
max_manifest_bytes=${PILOT_RESTORE_MAX_MANIFEST_BYTES:-16777216}

[[ "$site_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$ ]] || fail "site identity is invalid"
[[ "$source_dir" = /* && "$source_dir" != "/" && -d "$source_dir" && ! -L "$source_dir" ]] \
  || fail "backup source is invalid"
[[ "$(cd "$source_dir" && pwd -P)" = "$source_dir" ]] || fail "backup source traverses symlinks"
[[ "$evidence_target" = /* && "$evidence_target" != "/" && ! -e "$evidence_target" && ! -e "$evidence_target.incomplete" ]] \
  || fail "evidence target must be a separately named fresh path"
[[ "$receipt_target" = /* && "$receipt_target" != "/" && -d "$receipt_target" && ! -L "$receipt_target" ]] \
  || fail "restore receipt target is invalid"
[[ "$(cd "$receipt_target" && pwd -P)" = "$receipt_target" ]] || fail "receipt target traverses symlinks"
[[ "$target_database" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$ ]] \
  || fail "fresh restore database name is invalid"
[[ "$expected_schema" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$ ]] \
  || fail "expected schema revision is invalid"
[[ "$expected_config_sha256" =~ ^[a-f0-9]{64}$ && "$expected_model_sha256" =~ ^[a-f0-9]{64}$ ]] \
  || fail "expected configuration/model hashes are invalid"
[[ "$max_evidence_bytes" =~ ^[1-9][0-9]*$ && "$max_evidence_bytes" -le 107374182400 ]] \
  || fail "restore bound is invalid"
[[ "$max_evidence_objects" =~ ^[1-9][0-9]*$ && "$max_evidence_objects" -le 100000 ]] \
  || fail "restore object bound is invalid"
[[ "$max_database_bytes" =~ ^[1-9][0-9]*$ && "$max_database_bytes" -le 107374182400 ]] \
  || fail "restore database bound is invalid"
[[ "$max_manifest_bytes" =~ ^[1-9][0-9]*$ && "$max_manifest_bytes" -le 67108864 ]] \
  || fail "restore manifest bound is invalid"

parent=$(dirname "$evidence_target")
[[ -d "$parent" && ! -L "$parent" && "$(cd "$parent" && pwd -P)" = "$parent" ]] \
  || fail "evidence target parent is invalid"
volume_marker="$parent/.kuzet-pilot-encrypted-volume.v1"
expected_volume_marker=$(printf 'schema=kuzet-pilot-encrypted-volume.v1\nsite_id=%s\ncountry=KZ\nencrypted=true\n' "$site_id")
[[ -f "$volume_marker" && ! -L "$volume_marker" && "$(<"$volume_marker")" = "$expected_volume_marker" ]] \
  || fail "encrypted Kazakhstan evidence marker is invalid"
[[ -f "$volume_marker.sig" && ! -L "$volume_marker.sig" ]] \
  || fail "encrypted evidence marker signature is missing"
receipt_marker="$receipt_target/.kuzet-pilot-restore-receipts.v1"
[[ -f "$receipt_marker" && ! -L "$receipt_marker" ]] || fail "restore receipt marker is missing"
[[ -f "$receipt_marker.sig" && ! -L "$receipt_marker.sig" ]] \
  || fail "restore receipt marker signature is missing"
[[ "$(<"$receipt_marker")" = "schema=kuzet-pilot-restore-receipts.v1"$'\n'"site_id=$site_id" ]] \
  || fail "restore receipt marker is invalid"

for secret_name in pg_restore_service.conf pgpass backup_age_identity backup_age_recipient backup_signing_public_key kz_storage_attestation_public_key; do
  [[ -f "/run/secrets/$secret_name" && ! -L "/run/secrets/$secret_name" ]] \
    || fail "required Docker secret is unavailable"
done
for tool in age cmp openssl pg_restore psql python3 sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "required restore tool is unavailable"
done
openssl dgst -sha256 -verify /run/secrets/kz_storage_attestation_public_key -signature "$volume_marker.sig" "$volume_marker" >/dev/null \
  || fail "encrypted evidence attestation signature is invalid"
openssl dgst -sha256 -verify /run/secrets/kz_storage_attestation_public_key -signature "$receipt_marker.sig" "$receipt_marker" >/dev/null \
  || fail "restore receipt attestation signature is invalid"
for artifact in database.dump.age evidence.tar.age manifest.txt.age backup-receipt.txt.age config-manifest.age model-manifest.age checksums.sha256 checksums.sha256.sig; do
  [[ -f "$source_dir/$artifact" && ! -L "$source_dir/$artifact" ]] \
    || fail "backup artifact is missing"
done
source_entry_count=$(find "$source_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
[[ "$source_entry_count" = "8" ]] || fail "backup source contains unexpected artifacts"
checksum_manifest_bytes=$(wc -c < "$source_dir/checksums.sha256" | tr -d ' ')
checksum_signature_bytes=$(wc -c < "$source_dir/checksums.sha256.sig" | tr -d ' ')
[[ "$checksum_manifest_bytes" =~ ^[1-9][0-9]*$ && "$checksum_manifest_bytes" -le 8192 ]] \
  || fail "backup checksum manifest size is invalid"
[[ "$checksum_signature_bytes" =~ ^[1-9][0-9]*$ && "$checksum_signature_bytes" -le 16384 ]] \
  || fail "backup checksum signature size is invalid"
openssl dgst -sha256 \
  -verify /run/secrets/backup_signing_public_key \
  -signature "$source_dir/checksums.sha256.sig" \
  "$source_dir/checksums.sha256" >/dev/null \
  || fail "backup checksum signature is invalid"

checksum_names=$(awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[a-f0-9]+$/ {exit 2}
  {name=$2; sub(/^\*/, "", name); print name}
' "$source_dir/checksums.sha256" | LC_ALL=C sort) || fail "checksum manifest is invalid"
expected_names=$(printf '%s\n' \
  backup-receipt.txt.age config-manifest.age database.dump.age evidence.tar.age \
  manifest.txt.age model-manifest.age | LC_ALL=C sort)
[[ "$checksum_names" = "$expected_names" ]] || fail "checksum manifest contains unexpected artifacts"
max_database_ciphertext_bytes=$((max_database_bytes + 1048576))
max_manifest_ciphertext_bytes=$((max_manifest_bytes + 1048576))
max_evidence_archive_bytes=$((max_evidence_bytes + max_evidence_objects * 4096 + 16777216))
max_evidence_ciphertext_bytes=$((max_evidence_archive_bytes + 1048576))
database_ciphertext_bytes=$(wc -c < "$source_dir/database.dump.age" | tr -d ' ')
config_ciphertext_bytes=$(wc -c < "$source_dir/config-manifest.age" | tr -d ' ')
model_ciphertext_bytes=$(wc -c < "$source_dir/model-manifest.age" | tr -d ' ')
evidence_ciphertext_bytes=$(wc -c < "$source_dir/evidence.tar.age" | tr -d ' ')
backup_manifest_ciphertext_bytes=$(wc -c < "$source_dir/manifest.txt.age" | tr -d ' ')
backup_receipt_ciphertext_bytes=$(wc -c < "$source_dir/backup-receipt.txt.age" | tr -d ' ')
[[ "$database_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$database_ciphertext_bytes" -le "$max_database_ciphertext_bytes" ]] \
  || fail "encrypted database dump exceeds the configured restore bound"
[[ "$config_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$config_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" \
  && "$model_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$model_ciphertext_bytes" -le "$max_manifest_ciphertext_bytes" ]] \
  || fail "encrypted configuration/model manifest exceeds the configured restore bound"
[[ "$evidence_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$evidence_ciphertext_bytes" -le "$max_evidence_ciphertext_bytes" ]] \
  || fail "encrypted evidence archive exceeds the configured restore bound"
[[ "$backup_manifest_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$backup_manifest_ciphertext_bytes" -le 1048576 \
  && "$backup_receipt_ciphertext_bytes" =~ ^[1-9][0-9]*$ && "$backup_receipt_ciphertext_bytes" -le 1048576 ]] \
  || fail "encrypted backup metadata exceeds the finite size bound"
(
  cd "$source_dir"
  sha256sum --check checksums.sha256
)

stage=$(mktemp -d "$parent/.restore-staging.XXXXXX")
incomplete="$evidence_target.incomplete"
receipt_incomplete=
trap 'rm -rf -- "$stage" "$incomplete"; if [[ -n ${receipt_incomplete:-} ]]; then rm -rf -- "$receipt_incomplete"; fi' EXIT
for artifact in database.dump evidence.tar manifest.txt backup-receipt.txt config-manifest model-manifest; do
  age --decrypt --identity /run/secrets/backup_age_identity \
    --output "$stage/$artifact" "$source_dir/$artifact.age"
done
database_dump_bytes=$(wc -c < "$stage/database.dump" | tr -d ' ')
config_manifest_bytes=$(wc -c < "$stage/config-manifest" | tr -d ' ')
model_manifest_bytes=$(wc -c < "$stage/model-manifest" | tr -d ' ')
evidence_archive_bytes=$(wc -c < "$stage/evidence.tar" | tr -d ' ')
backup_manifest_bytes=$(wc -c < "$stage/manifest.txt" | tr -d ' ')
backup_receipt_bytes=$(wc -c < "$stage/backup-receipt.txt" | tr -d ' ')
[[ "$database_dump_bytes" =~ ^[1-9][0-9]*$ && "$database_dump_bytes" -le "$max_database_bytes" ]] \
  || fail "decrypted database dump exceeds the configured restore bound"
[[ "$config_manifest_bytes" =~ ^[1-9][0-9]*$ && "$config_manifest_bytes" -le "$max_manifest_bytes" \
  && "$model_manifest_bytes" =~ ^[1-9][0-9]*$ && "$model_manifest_bytes" -le "$max_manifest_bytes" ]] \
  || fail "decrypted configuration/model manifest exceeds the configured restore bound"
[[ "$evidence_archive_bytes" =~ ^[1-9][0-9]*$ && "$evidence_archive_bytes" -le "$max_evidence_archive_bytes" ]] \
  || fail "decrypted evidence archive exceeds the configured restore bound"
[[ "$backup_manifest_bytes" =~ ^[1-9][0-9]*$ && "$backup_manifest_bytes" -le 65536 \
  && "$backup_receipt_bytes" =~ ^[1-9][0-9]*$ && "$backup_receipt_bytes" -le 65536 ]] \
  || fail "decrypted backup metadata exceeds the finite size bound"

manifest_site=$(field site_id "$stage/manifest.txt")
source_database=$(field source_database "$stage/manifest.txt")
schema_revision=$(field schema_revision "$stage/manifest.txt")
country=$(field country "$stage/manifest.txt")
declared_evidence_bytes=$(field evidence_bytes "$stage/manifest.txt")
config_sha256=$(field config_sha256 "$stage/manifest.txt")
model_sha256=$(field model_sha256 "$stage/manifest.txt")
receipt_status=$(field status "$stage/backup-receipt.txt")
[[ "$manifest_site" = "$site_id" ]] || fail "backup site does not match restore site"
[[ "$country" = "KZ" ]] || fail "backup residency boundary is invalid"
[[ "$receipt_status" = "pending_fresh_target_restore" ]] || fail "backup receipt state is invalid"
[[ "$schema_revision" = "$expected_schema" ]] || fail "backup schema revision is not accepted"
[[ "$config_sha256" = "$expected_config_sha256" && "$model_sha256" = "$expected_model_sha256" ]] \
  || fail "backup configuration/model hashes do not match"
restored_config_sha256=$(sha256sum "$stage/config-manifest" | awk '{print $1}')
restored_model_sha256=$(sha256sum "$stage/model-manifest" | awk '{print $1}')
[[ "$restored_config_sha256" = "$config_sha256" && "$restored_config_sha256" = "$expected_config_sha256" \
  && "$restored_model_sha256" = "$model_sha256" && "$restored_model_sha256" = "$expected_model_sha256" ]] \
  || fail "configuration/model manifest integrity verification failed"
[[ "$source_database" != "$target_database" ]] || fail "restore database must differ from source"
[[ "$declared_evidence_bytes" =~ ^[0-9]+$ && "$declared_evidence_bytes" -le "$max_evidence_bytes" ]] \
  || fail "backup evidence bound is invalid"
pg_restore --list "$stage/database.dump" >/dev/null

python3 - "$stage/evidence.tar" "$max_evidence_bytes" "$max_evidence_objects" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
object_limit = int(sys.argv[3])
total = 0
with tarfile.open(archive) as source:
    members = source.getmembers()
    if len(members) > object_limit * 4 + 16:
        raise SystemExit("evidence archive exceeds member bound")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or len(path.parts) > 32
            or path.name == ".kuzet-pilot-restored-evidence.v1"
            or not (member.isdir() or member.isfile())
        ):
            raise SystemExit("unsafe evidence archive")
        total += member.size
        if total > limit + 8_388_608:
            raise SystemExit("evidence archive exceeds configured bound")
PY

export PGSERVICEFILE=/run/secrets/pg_restore_service.conf
export PGPASSFILE=/run/secrets/pgpass
actual_database=$(psql "service=kuzet_restore" -X -A -t -c 'SELECT current_database()')
[[ "$actual_database" = "$target_database" ]] || fail "restore service does not target requested database"
table_count=$(psql "service=kuzet_restore" -X -A -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
[[ "$table_count" = "0" ]] || fail "restore database is not fresh and empty"

mkdir -m 0700 "$incomplete"
tar -C "$incomplete" --no-same-owner --no-same-permissions -xf "$stage/evidence.tar"
python3 - "$incomplete" "$declared_evidence_bytes" "$max_evidence_objects" <<'PY'
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
declared_bytes = int(sys.argv[2])
object_limit = int(sys.argv[3])
checksum_path = root / "evidence-files.sha256"
if not checksum_path.is_file() or checksum_path.is_symlink():
    raise SystemExit("evidence checksum manifest is missing")
expected = {}
for line in checksum_path.read_text(encoding="utf-8").splitlines():
    fields = line.split(maxsplit=1)
    if len(fields) != 2:
        raise SystemExit("evidence checksum manifest is invalid")
    digest, raw_path = fields
    raw_path = raw_path.removeprefix("*")
    if not raw_path.startswith("./"):
        raise SystemExit("evidence checksum path is not canonical")
    relative = raw_path[2:]
    parts = relative.split("/")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}", relative)
        or any(part in {"", ".", ".."} for part in parts)
        or not re.fullmatch(r"[a-f0-9]{64}", digest)
        or relative in expected
    ):
        raise SystemExit("evidence checksum manifest is invalid")
    expected[relative] = digest
if len(expected) > object_limit:
    raise SystemExit("evidence checksum manifest exceeds object bound")

actual = {}
payload_bytes = 0
for path in root.rglob("*"):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not (
        stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
    ):
        raise SystemExit("restored evidence contains an unsafe entry")
    if not path.resolve(strict=True).is_relative_to(root):
        raise SystemExit("restored evidence escaped staging")
    if stat.S_ISREG(metadata.st_mode) and path != checksum_path:
        relative = path.relative_to(root).as_posix()
        actual[relative] = metadata.st_size
        payload_bytes += metadata.st_size
if set(actual) != set(expected):
    raise SystemExit("restored evidence file set does not match checksum manifest")
if payload_bytes != declared_bytes:
    raise SystemExit("restored evidence bytes do not match backup manifest")
PY
(
  cd "$incomplete"
  sha256sum --check evidence-files.sha256
)
pg_restore \
  --dbname=service=kuzet_restore \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-acl \
  "$stage/database.dump"
restored_schema=$(psql "service=kuzet_restore" -X -A -t -c 'SELECT version_num FROM alembic_version')
restored_site=$(psql "service=kuzet_restore" -X -A -t -c "SELECT site_id FROM sites WHERE site_id = '$site_id'")
[[ "$restored_schema" = "$schema_revision" && "$restored_site" = "$site_id" ]] \
  || fail "restored database integrity verification failed"
printf 'schema=kuzet-pilot-restored-evidence.v1\nsite_id=%s\n' "$site_id" \
  > "$incomplete/.kuzet-pilot-restored-evidence.v1"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
cat >"$stage/restore-drill-receipt.txt" <<EOF
schema=kuzet-pilot-restore-drill-receipt.v1
site_id=$site_id
schema_revision=$schema_revision
source_backup=$(basename "$source_dir")
target_database=$target_database
restored_at=$timestamp
status=verified_fresh_target_restore
EOF
receipt_bundle_name="restore-drill-$timestamp"
receipt_bundle="$receipt_target/$receipt_bundle_name"
receipt_incomplete="$receipt_bundle.incomplete"
[[ ! -e "$receipt_bundle" && ! -e "$receipt_incomplete" ]] || fail "restore receipt already exists"
mkdir -m 0700 "$receipt_incomplete"
receipt_name="restore-drill-receipt.age"
receipt="$receipt_incomplete/$receipt_name"
age --recipients-file /run/secrets/backup_age_recipient \
  --output "$receipt" "$stage/restore-drill-receipt.txt"
(
  cd "$receipt_incomplete"
  sha256sum "$receipt_name" > "$receipt_name.sha256"
)
age --decrypt --identity /run/secrets/backup_age_identity \
  --output "$stage/restore-drill-receipt.verify" "$receipt"
cmp -s "$stage/restore-drill-receipt.txt" "$stage/restore-drill-receipt.verify" \
  || fail "encrypted restore receipt verification failed"
mv "$incomplete" "$evidence_target"
mv "$receipt_incomplete" "$receipt_bundle"
echo "fresh-target restore verified; encrypted restore-drill-receipt created"
