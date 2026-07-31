# Controlled-pilot deployment runbook

Status: **PENDING implementation review and external execution**. This
repository packages contracts and target commands; it does not claim a CUDA,
DeepStream, TensorRT, 8-hour, 72-hour, or exact-20-camera result.

## Authority and activation boundary

This runbook coordinates, but does not replace:

- [Ready-to-Start](../../docs/pilot/ready_to_start.md)
- [Target acceptance](../../deploy/pilot/TARGET_ACCEPTANCE.md)
- [Network policy](../../deploy/pilot/NETWORK_POLICY.md)
- [Audit retention](../../deploy/pilot/AUDIT_RETENTION.md)

Use a fresh target campaign whenever the host, image, configuration, model or
engine, exact 20-source manifest, network identity, mount contract, or frozen
workload changes. Every alert remains a candidate until human confirmation.
There are no automatic police, fire-system, or door actions.

The base Compose file is the core control plane. Optional authority and egress
surfaces are selected only with these explicit overlays:

| Surface | Compose overlay | Service | Default |
|---|---|---|---|
| Shared NVIDIA runtime | `docker-compose.runtime.yml` | `runtime` | absent |
| Target acceptance V3 | `docker-compose.acceptance.yml` | `acceptance-controller` | absent |
| Approved Telegram delivery | `docker-compose.telegram.yml` | `notifications` | absent |
| Encrypted backup | `docker-compose.backup.yml` | `backup` | absent |
| Fresh-target restore drill | `docker-compose.restore.yml` | `restore` | absent |
| First administrator | `docker-compose.admin.yml` | `admin-bootstrap` | absent |

Compose interpolates all selected files before profile filtering. Do not add
acceptance or notification variables back to the base file.

## Target preflight

1. Provision Linux/amd64 NVIDIA hardware and verify the driver, container
   toolkit, Docker Engine/Compose, DeepStream/CUDA/TensorRT compatibility, NTP,
   DNS, TLS, PostgreSQL, and Kazakhstan-resident bounded storage.
2. Complete the signed manifest for exactly 20 lawful named streams or frozen
   replay fixtures. Continuous raw video remains in the customer NVR.
3. Complete model rights, artifact and engine hashes, source/site quality
   matrices, measured capacity, privacy approval, named operators, and
   exception ownership. Any missing input fails closed.
4. Pre-create the control/storage directories and every bind-mounted file.
   `create_host_path: false` is intentional. The runtime spool, journal, and
   preview paths must be encrypted, quota-bounded, monitored, and attested;
   a normal host directory is not sufficient.
5. Create the camera, storage, and—only if approved—notification networks
   exactly as described in `NETWORK_POLICY.md`.
6. Install secrets from the approved secret manager. Never place a password,
   private key, RTSP URI, object-store credential, TOTP seed, or bot token in
   an environment variable, Compose file, image, or command history.
7. Record the source commit, every final image digest, configuration and mount
   hashes, migration revision, and reviewers in
   [handover_manifest.md](handover_manifest.md).

On the target host, record the one reviewed GPU and software boundary. The
first command is deliberately a target-only gate, not a container build step:

```bash
nvidia-smi --query-gpu=uuid,driver_version --format=csv,noheader
nvidia-ctk --version
docker version
docker compose version
```

Set `PILOT_RUNTIME_GPU_UUID` to exactly the reviewed GPU UUID. Archive these
outputs, the container-toolkit configuration, and the rendered one-device
Compose request. A different UUID, driver, toolkit, or device count invalidates
capacity and acceptance.

## Build and pin images

Run these commands on the reviewed Linux/amd64 build host. `PILOT_*_IMAGE_TAG`
is a temporary immutable build tag; deployment uses the registry-resolved
content digest, never the tag.

```bash
docker buildx build \
  --platform linux/amd64 \
  --file deploy/pilot/Dockerfile.api \
  --tag "${PILOT_API_IMAGE_REPOSITORY}:${PILOT_API_IMAGE_TAG}" \
  --provenance=true \
  --sbom=true \
  --push .

docker buildx build \
  --platform linux/amd64 \
  --file deploy/pilot/Dockerfile.runtime \
  --build-arg "KUZET_RUNTIME_CODE_SHA256=${PILOT_RUNTIME_CODE_SHA256}" \
  --tag "${PILOT_RUNTIME_IMAGE_REPOSITORY}:${PILOT_RUNTIME_IMAGE_TAG}" \
  --provenance=true \
  --sbom=true \
  --push .

docker buildx build \
  --platform linux/amd64 \
  --file deploy/pilot/Dockerfile.ops \
  --tag "${PILOT_OPS_IMAGE_REPOSITORY}:${PILOT_OPS_IMAGE_TAG}" \
  --provenance=true \
  --sbom=true \
  --push .

docker buildx imagetools inspect \
  "${PILOT_API_IMAGE_REPOSITORY}:${PILOT_API_IMAGE_TAG}"
docker buildx imagetools inspect \
  "${PILOT_RUNTIME_IMAGE_REPOSITORY}:${PILOT_RUNTIME_IMAGE_TAG}"
docker buildx imagetools inspect \
  "${PILOT_OPS_IMAGE_REPOSITORY}:${PILOT_OPS_IMAGE_TAG}"
```

Copy only the reviewed linux/amd64 `sha256:` values into the deployment
environment and handover manifest. Archive and hash the immutable
`/usr/share/kuzet/*-package-versions.txt`,
`/usr/share/kuzet/*-tool-versions.txt`, and adjacent checksum files from the
built images. The operations Python dependency subset is hash-locked in
`deploy/pilot/ops-requirements.lock`; the final content digest and SBOM bind
the Debian package versions recorded during the pinned-base build. Image build
and inspection are **PENDING**.

For each rights-cleared ONNX artifact, a bounded target-only audit/build/audit
sequence is required. **MODEL ENGINE BUILD BLOCKED:** this revision does not
package a digest-pinned builder image or an exact in-container entrypoint and
read-only mount contract for `model_audit.py`, `build_engine.py`, TensorRT, the
input artifact, and new output receipts. A host-side `uv` command must not be
presented as though it executes inside the reviewed DeepStream/TensorRT image.

Before this gate can become runnable, implementation review must freeze the
builder image digest, exact executable and arguments, input/output mounts,
non-root identity, network isolation, timeout and byte limits, TensorRT
version, and atomic non-overwriting receipt publication. INT8 must additionally
bind the exact signed calibration cache; omitting it is not a fallback. The
resulting export audit, engine, build receipt, deployment audit, and their
SHA-256 values remain **PENDING**. None of these model-build artifacts or
commands is capacity acceptance.

The exact pending 20-source NVIDIA runtime command and its mount/fixture list
are the complete `Build and record the local image identity` and `Create the
runtime stopped` command blocks in
[`TARGET_ACCEPTANCE.md`](../../deploy/pilot/TARGET_ACCEPTANCE.md). Do not
abbreviate or copy only the final `docker start`. That raw launch is the sole
authoritative pending runtime launch. The Compose runtime overlay is
a render-only packaging template and cannot be activated in this revision.
The exact 8-hour and 72-hour commands are intentionally unavailable because
of the acceptance blocker documented below.

## Render every selected configuration

Create a reviewed environment file outside the repository and source it
without printing it. These commands are the mandatory static Compose gates:

```bash
docker compose \
  -f deploy/pilot/docker-compose.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.runtime.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.acceptance.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.telegram.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.backup.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.restore.yml \
  config --quiet

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.admin.yml \
  config --quiet
```

After every quiet gate succeeds, render each selected file set into its own new
private receipt directory. The redactor preserves service names, logical
secret identifiers, secret-file paths, mounts, networks, limits, and arguments,
but replaces direct sensitive values and URI user information. It publishes
the redacted inventory atomically, deletes the unredacted temporary file, and
hashes only the redacted artifact:

```bash
set -euo pipefail
umask 077
export PILOT_COMPOSE_CAMPAIGN_ID=REPLACE_WITH_EXACT_SIGNED_CAMPAIGN_ID
case "${PILOT_COMPOSE_CAMPAIGN_ID}" in
  ""|"."|".."|*REPLACE_WITH*|*[!A-Za-z0-9._-]*)
    echo "unsafe or unresolved signed Compose campaign ID" >&2
    exit 1
    ;;
esac
export PILOT_COMPOSE_RECEIPT_ROOT=\
"/srv/kuzet/deployment-receipts/${PILOT_COMPOSE_CAMPAIGN_ID}/compose"
test ! -e "${PILOT_COMPOSE_RECEIPT_ROOT}"
install -d -m 0700 "${PILOT_COMPOSE_RECEIPT_ROOT}"

render_compose_receipt() {
  label="$1"
  shift
  receipt_dir="${PILOT_COMPOSE_RECEIPT_ROOT}/${label}"
  test ! -e "${receipt_dir}"
  install -d -m 0700 "${receipt_dir}"
  raw_path="${receipt_dir}/compose-render.raw.json"
  redacted_path="${receipt_dir}/compose-render.redacted.json"

  docker compose "$@" config --format json >"${raw_path}"
  python3 - \
    "${raw_path}" \
    "${redacted_path}" \
    "${PILOT_COMPOSE_CAMPAIGN_ID}" <<'PY'
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


raw_path = Path(sys.argv[1])
redacted_path = Path(sys.argv[2])
sensitive = re.compile(
    r"(?:^|_)(?:password|passwd|secret|token|credential|private_?key|"
    r"rtsp_?url)(?:$|_)",
    re.IGNORECASE,
)
safe_suffixes = ("_FILE", "_PATH", "_DIR", "_NAME", "_ID", "_SHA256")


def sensitive_key(key: str) -> bool:
    upper = key.upper()
    return bool(sensitive.search(key)) and not upper.endswith(safe_suffixes)


def redact_uri(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or parsed.hostname is None or parsed.username is None:
        return value
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme, f"[REDACTED]@{host}", parsed.path, parsed.query, parsed.fragment)
    )


def redact(value: object) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if sensitive_key(key) and isinstance(item, (str, int, float, bool)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        result: list[object] = []
        for item in value:
            if isinstance(item, str) and "=" in item:
                key, item_value = item.split("=", 1)
                if sensitive_key(key):
                    result.append(f"{key}=[REDACTED]")
                    continue
                result.append(f"{key}={redact_uri(item_value)}")
                continue
            result.append(redact(item))
        return result
    if isinstance(value, str):
        return redact_uri(value)
    return value


temporary = redacted_path.with_suffix(".json.tmp")
try:
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    rendered = json.dumps(
        {
            "campaign_id": sys.argv[3],
            "compose": redact(payload),
            "schema": "kuzet.compose-render-receipt.v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as target:
        target.write(rendered)
        target.write(b"\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, redacted_path)
finally:
    raw_path.unlink(missing_ok=True)
    if temporary.exists():
        temporary.unlink()
PY
  test ! -e "${raw_path}"
  sha256sum "${redacted_path}" \
    >"${receipt_dir}/compose-render.redacted.sha256"
}

render_compose_receipt base \
  -f deploy/pilot/docker-compose.yml
render_compose_receipt runtime \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.runtime.yml
render_compose_receipt acceptance \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.acceptance.yml
render_compose_receipt telegram \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.telegram.yml
render_compose_receipt backup \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.backup.yml
render_compose_receipt restore \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.restore.yml
render_compose_receipt admin \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.admin.yml
```

Review each redacted inventory before signing it; fail the gate if any literal
secret remains or any required identity, mount, network, limit, or service
argument was removed. `PILOT_COMPOSE_CAMPAIGN_ID` must be the exact identifier
from the reviewed signed campaign record. The same validated value names the
receipt directory and is embedded in every canonical redacted document before
its digest is calculated. Compose rendering and review are **PENDING** in this
cloud environment because Docker is unavailable.

## Migrate, provision, and start the core

The migration, API, runtime-writer, and retention identities are distinct.
`role-bootstrap` creates the non-owner `kuzet_runtime` login before migrations
so reviewed migrations can grant only their bounded runtime functions and
read surfaces. It receives no blanket table or sequence DML. Run one-shot jobs
in order and stop on any non-zero result. `configs/pilot.example.yaml` is a
non-deployable template because it contains environment-secret references;
never copy it onto a pilot host. Install only a reviewed site configuration
whose exact bytes were approved and hashed:

For an upgrade of an existing pilot, stop intake and notification delivery
first. Record the current database revision, source commit, image/config/model/
engine digests, latest audit identity, and bounded object-version inventory.
Then run the exact encrypted **Backup** and **Fresh-target restore drill**
blocks below against the pre-change state. The signed restore receipt must end
in `status=verified_fresh_target_restore` before migration is authorized.
Apply the candidate migration to that restored fresh target first, verify the
target revision and every role/health/audit probe in this section, and archive
the redacted migration output plus its SHA-256. An empty first installation
still needs a disposable-target migration and role probe, but has no pre-change
customer database to back up.

```bash
test -f "${PILOT_REVIEWED_SITE_CONFIG_SOURCE}"
test ! -L "${PILOT_REVIEWED_SITE_CONFIG_SOURCE}"
test "$(sha256sum "${PILOT_REVIEWED_SITE_CONFIG_SOURCE}" | awk '{print $1}')" \
  = "${PILOT_SITE_CONFIG_SHA256}"
sudo install --owner=root --group=root --mode=0440 \
  "${PILOT_REVIEWED_SITE_CONFIG_SOURCE}" /etc/kuzet/pilot.yaml
test "$(sha256sum /etc/kuzet/pilot.yaml | awk '{print $1}')" \
  = "${PILOT_SITE_CONFIG_SHA256}"
export PILOT_SITE_CONFIG_PATH=/etc/kuzet/pilot.yaml

uv run python scripts/pilot/provision.py --help
uv run python scripts/pilot/validate_runtime_mounts.py --help

docker compose -f deploy/pilot/docker-compose.yml up -d postgres
docker compose -f deploy/pilot/docker-compose.yml run --rm role-bootstrap
docker compose -f deploy/pilot/docker-compose.yml run --rm migrate
docker compose -f deploy/pilot/docker-compose.yml run --rm role-grants
docker compose -f deploy/pilot/docker-compose.yml run --rm provision
docker compose -f deploy/pilot/docker-compose.yml \
  up -d api tls-proxy prometheus
```

The `migrate` job invokes `/app/scripts/pilot/migrate.py`; provisioning invokes
`/app/scripts/pilot/provision.py`. Verify migration revision, role grants,
health/readiness, audit continuity, bounded object-store access, and the
published configuration hashes before continuing.

The expected migration head for this handover is
`0008_runtime_persistence`. Use a root-owned libpq service file containing
named `kuzet_admin`, `kuzet_api`, `kuzet_runtime`, and `kuzet_retention`
connections; do not put database URLs or passwords in shell history. After
`role-grants`, run these exact target probes and archive their output:

```bash
export PGSERVICEFILE=/srv/kuzet/secrets/pilot-role-probes.pg_service.conf
test "$(stat -c %a "${PGSERVICEFILE}")" = 600

test "$(
  psql "service=kuzet_admin" -X -v ON_ERROR_STOP=1 -Atc \
    'SELECT version_num FROM alembic_version'
)" = "0008_runtime_persistence"

psql "service=kuzet_admin" -X -v ON_ERROR_STOP=1 <<'SQL'
SELECT role.rolname,
       role.rolcanlogin,
       role.rolsuper,
       role.rolcreatedb,
       role.rolcreaterole,
       role.rolinherit,
       role.rolreplication,
       role.rolbypassrls,
       (SELECT count(*) FROM pg_auth_members membership
         WHERE membership.member = role.oid
            OR membership.roleid = role.oid) AS membership_edges,
       (SELECT count(*) FROM pg_database item
         WHERE item.datdba = role.oid)
       + (SELECT count(*) FROM pg_namespace item
           WHERE item.nspowner = role.oid)
       + (SELECT count(*) FROM pg_class item
           WHERE item.relowner = role.oid)
       + (SELECT count(*) FROM pg_proc item
           WHERE item.proowner = role.oid) AS owned_objects
  FROM pg_roles role
 WHERE role.rolname IN ('kuzet_api', 'kuzet_runtime', 'kuzet_retention')
 ORDER BY role.rolname;

DO $probe$
DECLARE
  invalid_roles text;
BEGIN
  SELECT string_agg(role.rolname, ',' ORDER BY role.rolname)
    INTO invalid_roles
    FROM pg_roles role
   WHERE role.rolname IN ('kuzet_api', 'kuzet_runtime', 'kuzet_retention')
     AND (
       NOT role.rolcanlogin
       OR role.rolsuper
       OR role.rolcreatedb
       OR role.rolcreaterole
       OR role.rolinherit
       OR role.rolreplication
       OR role.rolbypassrls
       OR EXISTS (
         SELECT 1 FROM pg_auth_members membership
          WHERE membership.member = role.oid
             OR membership.roleid = role.oid
       )
       OR EXISTS (SELECT 1 FROM pg_database item WHERE item.datdba = role.oid)
       OR EXISTS (SELECT 1 FROM pg_namespace item WHERE item.nspowner = role.oid)
       OR EXISTS (SELECT 1 FROM pg_class item WHERE item.relowner = role.oid)
       OR EXISTS (SELECT 1 FROM pg_proc item WHERE item.proowner = role.oid)
     );
  IF invalid_roles IS NOT NULL THEN
    RAISE EXCEPTION 'unsafe service roles: %', invalid_roles;
  END IF;
END
$probe$;
SQL

for role in kuzet_api kuzet_runtime kuzet_retention; do
  test "$(
    psql "service=${role}" -X -v ON_ERROR_STOP=1 -Atc \
      'SELECT session_user || chr(58) || current_user'
  )" = "${role}:${role}"
  if psql "service=${role}" -X -v ON_ERROR_STOP=1 \
      -c 'SET ROLE kuzet_owner'; then
    echo "${role} unexpectedly acquired kuzet_owner" >&2
    exit 1
  fi
done
```

`NOINHERIT` is not sufficient: a direct membership still permits explicit
`SET ROLE`. Any membership, ownership, privileged flag, identity mismatch, or
successful negative probe blocks activation. Re-run this probe after every
migration/grant change and include its digest in the handover manifest.

The retention service receives the reviewed storage region explicitly and
runs registered-preview retirement plus orphan reconciliation in finite
batches. The packaged `--preview-batch-size=1000` applies independently to
registered retirement and orphan-version listing/deletion; the publication
grace is `--preview-publication-grace-seconds=900`. Changing either value or the
`PILOT_RETENTION_OBJECT_STORE_REGION` identity requires a reviewed Compose
change and fresh negative delete/versioning probes.

The `retention_database_url` must authenticate as `kuzet_retention` on both
its singleton-lock connection and its pooled repository connections. Owner,
migrator, API, and runtime URLs are invalid substitutes. The service verifies
both `session_user` and `current_user` before taking the advisory lock or
reading active configuration.

Before starting it, archive the exact retention identity policy and probes.
The bucket permissions are only `s3:GetBucketVersioning`,
`s3:GetLifecycleConfiguration`, and prefix-conditioned
`s3:ListBucketVersions`. The evidence prefix permissions are only
`s3:GetObjectVersion` and `s3:DeleteObjectVersion`; the separate archive
prefix additionally permits only `s3:GetObject` and `s3:PutObject`.
The full evidence-prefix lifecycle must match the reviewed retention days and
`NoncurrentDays=1`; the filter/expiration/noncurrent mappings must contain no
tag, size, `NewerNoncurrentVersions`, or other narrowing field. Prove
exact-version checksum lookup/deletion and
post-delete absence, and prove denial of simple `s3:DeleteObject`, evidence
writes, archive deletes, cross-prefix access, and lifecycle/versioning/ACL
mutation. With `aws:kms`, scope `kms:Decrypt` and `kms:GenerateDataKey` to the
one reviewed key and only the permitted read/write paths.

### Immutable-write and lifecycle probes

The application sends `If-None-Match: *`, but application intent alone does
not prevent an altered client from overwriting an object. The reviewed
bucket/resource policy must enforce the provider's exact equivalent of the
`s3:if-none-match` `*` condition for every runtime evidence write, runtime
preview write, and retention audit-archive write. Archive the effective
policy and provider documentation. If the Kazakhstan S3-compatible provider
cannot enforce and audit equivalent atomic and policy semantics, storage
acceptance is **BLOCKED**.

Use separate least-privilege AWS CLI profiles in root-owned configuration.
The profile names below are logical identities, not shared credentials. Run
the probes only in a dedicated signed site/campaign prefix:

```bash
set -euo pipefail
export AWS_CONFIG_FILE=/srv/kuzet/secrets/pilot-storage-probes.awsconfig
export AWS_SHARED_CREDENTIALS_FILE=/srv/kuzet/secrets/pilot-storage-probes.credentials
export PILOT_S3_ENDPOINT=REPLACE_WITH_REVIEWED_KAZAKHSTAN_HTTPS_ENDPOINT
export PILOT_S3_REGION=REPLACE_WITH_REVIEWED_KAZAKHSTAN_REGION
export PILOT_S3_BUCKET=REPLACE_WITH_REVIEWED_BUCKET
export PILOT_EVIDENCE_PREFIX=REPLACE_WITH_REVIEWED_EVIDENCE_PREFIX
export PILOT_PREVIEW_PREFIX=REPLACE_WITH_REVIEWED_PREVIEW_PREFIX
export PILOT_AUDIT_PREFIX=REPLACE_WITH_REVIEWED_AUDIT_PREFIX
export PILOT_SITE_ID=REPLACE_WITH_REVIEWED_SITE_ID
export PILOT_ACCEPTANCE_CAMPAIGN_ID=REPLACE_WITH_SIGNED_CAMPAIGN_ID
export PILOT_STORAGE_PROBE_ID=REPLACE_WITH_SIGNED_CAMPAIGN_ID
export PILOT_STORAGE_PROBE_BINDING=/srv/kuzet/reviewed/storage-probe-binding.json
export PILOT_STORAGE_PROBE_BINDING_SIGNATURE=/srv/kuzet/reviewed/storage-probe-binding.sig
export PILOT_STORAGE_PROBE_BINDING_PUBLIC_KEY=/srv/kuzet/reviewed/storage-probe-binding-public.pem
export PILOT_STORAGE_PROBE_BINDING_SHA256=REPLACE_WITH_REVIEWED_64_HEX
export PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY=/srv/kuzet/secrets/storage-probe-receipt-private.pem
export PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY=/srv/kuzet/reviewed/storage-probe-receipt-public.pem
export PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY_SHA256=REPLACE_WITH_REVIEWED_64_HEX
export PILOT_STORAGE_PROBE_RECEIPT_ROOT=/srv/kuzet/storage-probes
export PILOT_STORAGE_PROBE_RECEIPT_DIR=\
"${PILOT_STORAGE_PROBE_RECEIPT_ROOT}/${PILOT_STORAGE_PROBE_ID}"
umask 077

for required in \
  PILOT_S3_ENDPOINT PILOT_S3_REGION PILOT_S3_BUCKET \
  PILOT_EVIDENCE_PREFIX PILOT_PREVIEW_PREFIX PILOT_AUDIT_PREFIX \
  PILOT_SITE_ID PILOT_ACCEPTANCE_CAMPAIGN_ID PILOT_STORAGE_PROBE_ID \
  PILOT_STORAGE_PROBE_BINDING_SHA256 \
  PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY_SHA256; do
  value="${!required}"
  test -n "${value}"
  case "${value}" in
    *REPLACE_WITH*)
      echo "${required} is still a placeholder" >&2
      exit 1
      ;;
  esac
done
case "${PILOT_S3_ENDPOINT}" in
  https://*) ;;
  *)
    echo "storage endpoint must be reviewed HTTPS" >&2
    exit 1
    ;;
esac
case "${PILOT_STORAGE_PROBE_ID}" in
  ""|*[!A-Za-z0-9._-]*)
    echo "unsafe storage probe ID" >&2
    exit 1
    ;;
esac
validate_probe_prefix() {
  case "$1" in
    ""|/*|*/|*..*|*//*)
      echo "unsafe or unbounded storage probe prefix" >&2
      exit 1
      ;;
  esac
}
validate_probe_prefix "${PILOT_EVIDENCE_PREFIX}"
validate_probe_prefix "${PILOT_PREVIEW_PREFIX}"
validate_probe_prefix "${PILOT_AUDIT_PREFIX}"
test "${PILOT_PREVIEW_PREFIX}" = "${PILOT_EVIDENCE_PREFIX}/previews"
test "${PILOT_AUDIT_PREFIX}" != "${PILOT_EVIDENCE_PREFIX}"
test -d "${PILOT_STORAGE_PROBE_RECEIPT_ROOT}"
test ! -L "${PILOT_STORAGE_PROBE_RECEIPT_ROOT}"
test "$(stat -c %u:%g:%a "${PILOT_STORAGE_PROBE_RECEIPT_ROOT}")" = "0:0:700"
test "${PILOT_STORAGE_PROBE_RECEIPT_DIR}" = \
  "${PILOT_STORAGE_PROBE_RECEIPT_ROOT}/${PILOT_STORAGE_PROBE_ID}"
for signed_input in \
  "${PILOT_STORAGE_PROBE_BINDING}" \
  "${PILOT_STORAGE_PROBE_BINDING_SIGNATURE}" \
  "${PILOT_STORAGE_PROBE_BINDING_PUBLIC_KEY}" \
  "${PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY}" \
  "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}"; do
  test -f "${signed_input}"
  test ! -L "${signed_input}"
done
test "$(sha256sum "${PILOT_STORAGE_PROBE_BINDING}" | awk '{print $1}')" \
  = "${PILOT_STORAGE_PROBE_BINDING_SHA256}"
test "$(sha256sum "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}" | awk '{print $1}')" \
  = "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY_SHA256}"
test "$(stat -c %a "${PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY}")" = 600
openssl dgst -sha256 \
  -verify "${PILOT_STORAGE_PROBE_BINDING_PUBLIC_KEY}" \
  -signature "${PILOT_STORAGE_PROBE_BINDING_SIGNATURE}" \
  "${PILOT_STORAGE_PROBE_BINDING}"
python3 - \
  "${PILOT_STORAGE_PROBE_BINDING}" \
  "${PILOT_SITE_ID}" \
  "${PILOT_ACCEPTANCE_CAMPAIGN_ID}" \
  "${PILOT_STORAGE_PROBE_ID}" \
  "${PILOT_S3_ENDPOINT}" \
  "${PILOT_S3_REGION}" \
  "${PILOT_S3_BUCKET}" \
  "${PILOT_EVIDENCE_PREFIX}" \
  "${PILOT_PREVIEW_PREFIX}" \
  "${PILOT_AUDIT_PREFIX}" \
  "${PILOT_STORAGE_PROBE_RECEIPT_DIR}" \
  "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY_SHA256}" <<'PY'
import json
import sys

keys = (
    "site_id",
    "campaign_id",
    "probe_id",
    "endpoint",
    "region",
    "bucket",
    "evidence_prefix",
    "preview_prefix",
    "audit_prefix",
    "receipt_dir",
    "receipt_verify_key_sha256",
)
payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload.get("schema") != "kuzet.storage-probe-binding.v1":
    raise SystemExit("unexpected storage-probe binding schema")
expected = dict(zip(keys, sys.argv[2:], strict=True))
actual = {key: payload.get(key) for key in keys}
if actual != expected:
    raise SystemExit("storage-probe binding does not match the exact campaign")
PY
test ! -e "${PILOT_STORAGE_PROBE_RECEIPT_DIR}"
install -d -m 0700 "${PILOT_STORAGE_PROBE_RECEIPT_DIR}"
probe_root="${PILOT_STORAGE_PROBE_RECEIPT_DIR}"
test "$(realpath -e -- "$(dirname -- "${probe_root}")")" = \
  "$(realpath -e -- "${PILOT_STORAGE_PROBE_RECEIPT_ROOT}")"

aws_kz() {
  aws \
    --endpoint-url "${PILOT_S3_ENDPOINT}" \
    --region "${PILOT_S3_REGION}" \
    --no-cli-pager \
    "$@"
}

printf 'original:%s\n' "${PILOT_STORAGE_PROBE_ID}" >"${probe_root}/original"
printf 'replacement:%s\n' "${PILOT_STORAGE_PROBE_ID}" >"${probe_root}/replacement"
original_sha="$(sha256sum "${probe_root}/original" | awk '{print $1}')"
replacement_sha="$(sha256sum "${probe_root}/replacement" | awk '{print $1}')"

probe_conditional_writer() {
  profile="$1"
  key="$2"
  label="$3"

  aws_kz --profile "${profile}" s3api put-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --body "${probe_root}/original" --if-none-match '*' \
    --checksum-algorithm SHA256 \
    --metadata "probe-id=${PILOT_STORAGE_PROBE_ID},probe-sha256=${original_sha}"

  set +e
  aws_kz --profile "${profile}" s3api put-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --body "${probe_root}/replacement" --if-none-match '*' \
    --checksum-algorithm SHA256 \
    --metadata "probe-id=changed,probe-sha256=${replacement_sha}" \
    >"${probe_root}/${label}.conditional.out" \
    2>"${probe_root}/${label}.conditional.err"
  conditional_status=$?
  aws_kz --profile "${profile}" s3api put-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --body "${probe_root}/replacement" \
    --checksum-algorithm SHA256 \
    --metadata "probe-id=changed,probe-sha256=${replacement_sha}" \
    >"${probe_root}/${label}.unconditional.out" \
    2>"${probe_root}/${label}.unconditional.err"
  unconditional_status=$?
  set -e

  test "${conditional_status}" -ne 0
  grep -Eq 'PreconditionFailed|ConditionalRequestConflict|409|412' \
    "${probe_root}/${label}.conditional.err"
  test "${unconditional_status}" -ne 0
  grep -Eq 'AccessDenied|403' "${probe_root}/${label}.unconditional.err"

  aws_kz --profile "${profile}" s3api head-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --checksum-mode ENABLED >"${probe_root}/${label}.head.json"
  aws_kz --profile "${profile}" s3api get-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --range 'bytes=0-1048575' \
    "${probe_root}/${label}.current" >/dev/null
  test "$(sha256sum "${probe_root}/${label}.current" | awk '{print $1}')" \
    = "${original_sha}"
}

evidence_key="${PILOT_EVIDENCE_PREFIX}/acl-probes/${PILOT_STORAGE_PROBE_ID}.bin"
preview_key="${PILOT_PREVIEW_PREFIX}/acl-probes/${PILOT_STORAGE_PROBE_ID}.mp4"
archive_key="${PILOT_AUDIT_PREFIX}/acl-probes/${PILOT_STORAGE_PROBE_ID}.age"
probe_conditional_writer kuzet-runtime "${evidence_key}" evidence
probe_conditional_writer kuzet-runtime "${preview_key}" preview
probe_conditional_writer kuzet-retention "${archive_key}" archive

for key in "${evidence_key}" "${preview_key}" "${archive_key}"; do
  aws_kz --profile kuzet-storage-auditor s3api list-object-versions \
    --bucket "${PILOT_S3_BUCKET}" --prefix "${key}" \
    --max-keys 100 --no-paginate \
    >"${probe_root}/$(basename "${key}").versions.json"
done

for binding in \
  "evidence:${evidence_key}" \
  "preview:${preview_key}" \
  "archive:${archive_key}"; do
  label="${binding%%:*}"
  key="${binding#*:}"
  version_id="$(
    python3 - "${probe_root}/$(basename "${key}").versions.json" "${key}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if any(
    payload.get(field)
    for field in (
        "IsTruncated",
        "NextToken",
        "NextKeyMarker",
        "NextVersionIdMarker",
    )
):
    raise SystemExit("probe version inventory exceeded its single bounded page")
matches = [
    item
    for item in payload.get("Versions", [])
    if item.get("Key") == sys.argv[2] and item.get("IsLatest") is True
]
if len(matches) != 1 or not isinstance(matches[0].get("VersionId"), str):
    raise SystemExit("probe version identity is not exact")
print(matches[0]["VersionId"])
PY
  )"
  aws_kz --profile kuzet-storage-auditor s3api get-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --version-id "${version_id}" \
    --range 'bytes=0-1048575' \
    "${probe_root}/${label}.version" >/dev/null
  printf '%s\n' "${version_id}" >"${probe_root}/${label}.version-id"
  test "$(sha256sum "${probe_root}/${label}.version" | awk '{print $1}')" \
    = "${original_sha}"
done

python3 - "${probe_root}" "${PILOT_STORAGE_PROBE_ID}" "${original_sha}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected_id = sys.argv[2]
expected_sha = sys.argv[3]
for label in ("evidence", "preview", "archive"):
    payload = json.loads((root / f"{label}.head.json").read_text())
    metadata = payload.get("Metadata")
    if not isinstance(metadata, dict):
        raise SystemExit(f"{label} HEAD omitted metadata")
    if (
        metadata.get("probe-id") != expected_id
        or metadata.get("probe-sha256") != expected_sha
    ):
        raise SystemExit(f"{label} current metadata changed")
PY

aws_kz --profile kuzet-storage-auditor s3api get-bucket-policy \
  --bucket "${PILOT_S3_BUCKET}" >"${probe_root}/storage-policy.json"
aws_kz --profile kuzet-storage-auditor s3api get-bucket-versioning \
  --bucket "${PILOT_S3_BUCKET}" >"${probe_root}/storage-versioning.json"
aws_kz --profile kuzet-storage-auditor s3api \
  get-bucket-lifecycle-configuration \
  --bucket "${PILOT_S3_BUCKET}" >"${probe_root}/storage-lifecycle.json"
for item in policy versioning lifecycle; do
  python3 -m json.tool --sort-keys --compact \
    "${probe_root}/storage-${item}.json" \
    >"${probe_root}/storage-${item}.canonical.json"
done
sha256sum "${probe_root}"/*.json "${probe_root}"/*.out \
  "${probe_root}"/*.err "${probe_root}"/*.current \
  "${probe_root}"/*.version \
  >"${probe_root}/probe-receipt.sha256"
```

This is a three-way test for each writer scope:

1. a new key with `If-None-Match: *` succeeds;
2. the same key with different bytes and metadata plus
   `If-None-Match: *` fails atomically with HTTP 409/412; and
3. the same key without that header fails authorization with HTTP 403.

The exact HEAD, current GET, object-version inventory, and metadata receipt
must prove the first object's bytes and metadata remain current and unchanged.
The 409/412 result proves provider atomic conditional semantics; the separate
403 proves bucket/resource-policy enforcement. Neither substitutes for the
other.

The auditor must observe versioning `Status=Enabled`. Each evidence/preview
rule uses only the exact prefix filter,
`Expiration: {Days: <reviewed>}`, and
`NoncurrentVersionExpiration: {NoncurrentDays: 1}`. No
`NewerNoncurrentVersions`, tags, object-size filters, transitions, earlier
overlapping rule, or ambiguous global/ancestor/child rule is allowed.

Run additional positive and negative authorization probes for each identity:

- API preview: exact-version ranged `GetObjectVersion` succeeds; current
  `GetObject`, list, put, delete, cross-prefix, and bucket mutation fail.
- Runtime writer: current `GetObject` and conditional `PutObject` succeed;
  `GetObjectVersion`, list, delete, cross-prefix, ACL, lifecycle, and
  versioning mutation fail.
- Retention: prefix-conditioned `ListBucketVersions`, evidence
  `GetObjectVersion`/`DeleteObjectVersion`, and archive
  `GetObject`/conditional `PutObject` succeed; simple `DeleteObject`,
  evidence write, archive delete, cross-prefix, ACL, lifecycle, and versioning
  mutation fail.

Execute the object-level subset with the same untouched probe identities and
receipt directory. A success from any `expect_denied` call is a failed storage
gate; do not continue after such a result:

```bash
expect_denied() {
  label="$1"
  shift
  set +e
  "$@" >"${probe_root}/${label}.out" 2>"${probe_root}/${label}.err"
  status=$?
  set -e
  test "${status}" -ne 0
  grep -Eq 'AccessDenied|Forbidden|403' "${probe_root}/${label}.err"
}

evidence_version_id="$(cat "${probe_root}/evidence.version-id")"
preview_version_id="$(cat "${probe_root}/preview.version-id")"
archive_version_id="$(cat "${probe_root}/archive.version-id")"

# API preview: exact named version only.
aws_kz --profile kuzet-api-preview s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${preview_key}" \
  --version-id "${preview_version_id}" --range 'bytes=0-0' \
  "${probe_root}/api-preview-version.byte" \
  >"${probe_root}/api-preview-version.out"
expect_denied api-current-get \
  aws_kz --profile kuzet-api-preview s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${preview_key}" \
  --range 'bytes=0-0' \
  "${probe_root}/api-current-get.bin"
expect_denied api-list-versions \
  aws_kz --profile kuzet-api-preview s3api list-object-versions \
  --bucket "${PILOT_S3_BUCKET}" --prefix "${preview_key}" \
  --max-keys 100 --no-paginate
expect_denied api-put \
  aws_kz --profile kuzet-api-preview s3api put-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${preview_key}" \
  --body "${probe_root}/replacement" --if-none-match '*'
expect_denied api-delete-version \
  aws_kz --profile kuzet-api-preview s3api delete-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${preview_key}" \
  --version-id "${preview_version_id}"

# Runtime writer: current reads and conditional creates, never named versions.
aws_kz --profile kuzet-runtime s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${evidence_key}" \
  --range 'bytes=0-1048575' \
  "${probe_root}/runtime-current.bin" \
  >"${probe_root}/runtime-current.out"
expect_denied runtime-version-get \
  aws_kz --profile kuzet-runtime s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${evidence_key}" \
  --version-id "${evidence_version_id}" \
  --range 'bytes=0-0' \
  "${probe_root}/runtime-version-get.bin"
expect_denied runtime-list-versions \
  aws_kz --profile kuzet-runtime s3api list-object-versions \
  --bucket "${PILOT_S3_BUCKET}" --prefix "${evidence_key}" \
  --max-keys 100 --no-paginate
expect_denied runtime-delete-version \
  aws_kz --profile kuzet-runtime s3api delete-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${evidence_key}" \
  --version-id "${evidence_version_id}"
expect_denied runtime-cross-prefix-get \
  aws_kz --profile kuzet-runtime s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${archive_key}" \
  --range 'bytes=0-0' \
  "${probe_root}/runtime-cross-prefix-get.bin"

# Retention: exact evidence/preview version retirement and immutable archive.
aws_kz --profile kuzet-retention s3api list-object-versions \
  --bucket "${PILOT_S3_BUCKET}" --prefix "${evidence_key}" \
  --max-keys 100 --no-paginate \
  >"${probe_root}/retention-list-versions.out"
aws_kz --profile kuzet-retention s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${evidence_key}" \
  --version-id "${evidence_version_id}" \
  --range 'bytes=0-1048575' \
  "${probe_root}/retention-evidence-version.bin" \
  >"${probe_root}/retention-evidence-version.out"
aws_kz --profile kuzet-retention s3api get-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${archive_key}" \
  --range 'bytes=0-1048575' \
  "${probe_root}/retention-archive-current.bin" \
  >"${probe_root}/retention-archive-current.out"
expect_denied retention-simple-delete \
  aws_kz --profile kuzet-retention s3api delete-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${evidence_key}"
expect_denied retention-evidence-write \
  aws_kz --profile kuzet-retention s3api put-object \
  --bucket "${PILOT_S3_BUCKET}" \
  --key "${PILOT_EVIDENCE_PREFIX}/acl-probes/retention-denied-${PILOT_STORAGE_PROBE_ID}.bin" \
  --body "${probe_root}/replacement" --if-none-match '*'
expect_denied retention-archive-delete \
  aws_kz --profile kuzet-retention s3api delete-object \
  --bucket "${PILOT_S3_BUCKET}" --key "${archive_key}" \
  --version-id "${archive_version_id}"

sha256sum "${probe_root}"/*.json "${probe_root}"/*.out \
  "${probe_root}"/*.err "${probe_root}"/*.bin \
  "${probe_root}"/*.byte "${probe_root}"/*.current \
  "${probe_root}"/*.version "${probe_root}"/*.version-id \
  >"${probe_root}/probe-receipt-final.sha256"
openssl dgst -sha256 \
  -sign "${PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY}" \
  -out "${probe_root}/probe-receipt-final.sig" \
  "${probe_root}/probe-receipt-final.sha256"
openssl dgst -sha256 \
  -verify "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}" \
  -signature "${probe_root}/probe-receipt-final.sig" \
  "${probe_root}/probe-receipt-final.sha256"
```

Use the provider's read-only policy simulator or authorization-details API to
prove the expected denials for ACL and bucket policy/lifecycle/versioning
mutation; do not test those administrative denials by issuing a live mutation
against the pilot bucket. Run separate SSE-KMS positive and negative probes
when configured, binding the exact key ARN and confirming that no service
identity has wildcard key-management authority.

Use the retention identity to remove only exact evidence/preview probe
versions after their version IDs, checksums, policy digest, positive outcomes,
and every expected denial are archived. Archive objects are immutable and
must age under their reviewed lifecycle or be removed only by a separately
approved storage administrator procedure; never grant a service broader
delete access for probe cleanup.

After the approved receipt verifier has validated the detached signature on
`probe-receipt-final.sha256`, prove the two permitted exact-version deletions.
The deletion block re-verifies the receipt before issuing either destructive
request:

```bash
test -s "${probe_root}/probe-receipt-final.sha256"
test -s "${probe_root}/probe-receipt-final.sig"
openssl dgst -sha256 \
  -verify "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}" \
  -signature "${probe_root}/probe-receipt-final.sig" \
  "${probe_root}/probe-receipt-final.sha256"

delete_probe_version() {
  label="$1"
  key="$2"
  version_id="$3"
  aws_kz --profile kuzet-retention s3api delete-object \
    --bucket "${PILOT_S3_BUCKET}" --key "${key}" \
    --version-id "${version_id}" \
    >"${probe_root}/${label}.exact-delete.out"
  aws_kz --profile kuzet-storage-auditor s3api list-object-versions \
    --bucket "${PILOT_S3_BUCKET}" --prefix "${key}" \
    --max-keys 100 --no-paginate \
    >"${probe_root}/${label}.after-delete.json"
  python3 - "${probe_root}/${label}.after-delete.json" \
    "${key}" "${version_id}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if any(
    payload.get(field)
    for field in (
        "IsTruncated",
        "NextToken",
        "NextKeyMarker",
        "NextVersionIdMarker",
    )
):
    raise SystemExit("post-delete inventory exceeded its single bounded page")
remaining = [
    item
    for collection in ("Versions", "DeleteMarkers")
    for item in payload.get(collection, [])
    if item.get("Key") == sys.argv[2] and item.get("VersionId") == sys.argv[3]
]
if remaining:
    raise SystemExit("exact probe version still exists")
PY
}
delete_probe_version evidence "${evidence_key}" "${evidence_version_id}"
delete_probe_version preview "${preview_key}" "${preview_version_id}"
sha256sum "${probe_root}"/*.after-delete.json \
  "${probe_root}"/*.exact-delete.out \
  >"${probe_root}/probe-cleanup-receipt.sha256"
openssl dgst -sha256 \
  -sign "${PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY}" \
  -out "${probe_root}/probe-cleanup-receipt.sig" \
  "${probe_root}/probe-cleanup-receipt.sha256"
openssl dgst -sha256 \
  -verify "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}" \
  -signature "${probe_root}/probe-cleanup-receipt.sig" \
  "${probe_root}/probe-cleanup-receipt.sha256"

python3 - \
  "${PILOT_STORAGE_PROBE_BINDING_SHA256}" \
  "${probe_root}/probe-receipt-final.sha256" \
  "${probe_root}/probe-receipt-final.sig" \
  "${probe_root}/probe-cleanup-receipt.sha256" \
  "${probe_root}/storage-probe-authority.json" <<'PY'
import hashlib
import json
import os
import pathlib
import sys


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


target = pathlib.Path(sys.argv[5])
payload = {
    "schema": "kuzet.storage-probe-authority.v1",
    "binding_sha256": sys.argv[1],
    "probe_receipt_sha256": digest(pathlib.Path(sys.argv[2])),
    "probe_signature_sha256": digest(pathlib.Path(sys.argv[3])),
    "cleanup_receipt_sha256": digest(pathlib.Path(sys.argv[4])),
    "verdict": "verified",
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
descriptor = os.open(target, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(payload, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
openssl dgst -sha256 \
  -sign "${PILOT_STORAGE_PROBE_RECEIPT_SIGNING_KEY}" \
  -out "${probe_root}/storage-probe-authority.sig" \
  "${probe_root}/storage-probe-authority.json"
openssl dgst -sha256 \
  -verify "${PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY}" \
  -signature "${probe_root}/storage-probe-authority.sig" \
  "${probe_root}/storage-probe-authority.json"
sha256sum \
  "${probe_root}/storage-probe-authority.json" \
  "${probe_root}/storage-probe-authority.sig" \
  >"${probe_root}/storage-probe-authority.verified"
test -s "${probe_root}/storage-probe-authority.verified"

docker compose -f deploy/pilot/docker-compose.yml up -d retention
```

Retention starts only after the signed campaign binding, non-destructive
three-way and denial probes, receipt verification, two exact-version delete
probes, post-delete absence checks, and signed cleanup/authority receipts all
pass. Any command failure keeps retention stopped and blocks activation.

The services attest versioning/lifecycle at startup and the retention service
rechecks before every hourly destructive cycle. Independently poll and hash
the effective policy, versioning, and lifecycle at least hourly; alert on any
digest change. Provider audit logs must identify the actor and UTC time of
every policy/versioning/lifecycle change. Missing drift visibility keeps the
storage gate PENDING.

### Retention arrival, drain, and backlog target

The rendered deployment uses a 3,600-second cadence and evidence, audit,
registered-preview, and orphan-version batch limits of 1,000, 10,000, 1,000,
and 1,000 respectively. Process uptime is not proof of bounded retention. On
a fresh disposable target database/object prefix, install one signed
retention fixture containing:

- `configured_evidence_batch + 1` expiry-eligible evidence rows and exact
  immutable object versions;
- `configured_audit_batch + 1` small expiry-eligible audit rows whose
  canonical archive stays within the configured byte bound;
- `configured_preview_batch + 1` expiry-eligible preview receipts/versions;
- `configured_orphan_batch + 1` orphan preview versions older than the
  publication grace period; and
- at least one additional identity per class that becomes eligible during
  each measured window.

The fixture manifest binds every row/object ID, key, version ID, SHA-256,
byte size, eligible time, active configuration digest, lifecycle/policy
digest, and expected batch. It contains no continuous video and must never be
inserted into the activated customer database.

Use PostgreSQL `CURRENT_TIMESTAMP`, not the host clock, to capture sorted
identity snapshots around every cycle. The read-only probe account is
separate from all service roles:

```bash
set -euo pipefail
export PGSERVICEFILE=/srv/kuzet/secrets/pilot-role-probes.pg_service.conf
export PILOT_RETENTION_SNAPSHOT_ROOT=/srv/kuzet/retention-measurement
export PILOT_RETENTION_CYCLE_ID=REPLACE_WITH_SIGNED_UNIQUE_CYCLE_ID
export PILOT_RETENTION_RECEIPT_SIGNING_KEY=/srv/kuzet/secrets/retention-receipt-private.pem
export PILOT_RETENTION_RECEIPT_VERIFY_KEY=/srv/kuzet/reviewed/retention-receipt-public.pem
export PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE=REPLACE_WITH_REVIEWED_FINITE_BYTES
export PILOT_RETENTION_RECEIPT_MAX_FILES_PER_CYCLE=REPLACE_WITH_REVIEWED_FINITE_FILES
export PILOT_RETENTION_RECEIPT_ROOT_QUOTA_BYTES=REPLACE_WITH_REVIEWED_FINITE_BYTES
export PILOT_RETENTION_RECEIPT_ROOT_QUOTA_FILES=REPLACE_WITH_REVIEWED_FINITE_FILES
export PILOT_RETENTION_FORECAST_CYCLES=REPLACE_WITH_REVIEWED_FINITE_CYCLES
export PILOT_SITE_ID=REPLACE_WITH_REVIEWED_SITE_ID
export PILOT_EVIDENCE_RETENTION_DAYS=REPLACE_WITH_REVIEWED_FINITE_DAYS
export PILOT_AUDIT_RETENTION_DAYS=REPLACE_WITH_REVIEWED_FINITE_DAYS
case "${PILOT_RETENTION_CYCLE_ID}" in
  ""|*REPLACE_WITH*|*[!A-Za-z0-9._-]*)
    echo "unsafe or unresolved retention cycle ID" >&2
    exit 1
    ;;
esac
test -d "${PILOT_RETENTION_SNAPSHOT_ROOT}"
test ! -L "${PILOT_RETENTION_SNAPSHOT_ROOT}"
cycle_dir="${PILOT_RETENTION_SNAPSHOT_ROOT}/${PILOT_RETENTION_CYCLE_ID}"
test ! -e "${cycle_dir}"
install -d -m 0700 "${cycle_dir}"
test "$(realpath -e -- "$(dirname -- "${cycle_dir}")")" = \
  "$(realpath -e -- "${PILOT_RETENTION_SNAPSHOT_ROOT}")"
for receipt_key in \
  "${PILOT_RETENTION_RECEIPT_SIGNING_KEY}" \
  "${PILOT_RETENTION_RECEIPT_VERIFY_KEY}"; do
  test -f "${receipt_key}"
  test ! -L "${receipt_key}"
done

PILOT_RETENTION_WINDOW_START="$(
  psql "service=kuzet_retention_probe" -X -v ON_ERROR_STOP=1 -Atc \
    "SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'"
)"
PILOT_RETENTION_WINDOW_END="$(
  psql "service=kuzet_retention_probe" -X -v ON_ERROR_STOP=1 -Atc \
    "SELECT (CURRENT_TIMESTAMP + interval '3600 seconds') AT TIME ZONE 'UTC'"
)"

capture_retention_ids() {
  target="$1"
  psql "service=kuzet_retention_probe" -X -v ON_ERROR_STOP=1 \
    -v site_id="${PILOT_SITE_ID}" \
    -v evidence_days="${PILOT_EVIDENCE_RETENTION_DAYS}" \
    -v audit_days="${PILOT_AUDIT_RETENTION_DAYS}" \
    -v window_end="${PILOT_RETENTION_WINDOW_END}" -AtF '|' \
    <<'SQL' | LC_ALL=C sort >"${target}"
SELECT 'evidence', evidence.evidence_id,
       evidence.created_at
         + make_interval(days => (:'evidence_days')::integer)
  FROM evidence
  JOIN candidate_events event ON event.event_id = evidence.event_id
  JOIN cameras camera ON camera.camera_id = event.camera_id
 WHERE camera.site_id = :'site_id'
   AND evidence.status IN ('ready', 'unavailable')
   AND evidence.created_at
         + make_interval(days => (:'evidence_days')::integer)
       <= (:'window_end')::timestamp AT TIME ZONE 'UTC'
UNION ALL
SELECT 'audit', audit.audit_id,
       audit.occurred_at + make_interval(days => (:'audit_days')::integer)
  FROM audit_entries audit
 WHERE audit.site_id = :'site_id'
   AND audit.occurred_at + make_interval(days => (:'audit_days')::integer)
       <= (:'window_end')::timestamp AT TIME ZONE 'UTC'
UNION ALL
SELECT 'preview', preview.event_id,
       preview.receipt_created_at
         + make_interval(days => (:'evidence_days')::integer)
  FROM preview_publications preview
 WHERE preview.site_id = :'site_id'
   AND preview.publication_state IN ('ready', 'retiring')
   AND preview.receipt_created_at IS NOT NULL
   AND preview.receipt_created_at
         + make_interval(days => (:'evidence_days')::integer)
       <= (:'window_end')::timestamp AT TIME ZONE 'UTC';
SQL
}

capture_retention_ids "${cycle_dir}/before.ids"
# After the externally observed cycle receipt and the fixed window end:
test "$(
  psql "service=kuzet_retention_probe" -X -v ON_ERROR_STOP=1 \
    -v window_end="${PILOT_RETENTION_WINDOW_END}" -At <<'SQL'
SELECT CURRENT_TIMESTAMP >=
       ((:'window_end')::timestamp AT TIME ZONE 'UTC');
SQL
)" = "t"
capture_retention_ids "${cycle_dir}/after.ids"

comm -23 \
  "${cycle_dir}/before.ids" \
  "${cycle_dir}/after.ids" \
  >"${cycle_dir}/drained.ids"
comm -13 \
  "${cycle_dir}/before.ids" \
  "${cycle_dir}/after.ids" \
  >"${cycle_dir}/unexpected.ids"
test ! -s "${cycle_dir}/unexpected.ids"

python3 - \
  "${cycle_dir}/before.ids" \
  "${cycle_dir}/after.ids" \
  "${PILOT_RETENTION_WINDOW_START}" \
  "${PILOT_RETENTION_WINDOW_END}" \
  >"${cycle_dir}/cycle-summary.json" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def stamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace(" ", "T"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def rows(path: str) -> dict[tuple[str, str], datetime]:
    result: dict[tuple[str, str], datetime] = {}
    for line in Path(path).read_text().splitlines():
        kind, identity, eligible_at = line.split("|", 2)
        key = (kind, identity)
        if key in result:
            raise SystemExit("duplicate retention identity")
        result[key] = stamp(eligible_at)
    return result


before = rows(sys.argv[1])
after = rows(sys.argv[2])
start = stamp(sys.argv[3])
end = stamp(sys.argv[4])
if not after.keys() <= before.keys():
    raise SystemExit("unexpected retention identities appeared")
summary: dict[str, object] = {}
for kind in ("evidence", "audit", "preview"):
    initial = {key for key, value in before.items() if key[0] == kind and value <= start}
    arrivals = {key for key, value in before.items() if key[0] == kind and start < value <= end}
    remaining = {key for key in after if key[0] == kind}
    drained = (initial | arrivals) - remaining
    oldest = max(
        (end - before[key]).total_seconds() for key in remaining
    ) if remaining else 0
    summary[kind] = {
        "initial_backlog": len(initial),
        "eligible_arrivals": len(arrivals),
        "drained": len(drained),
        "ending_backlog": len(remaining),
        "oldest_eligible_age_seconds": max(0, oldest),
    }
print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
PY

sha256sum "${cycle_dir}"/*.ids \
  "${cycle_dir}/cycle-summary.json" \
  >"${cycle_dir}/cycle-receipt.sha256"

for finite_bound in \
  PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE \
  PILOT_RETENTION_RECEIPT_MAX_FILES_PER_CYCLE \
  PILOT_RETENTION_RECEIPT_ROOT_QUOTA_BYTES \
  PILOT_RETENTION_RECEIPT_ROOT_QUOTA_FILES \
  PILOT_RETENTION_FORECAST_CYCLES; do
  finite_value="${!finite_bound}"
  case "${finite_value}" in
    ""|0|*[!0-9]*)
      echo "${finite_bound} must be a positive finite integer" >&2
      exit 1
      ;;
  esac
done

cycle_bytes_before_signature="$(
  du -sb "${cycle_dir}" | awk '{print $1}'
)"
cycle_files_before_signature="$(
  find "${cycle_dir}" -xdev -type f -printf . | wc -c
)"
test "${cycle_bytes_before_signature}" \
  -le "${PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE}"
test "$((cycle_files_before_signature + 1))" \
  -le "${PILOT_RETENTION_RECEIPT_MAX_FILES_PER_CYCLE}"

openssl dgst -sha256 \
  -sign "${PILOT_RETENTION_RECEIPT_SIGNING_KEY}" \
  -out "${cycle_dir}/cycle-receipt.sig" \
  "${cycle_dir}/cycle-receipt.sha256"
openssl dgst -sha256 \
  -verify "${PILOT_RETENTION_RECEIPT_VERIFY_KEY}" \
  -signature "${cycle_dir}/cycle-receipt.sig" \
  "${cycle_dir}/cycle-receipt.sha256"

cycle_bytes="$(du -sb "${cycle_dir}" | awk '{print $1}')"
cycle_files="$(
  find "${cycle_dir}" -xdev -type f -printf . | wc -c
)"
test "${cycle_bytes}" \
  -le "${PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE}"
test "${cycle_files}" \
  -le "${PILOT_RETENTION_RECEIPT_MAX_FILES_PER_CYCLE}"

receipt_root_bytes="$(
  du -sb "${PILOT_RETENTION_SNAPSHOT_ROOT}" | awk '{print $1}'
)"
receipt_root_files="$(
  find "${PILOT_RETENTION_SNAPSHOT_ROOT}" -xdev -type f -printf . | wc -c
)"
python3 - \
  "${receipt_root_bytes}" \
  "${receipt_root_files}" \
  "${PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE}" \
  "${PILOT_RETENTION_RECEIPT_MAX_FILES_PER_CYCLE}" \
  "${PILOT_RETENTION_RECEIPT_ROOT_QUOTA_BYTES}" \
  "${PILOT_RETENTION_RECEIPT_ROOT_QUOTA_FILES}" \
  "${PILOT_RETENTION_FORECAST_CYCLES}" <<'PY'
import sys

values = [int(value) for value in sys.argv[1:]]
if any(value <= 0 for value in values):
    raise SystemExit("retention receipt forecast values must be positive")
(
    current_bytes,
    current_files,
    per_cycle_bytes,
    per_cycle_files,
    quota_bytes,
    quota_files,
    forecast_cycles,
) = values
if current_bytes > quota_bytes or current_files > quota_files:
    raise SystemExit("retention receipt root already exceeds its quota")
if current_bytes + per_cycle_bytes * forecast_cycles > quota_bytes:
    raise SystemExit("retention receipt byte forecast exceeds its quota")
if current_files + per_cycle_files * forecast_cycles > quota_files:
    raise SystemExit("retention receipt file forecast exceeds its quota")
PY
```

Repeat this for at least six consecutive cycles and combine it with exact
object-version inventories, archive receipts, and independently timestamped
service batch results. Measure registered preview retirement and orphan
version deletion separately. The target is: no failed batch; each seeded
batch-plus-one backlog clears within two cycles; cumulative drain is at least
cumulative eligible arrival after the seed clears; measured drain capacity is
at least 125% of observed arrival while backlog is nonzero; end depth does not
exceed start depth; and oldest eligible backlog age is at most two cycles
(7,200 seconds). Each cycle uses a new signed ID and new directory; never
truncate, reuse, or overwrite a prior cycle. Treat signed audit and cycle
receipt roots as irreducible records, not as a drainable queue. Their reviewed
maximum bytes/files per cycle are checked against the actual cycle directory
both before and after detached-signature creation, then used for the root
forecast. Campaign length, quota, retention lifecycle, and alert threshold
must demonstrate **bounded and forecasted audit receipt-root growth** and be
bound into the signed fixture and handover manifest.

The current service does not yet export a complete signed arrival/drain/
backlog cycle receipt. Until bounded target instrumentation supplies that
receipt, the measurements above and retention acceptance remain **PENDING**.
Any unexpected identity, widening backlog, older item, missing receipt, or
policy drift blocks activation.

**orphan-version instrumentation remains BLOCKED.** The database-clock query
above cannot discover unregistered object versions, and this revision does not
package a campaign-bound, endpoint/region-bound, finitely paginated orphan
inventory joined to the exact service deletion receipt. The six-cycle
procedure therefore cannot yet prove orphan arrival, drain, depth, or
oldest-age. Aggregate retention steady state remains unproven until that
instrumentation is implemented, reviewed, signed, and run on the disposable
Kazakhstan target.

## Bind the exact 20 camera secrets

The reviewed site configuration must use these one-to-one Docker-secret
references—one unique file per canonical source index. Controlled-pilot rule:
RTSP credentials through environment variables are forbidden.

```yaml
camera-01: {docker_secret: /run/secrets/camera_01_rtsp_url}
camera-02: {docker_secret: /run/secrets/camera_02_rtsp_url}
camera-03: {docker_secret: /run/secrets/camera_03_rtsp_url}
camera-04: {docker_secret: /run/secrets/camera_04_rtsp_url}
camera-05: {docker_secret: /run/secrets/camera_05_rtsp_url}
camera-06: {docker_secret: /run/secrets/camera_06_rtsp_url}
camera-07: {docker_secret: /run/secrets/camera_07_rtsp_url}
camera-08: {docker_secret: /run/secrets/camera_08_rtsp_url}
camera-09: {docker_secret: /run/secrets/camera_09_rtsp_url}
camera-10: {docker_secret: /run/secrets/camera_10_rtsp_url}
camera-11: {docker_secret: /run/secrets/camera_11_rtsp_url}
camera-12: {docker_secret: /run/secrets/camera_12_rtsp_url}
camera-13: {docker_secret: /run/secrets/camera_13_rtsp_url}
camera-14: {docker_secret: /run/secrets/camera_14_rtsp_url}
camera-15: {docker_secret: /run/secrets/camera_15_rtsp_url}
camera-16: {docker_secret: /run/secrets/camera_16_rtsp_url}
camera-17: {docker_secret: /run/secrets/camera_17_rtsp_url}
camera-18: {docker_secret: /run/secrets/camera_18_rtsp_url}
camera-19: {docker_secret: /run/secrets/camera_19_rtsp_url}
camera-20: {docker_secret: /run/secrets/camera_20_rtsp_url}
```

Create the 20 external secrets out of band, confirm that Compose mounts them
at exactly those paths, and validate that the signed config has source indices
0–19 and no duplicate/missing secret reference. Never print or archive the
secret contents. Changing a URI or secret identity requires source profiling,
config re-signing, and applicable reacceptance.

## Bootstrap the first administrator

Create external Docker secrets containing the database URL, normalized
username, strong password, TOTP seed, and TOTP encryption key. Then run:

```bash
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.admin.yml \
  run --rm admin-bootstrap
```

The job is zero-user-only and refuses a second bootstrap. Test login, TOTP,
role enforcement, and audit output, then revoke/remove the bootstrap username,
password, and TOTP-seed secrets. Retain the encryption key through the normal
key-management lifecycle.

## Start the shared runtime

The complete `TARGET_ACCEPTANCE.md` raw sequence is the sole authoritative
pending runtime launch.

### Raw pending target-acceptance path

Use the complete stopped-create, network-connect, and start sequence in
`TARGET_ACCEPTANCE.md`. Its validated 35-mount production contract applies
only to that raw container.

### Compose runtime template is render-only

Compose runtime activation is **BLOCKED**. Keep rendering the selected base
plus runtime overlay as a static packaging check, but do not start its runtime
service. The raw mount validator does not validate the rendered Compose secret
and directory layout.

Activation remains blocked until a reviewed host wrapper attests the rendered
container's exact image ID and config, every individual file and writable
directory mount, secret target, runtime identity, network attachment, tmpfs,
resource limit, and logging limit before start. Manual inspection does not
close this gate. This runbook therefore provides no executable Compose runtime
start command.

The render-only template selects the dedicated
`protector.pilot.runtime.production_main` composition. It consumes the
database/object-store authorities, claims the current reviewed writer, loads
the canonical active configuration and compiled rules, binds the durable
event/evidence/preview worker, and only then starts the shared graph.

The template configures `protector.pilot.runtime.production_main` with the
signed site, runtime, capacity, image, code, mount, nonce, control-plane,
database-secret, object-store-secret, and region arguments. It binds exactly
20 camera secret files and one reviewed GPU UUID, and connects to separate
camera, control, data, and Kazakhstan storage networks. Once the missing
wrapper closes the gate, verify one shared multistream graph and shared models,
supervised RTSP, hardware decode, cross-camera batching, per-camera
timestamps/state, bounded leaky queues, and bounded event evidence on the
target host. Do not infer capacity from image startup.

Rendering the runtime overlay also shows the API extension with the same
reviewed site configuration digest and distinct, read-only preview
object-store credentials.
The reviewed site configuration owns endpoint, bucket, and prefix; the
required `PILOT_PREVIEW_OBJECT_STORE_REGION` supplies only the client region.
The preview IAM identity needs only prefix-scoped `s3:GetObjectVersion`, plus
bucket-level read-only
`s3:GetBucketVersioning` and `s3:GetLifecycleConfiguration` on the exact
reviewed bucket. Verify it cannot create, overwrite, list, delete, mutate
lifecycle/versioning, or access another prefix, and that runtime writer
credentials are not mounted into the API.

The API database secret must authenticate as `kuzet_api`; owner, migrator,
runtime, and retention URLs are invalid substitutes. Startup verifies both
`session_user` and `current_user` before reading the site or camera inventory.
For `aws:kms` preview storage, its version-specific checksum HEAD requires
key-scoped `kms:GenerateDataKey` and `kms:Decrypt`; archive positive and
negative KMS probes with the preview ACL receipt.

The `runtime_database_url` must authenticate as the dedicated
`kuzet_runtime` login created by `role-bootstrap`. Archive proof that it is a
non-owner, non-superuser role and can execute only migration-granted bounded
runtime functions/read surfaces; API, migrator, retention, and owner database
URLs are invalid substitutes.

The distinct runtime writer identity has only bucket
`s3:GetBucketVersioning`/`s3:GetLifecycleConfiguration` and reviewed-prefix
`s3:GetObject`/`s3:PutObject`. It must be unable to read a named noncurrent
version, list, delete, mutate bucket controls or ACLs, or cross the reviewed
prefix.
The startup lifecycle probe requires exact current retention and
`NoncurrentDays=1`. If storage uses `aws:kms`, grant only key-scoped
`kms:GenerateDataKey` and `kms:Decrypt` needed by those operations.

Expected target metrics are the authoritative `TARGET_ACCEPTANCE.md` gates:
effective throughput with at least 25% measured headroom; GPU at or below 75%;
VRAM at or below 80%; scheduled drops below 1%; plus the documented queue-age,
reconnect, latency, disk, evidence, audit, and cross-camera isolation metrics.
No universal cameras-per-GPU coefficient is accepted.

Archive raw bounded samples and the calculation code for every result. The
pending pass targets are:

| Target evidence | Required result |
|---|---|
| stream concurrency/duration | Exactly the signed 20 sources for the complete 8-hour integration gate and later the complete 72-hour soak. |
| analytic availability | At least 99.5%, excluding only separately evidenced upstream source outage. |
| scheduled analysis drops | Below 1% for every scheduled module and the aggregate; no missing interval is treated as zero. |
| analysis queue age | Per camera and aggregate p95 below 1 second and p99 below 2 seconds, with capacity and coverage frozen for the whole run. |
| source return | RTSP recovery within 30 seconds after the authority-observed source return. |
| event latency | Candidate-to-event p95 at most 1 second. |
| evidence latency/integrity | First preview p95 at most 2 seconds; every expected candidate has exact bounded evidence state, object/version/hash/size/codec/time identity, or an explicit failure. |
| GPU/VRAM | Interval high-water GPU utilization at most 75% and VRAM utilization at most 80%; exact GPU UUID/product/PCI/VRAM/driver/CUDA/MIG identity is bound. |
| capacity | Completed unique work over the measured monotonic window is at least 125% of the centrally derived frozen offered workload. |
| queues/disks/stores | Bounded capacities throughout; no monotonic queue, spool, evidence, or preview growth; bounded and forecasted audit receipt-root growth; retention arrival/drain/depth/oldest-age target passes. |
| recovery/safety | No crash, OOM, cross-camera tracker/analytic state leakage, unaudited transition, or notification before a human-confirmed eligible candidate. |

Percentiles, outage exclusions, high-water values, and no-growth conclusions
come from the authority-bound raw evidence. A dashboard screenshot, final
scalar, container uptime, or hardware specification is not a measurement.

## Run target acceptance

Pre-create private, finite acceptance state, snapshot, proof, capture, and
launch-bound channel paths with the reviewed UID/mode. The capture root and
channel root must resolve to distinct directories: the controller retains
bounded collector artifacts under
`PILOT_ACCEPTANCE_CAPTURE_PATH`, while launch grants and acknowledgements use
`PILOT_ACCEPTANCE_CHANNEL_PATH`.

The packaged overlay selects
`create_production_acceptance_controller_v3_app`. It exposes the retained V2
collection routes and the provider-owned
`/api/internal/acceptance/v3/collectors/{collector_id}/finalize` route. The
target runner now preserves the canonical `+40s` runtime-restart fault as an
append-only execution transition, retires the second runtime/channel, and
launches a third controller-owned signed source profile, nonce, channel, and
runtime epoch. Fresh prewarm and completed-work authority plus the
collector-authenticated acknowledgement are cross-bound into final C2/V3
evidence; the consumed one-shot claim is never relabelled or reused.

Production target mode fails closed unless it receives exactly three ordered
source-profile attestations, three matching signatures, and three unique
32-lower-hex launch nonces. Its absolute transition-journal parent must be a
private UID/GID `10001:10001`, mode `0700` directory, and the journal must be
lexically and inode-distinct from collector state and the packaged
controller's existing V3 authority journal. The host runner passes the exact
same `PILOT_ACCEPTANCE_STATE_PATH`, `PILOT_ACCEPTANCE_PROOF_PATH`,
`PILOT_ACCEPTANCE_SNAPSHOT_PATH`, `PILOT_ACCEPTANCE_CHANNEL_PATH`, and
`PILOT_ACCEPTANCE_CAPTURE_PATH` mounted into the controller; it has no local V3
finalizer. The 8-hour and 72-hour raw host command contracts in
`ready_to_start.md` include those requirements and the current
capture/snapshot/proof/operational routes.

This closes the internal continuation blocker only. The commands are
**PENDING external NVIDIA/site execution — NOT RUN**, and their presence does
not establish CUDA, DeepStream, TensorRT, GPU capacity, exact-20 behavior, or
either endurance verdict. Starting the controller alone is not acceptance.
The pending controller start command is:

```bash
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.acceptance.yml \
  up -d acceptance-controller
```

The overlay exposes only host loopback, never mounts `docker.sock`, and uses
the offline-root trust chain plus the protected controller/runtime channel.
Use all required fixtures: exact signed 20-source manifest; five role keys;
reviewed site/runtime/capacity/mount
artifacts; all image, network, model, engine, adapter, observer, and code
digests; exact twenty lawful source secrets or hash-bound replay fixtures;
three ordered source-profile attestations and signatures; the first,
replacement, and continuation launch nonces/channels/epochs; unique-work
projections; an append-only transition journal; operational limits and
evidence; repository boundary; distinct private state/capture/snapshot/proof/
adapter/observer work roots; machine/controller tokens; and new, nonexistent
run/result/attestation/signature/proof/report output paths. Every fixture and
public key has a signed manifest entry, byte size, SHA-256, named reviewer, and
UTC approval. No private key, token, or RTSP value enters that manifest.

Verdicts remain:

- 8-hour exact-20 integration replay: **PENDING external NVIDIA execution**
- 72-hour exact-20 soak: **PENDING external NVIDIA execution**
- measured 25% effective-throughput headroom: **PENDING**
- retention arrival/drain/depth/oldest-age no-growth proof: **PENDING**
- bucket-policy conditional-create and lifecycle-drift proof: **PENDING**
- PostgreSQL migration/role-membership/live-function proof: **PENDING**
- fire/weapon site matrices: **PENDING**
- heavy X-CLIP/ViT and whole-frame OWLv2: **shadow/PENDING**

Never substitute a portable replay, scalar fixture, Apple run, prior report,
hardware datasheet, or ordinary controller exit for signed target evidence.

## Enable the approved notification connector

Telegram remains absent unless the customer approval and fenced network
approval are both signed and `PILOT_TELEGRAM_CUSTOMER_APPROVED=true` and
`PILOT_TELEGRAM_NETWORK_APPROVED=true`.

A **notification-specific PostgreSQL role** and ACL receipt are an additional
prerequisite. The current base role bootstrap does not provision that role, so
do not point `notification_database_url` at the API or owner role and keep the
overlay unselected. Before activation, a reviewed migration/provisioning
change must grant only the finite outbox, delivery-attempt, eligible event,
operator attribution, and redacted audit operations the worker actually
uses. `notification_machine_token` authenticates only notification telemetry
and must be distinct from runtime and monitoring machine credentials. The
`evidence_link_signing_secret` is deliberately the one shared HMAC key mounted
read-only into the API and notification worker so they issue and verify the
same bounded application links. It must never be used as, derived from, or
aliased to any machine credential.

After the role, ACL, customer, and network gates:

```bash
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.telegram.yml \
  up -d api notifications
```

Exercise confirmed, rejected, evidence-pending, expired, duplicate, and
notification-failure drills. Only a human-confirmed, audited candidate may
notify. If either approval is missing, keep the overlay unselected.

## Backup

`Dockerfile.ops` is a digest-pinned, non-root operations image containing the
tools required by `scripts/pilot/backup.sh` and `scripts/pilot/restore.sh`.
The logical `backup_database_url` secret must contain the complete
`[kuzet_backup]` libpq service document expected at `pg_service.conf`; the
logical `backup_object_store_access_key` secret must contain the bounded AWS
shared-credentials document expected at `aws_credentials`. Secret bytes never
belong in Compose or environment variables.

Set the signed site-scoped endpoint/bucket/prefix, config/model manifests,
finite byte/object/run limits, and pre-attested encrypted target. Then:

```bash
export PILOT_BACKUP_TARGET=/srv/kuzet/encrypted-backups
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.backup.yml \
  run --rm backup
```

Archive the encrypted bundle, signed checksum manifest, and pending restore
receipt. A successful backup process is not acceptance.

## Fresh-target restore drill

The source backup directory must be read-only. The target database must be
empty and separately named. `PILOT_RESTORE_EVIDENCE_NAME` must not exist
beneath the signed encrypted parent, and the signed restore-receipt directory
is a separate writable bind:

```bash
export PILOT_RESTORE_SOURCE=/srv/kuzet/encrypted-backups/backup-YYYYMMDDTHHMMSSZ
export PILOT_RESTORE_DATABASE_NAME=kuzet_restore_drill_YYYYMMDD
export PILOT_RESTORE_EVIDENCE_PARENT=/srv/kuzet/restore-drill
export PILOT_RESTORE_EVIDENCE_NAME=evidence-YYYYMMDD
export PILOT_RESTORE_RECEIPT_TARGET=/srv/kuzet/restore-receipts

test ! -e \
  "${PILOT_RESTORE_EVIDENCE_PARENT}/${PILOT_RESTORE_EVIDENCE_NAME}"

docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.restore.yml \
  run --rm restore
```

Before restore, set the expected migration revision, exact configuration/model
SHA-256 values, finite bounds, and every external secret used by
`scripts/pilot/restore.sh`. Acceptance requires a signed receipt whose exact
terminal line is `status=verified_fresh_target_restore`; container exit alone
is insufficient. Archive and verify the receipt before removing drill
resources.

## Credential rotation, stop, and rollback

Create new database, API session, TOTP-envelope, machine, object-store,
notification, signing, backup-encryption, and TLS material in the approved
secret manager. Update only bound consumers, verify health/authentication,
then revoke old material. TOTP master-key rotation requires a reviewed
re-encryption migration; never treat it as an ordinary environment edit.
Record operator, UTC time, old/new key identifiers, affected services, and
verification result—never secret bytes.

For an orderly stop, disable notification delivery, stop the runtime, drain
terminal audit transitions, and then stop the core. Set each selection flag to
`true` only when that overlay was actually rendered and started; an absent
optional overlay must not be interpolated during shutdown:

```bash
if [ "${PILOT_TELEGRAM_OVERLAY_SELECTED:-false}" = true ]; then
  docker compose \
    -f deploy/pilot/docker-compose.yml \
    -f deploy/pilot/docker-compose.telegram.yml \
    stop notifications
fi
if [ "${PILOT_RUNTIME_OVERLAY_SELECTED:-false}" = true ]; then
  docker compose \
    -f deploy/pilot/docker-compose.yml \
    -f deploy/pilot/docker-compose.runtime.yml \
    stop runtime
fi
if [ "${PILOT_ACCEPTANCE_OVERLAY_SELECTED:-false}" = true ]; then
  docker compose \
    -f deploy/pilot/docker-compose.yml \
    -f deploy/pilot/docker-compose.acceptance.yml \
    stop acceptance-controller
fi
docker compose -f deploy/pilot/docker-compose.yml down
```

Rollback only to the digest-pinned bundle in the handover manifest. The bundle
must bind the previous source commit, linux/amd64 image digests, rendered
Compose/configuration/mount hashes, model/artifact/engine/build-receipt hashes,
migration head, secret key identifiers, storage policy/lifecycle digests,
source manifest, and signed pre-change backup/fresh-target restore receipt.
Verify every digest before an endpoint switch.

Do not use an in-place `alembic downgrade`, overwrite the active database, or
delete its audit journal, bounded evidence, acceptance proof, or restore
receipt. Restore the signed pre-change bundle into a new empty database and
new evidence target with the exact restore command above. Require the terminal
`status=verified_fresh_target_restore`, verify the old expected migration head,
role/identity probes, audit continuity, bounded object hashes, and application
health against the old digest bundle, then obtain named customer/deployment
approval for the controlled endpoint switch. Preserve the failed/current
target read-only for investigation until retention and incident policy permit
removal. If a fresh target cannot be restored and verified, rollback is
**BLOCKED** and the pilot remains stopped.

Any changed host, image, configuration, model, engine, source identity,
storage policy, or rollback target invalidates the relevant gates and requires
fresh acceptance.

## Handover

Archive the signed 8-hour and 72-hour reports, proof metadata, raw bounded
metrics, restore receipt, source/field matrices, model register, rendered
Compose inventory, image/configuration/migration hashes, training records,
support roster, and signed exception list. Until every mandatory row in the
handover manifest is complete and reviewed, status remains **PENDING** and the
pilot stays disabled or shadow-only.
