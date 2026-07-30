# Controlled-pilot deployment runbook

Status: **PENDING external NVIDIA/site execution**. Local Apple M2 tests verify
contracts and fake/replay behavior only. They do not authorize a 20-camera
deployment.

## Authoritative gates

This runbook coordinates, but does not replace:

- [Ready-to-Start](../../docs/pilot/ready_to_start.md)
- [Target acceptance](../../deploy/pilot/TARGET_ACCEPTANCE.md)
- [Network policy](../../deploy/pilot/NETWORK_POLICY.md)
- [Audit retention](../../deploy/pilot/AUDIT_RETENTION.md)

Use a **fresh target** acceptance campaign whenever the host, image,
configuration, model/engine, exact 20-source manifest, or frozen workload
changes.

## Preflight

1. Provision a Linux NVIDIA node and verify driver, CUDA, container-toolkit,
   Docker/Compose, NTP, DNS, TLS, PostgreSQL, Kazakhstan-resident bounded
   evidence storage, local encrypted spool, and customer NVR connectivity.
2. Complete the signed source manifest for exactly 20 lawful named streams or
   frozen replay fixtures. Continuous raw video remains in the customer NVR.
3. Complete model rights, artifact and engine hashes, site quality matrices,
   capacity inputs, field/privacy approval, named operators, and exception
   ownership. Missing input is a fail-closed result.
4. Install secrets from the approved secret manager or root-owned mounted
   paths. Never place credentials or private signing keys in the repository,
   compose file, image, or command history.
5. Record digest-pinned container references, configuration hash, migration
   revision, model/engine hashes, and reviewers in
   [handover_manifest.md](handover_manifest.md).

## Configure, validate, and start

```bash
cp configs/pilot.example.yaml /etc/kuzet/pilot.yaml
uv run python scripts/pilot/provision.py --help
uv run python scripts/pilot/validate_runtime_mounts.py --help
docker compose -f deploy/pilot/docker-compose.yml config
docker compose -f deploy/pilot/docker-compose.yml up -d postgres
docker compose -f deploy/pilot/docker-compose.yml run --rm role-bootstrap
docker compose -f deploy/pilot/docker-compose.yml run --rm migrate
docker compose -f deploy/pilot/docker-compose.yml run --rm role-grants
docker compose -f deploy/pilot/docker-compose.yml run --rm provision
docker compose -f deploy/pilot/docker-compose.yml up -d api retention tls-proxy prometheus
```

Populate site-specific values through reviewed configuration and secret mounts;
do not commit the resulting file. Validate that the inference runtime uses one
shared multistream graph/model stack rather than one stack per camera, and that
queues, evidence, and local spool are bounded.

The `migrate` job invokes `/app/scripts/pilot/migrate.py` as the one-shot
migration identity. The provisioning job invokes
`/app/scripts/pilot/provision.py`; `scripts/pilot/validate_runtime_mounts.py`
is the authoritative mount validator. Verify health, readiness, source
supervision, camera identity, metrics, audit continuity, object-store access,
and notification egress before enabling operator access.

## Acceptance

Follow `TARGET_ACCEPTANCE.md` exactly on the NVIDIA host with the frozen workload:

- exact 20 simultaneous sources;
- 8-hour integration replay with required failure injection;
- 72-hour continuous soak;
- measured effective throughput with at least 25% headroom;
- GPU at or below 75%, VRAM at or below 80%, scheduled drops below 1%;
- queue age, recovery, event latency, evidence latency, disk, exception, audit,
  and confirmation/notification gates.

Do not substitute synthetic scalar inputs, an Apple run, a previous report, or
hardware marketing claims. Archive signed reports and raw bounded metrics. Fire
and weapon quality matrices are independent; heavy violence analytics stay
shadow until separately approved.

## Credential rotation

Create new database, API session, TOTP-envelope, machine, object-store,
notification, signing, backup-encryption, and TLS material in the approved
secret manager. Update the corresponding external Docker secret, restart only
the bound consumers, verify health and authentication, and then revoke the old
material. TOTP master-key rotation requires a reviewed re-encryption migration;
never replace it as an ordinary environment edit. Record the operator, UTC
time, old/new key identifiers (not secret bytes), affected services, and
verification result.

## Stop, rollback, backup, and restore

For an orderly stop, disable approved notification delivery, drain terminal
audit transitions, then run:

```bash
docker compose -f deploy/pilot/docker-compose.yml down
```

Rollback only to the digest-pinned, migration-compatible bundle in the handover
manifest. The hardened backup and fresh-target restore entrypoints are
`scripts/pilot/backup.sh` and `scripts/pilot/restore.sh`. Run them only through
the separately selected operations jobs, with their documented external
secrets and signed storage markers:

```bash
export PILOT_BACKUP_TARGET=/srv/kuzet/encrypted-backups
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.backup.yml \
  run --rm backup

export PILOT_RESTORE_SOURCE=/srv/kuzet/encrypted-backups/backup-YYYYMMDDTHHMMSSZ
export PILOT_RESTORE_DATABASE_NAME=kuzet_restore_drill_YYYYMMDD
export PILOT_RESTORE_EVIDENCE_TARGET=/srv/kuzet/restore-drill/evidence-YYYYMMDD
export PILOT_RESTORE_RECEIPT_TARGET=/srv/kuzet/restore-receipts
docker compose \
  -f deploy/pilot/docker-compose.yml \
  -f deploy/pilot/docker-compose.restore.yml \
  run --rm restore
```

Before backup, also set the signed site-scoped storage endpoint/bucket/prefix,
configuration/model manifests, byte/object bounds, and external secrets
required by `scripts/pilot/backup.sh`. Before restore, set the expected
migration revision plus exact configuration/model SHA-256 values and every
external secret required by `scripts/pilot/restore.sh`. The drill passes only
when the signed receipt contains `status=verified_fresh_target_restore`;
container exit alone is insufficient.

Restore the database, audit journal, bounded evidence metadata, and object
store into separately named fresh targets. Archive the receipt before removing
the drill resources. After rollback or restore, verify audit continuity and
repeat all invalidated gates.

## Handover

Archive the signed 72-hour report, 8-hour report, restore-drill output, source
and field matrices, model register, configuration, digests, training records,
and signed exception list. Until every mandatory item is complete, keep the
manifest PENDING and the controlled pilot disabled or shadow-only.
