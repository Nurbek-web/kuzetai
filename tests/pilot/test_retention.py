from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import yaml
from sqlalchemy import select

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.retention import EvidenceRetentionCoordinator
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditEntryModel,
    Base,
    CandidateEventModel,
    EvidenceModel,
)
from protector.pilot.storage.object_store import ObjectPublishError
from protector.pilot.storage.repositories import AuditEntryInput, EvidenceInput, PilotRepository

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).parents[2]


class RecordingStore:
    def __init__(self, *, fail_keys: set[str] | None = None) -> None:
        self.deleted: list[str] = []
        self.fail_keys = fail_keys or set()

    def delete(self, key: str) -> None:
        if key in self.fail_keys:
            raise ObjectPublishError("generic retention failure")
        self.deleted.append(key)


def _repository(tmp_path: Path) -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'retention.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    for site_id in ("site-1", "site-2"):
        repository.add_site(site_id=site_id, name=site_id)
        repository.add_camera(
            camera_id=f"{site_id}-cam",
            site_id=site_id,
            name="Camera",
            source_reference=f"rtsp://private/{site_id}",
            codec="h264",
        )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            analytic="person",
            sha256="a" * 64,
            source="registry://private",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights",
                terms_reference="legal://rights",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox",
        )
    )
    return repository


def _add_evidence(
    repository: PilotRepository,
    *,
    site_id: str,
    created_at: datetime,
    suffix: str,
) -> tuple[str, str]:
    event_id = uuid4()
    evidence_id = uuid4()
    repository.add_event(
        CandidateEventV1(
            schema_version="candidate-event.v1",
            event_id=event_id,
            camera_id=f"{site_id}-cam",
            module="person",
            opened_at=created_at,
            last_seen_at=created_at + timedelta(seconds=2),
            peak_confidence=0.8,
            reason="candidate",
            model_artifact_id="person-v1",
            gate_mode="operator",
            evidence_status="ready",
            review_status="candidate",
        )
    )
    key = f"events/{site_id}/{suffix}.mp4"
    repository.add_evidence(
        EvidenceInput(
            evidence_id=evidence_id,
            event_id=event_id,
            object_key=key,
            sha256="b" * 64,
            codec="h264",
            start_at=created_at,
            end_at=created_at + timedelta(seconds=4),
            source_reference="encoded-ring://private",
            status="ready",
        )
    )
    with repository.session_factory.begin() as session:
        session.get(EvidenceModel, str(evidence_id)).created_at = created_at
    return str(event_id), key


def test_retention_is_bounded_site_scoped_exact_cutoff_and_idempotent(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    old_one = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=31, seconds=1),
        suffix="old-1",
    )
    old_two = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=32),
        suffix="old-2",
    )
    exact = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=30),
        suffix="exact",
    )
    foreign = _add_evidence(
        repository,
        site_id="site-2",
        created_at=NOW - timedelta(days=90),
        suffix="foreign",
    )
    store = RecordingStore()
    coordinator = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=1,
        clock=lambda: NOW,
    )

    first = coordinator.run_once()
    second = coordinator.run_once()
    third = coordinator.run_once()

    assert first.scanned == second.scanned == 1
    assert first.deleted == second.deleted == 1
    assert third.scanned == third.deleted == third.failed == 0
    assert set(store.deleted) == {old_one[1], old_two[1]}
    assert exact[1] not in store.deleted
    assert foreign[1] not in store.deleted
    with repository.session_factory() as session:
        rows = list(session.scalars(select(EvidenceModel)))
        states = {row.object_key: row.status for row in rows}
        event_states = {
            row.event_id: row.evidence_status
            for row in session.scalars(select(CandidateEventModel))
        }
    assert old_one[1] not in states
    assert old_two[1] not in states
    assert states[exact[1]] == "ready"
    assert states[foreign[1]] == "ready"
    assert event_states[old_one[0]] == "unavailable"
    assert event_states[old_two[0]] == "unavailable"


def test_retention_partial_failure_fails_closed_and_never_mutates_audit(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    failed = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="failed",
    )
    succeeded = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=50),
        suffix="succeeded",
    )
    repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.guard",
            entity_type="site",
            entity_id="site-1",
            payload={"bounded": True},
            idempotency_key="retention-audit",
            occurred_at=NOW - timedelta(days=400),
        )
    )
    store = RecordingStore(fail_keys={failed[1]})
    result = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()

    assert result.scanned == 2
    assert result.deleted == 1
    assert result.failed == 1
    assert result.retained == 1
    assert result.failure_reasons == ("object_delete_failed",)
    with repository.session_factory() as session:
        rows = {row.object_key: row.status for row in session.scalars(select(EvidenceModel))}
        audit = list(session.scalars(select(AuditEntryModel)))
    assert rows[failed[1]] == "unavailable"
    assert succeeded[1] not in rows
    assert len(audit) == 1

    store.fail_keys.clear()
    retried = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()
    assert retried.deleted == 1
    with repository.session_factory() as session:
        assert session.scalar(
            select(EvidenceModel).where(EvidenceModel.object_key == failed[1])
        ) is None


def test_failed_tombstone_retry_cannot_starve_newer_ready_expiry(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    oldest = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=90),
        suffix="permanent-failure",
    )
    newer = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="newer-ready",
    )
    store = RecordingStore(fail_keys={oldest[1]})
    coordinator = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=1,
        clock=lambda: NOW,
    )

    assert coordinator.run_once().failed == 1
    assert coordinator.run_once().deleted == 1
    assert newer[1] in store.deleted


def test_expiring_one_clip_keeps_event_ready_while_another_ready_clip_remains(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    event_id, old_key = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="old-clip",
    )
    newer_evidence_id = uuid4()
    newer_key = "events/site-1/newer-clip.mp4"
    repository.add_evidence(
        EvidenceInput(
            evidence_id=newer_evidence_id,
            event_id=UUID(event_id),
            object_key=newer_key,
            sha256="c" * 64,
            codec="h264",
            start_at=NOW - timedelta(days=1),
            end_at=NOW - timedelta(days=1) + timedelta(seconds=4),
            source_reference="encoded-ring://private",
            status="ready",
        )
    )
    with repository.session_factory.begin() as session:
        session.get(EvidenceModel, str(newer_evidence_id)).created_at = NOW - timedelta(days=1)

    result = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=RecordingStore(),
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()

    assert result.deleted == 1
    with repository.session_factory() as session:
        event = session.get(CandidateEventModel, event_id)
        keys = set(session.scalars(select(EvidenceModel.object_key)))
    assert event.evidence_status == "ready"
    assert old_key not in keys
    assert newer_key in keys


@pytest.mark.parametrize(
    ("site_id", "retention_days", "batch_size"),
    (("", 30, 10), ("site-1", 0, 10), ("site-1", 30, 0), ("x" * 129, 30, 10)),
)
def test_retention_configuration_is_finite_and_bounded(
    tmp_path: Path,
    site_id: str,
    retention_days: int,
    batch_size: int,
) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(ValueError):
        EvidenceRetentionCoordinator(
            session_factory=repository.session_factory,
            object_store=RecordingStore(),
            pilot_site_id=site_id,
            retention_days=retention_days,
            batch_size=batch_size,
            clock=lambda: NOW,
        )


def test_backup_and_restore_refuse_unsafe_targets_before_invoking_tools(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    (unsafe / "unrelated").write_text("preserve")
    common = {
        **os.environ,
        "PILOT_SITE_ID": "site-1",
        "PILOT_BACKUP_TARGET": str(unsafe),
    }

    backup = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/pilot/backup.sh")],
        env=common,
        text=True,
        capture_output=True,
        check=False,
    )
    assert backup.returncode != 0
    assert "marker" in backup.stderr.lower()
    assert (unsafe / "unrelated").read_text() == "preserve"

    restore_target = tmp_path / "existing-restore"
    restore_target.mkdir()
    (restore_target / "keep").write_text("keep")
    restore = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/pilot/restore.sh")],
        env={
            **common,
            "PILOT_RESTORE_SOURCE": str(tmp_path / "missing-backup"),
            "PILOT_RESTORE_DATABASE_NAME": "fresh_restore",
            "PILOT_RESTORE_EVIDENCE_TARGET": str(restore_target),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert restore.returncode != 0
    assert (restore_target / "keep").read_text() == "keep"


def test_fake_tools_prove_backup_pending_then_fresh_restore_receipt(tmp_path: Path) -> None:
    secret_root = tmp_path / "fixed-secrets"
    secret_root.mkdir()
    for name, value in {
        "pg_service.conf": "[kuzet_backup]\ndbname=source_db\n",
        "pg_restore_service.conf": "[kuzet_restore]\ndbname=fresh_restore\n",
        "pgpass": "*:*:*:*:fixture-only\n",
        "backup_age_recipient": "age1fixture\n",
        "backup_age_identity": "AGE-SECRET-KEY-FIXTURE\n",
        "backup_signing_private_key": "fixture-private-signing-key\n",
        "backup_signing_public_key": "fixture-public-signing-key\n",
        "aws_credentials": "[default]\nfixture=yes\n",
        "kz_storage_attestation_public_key": "fixture-public-key\n",
    }.items():
        (secret_root / name).write_text(value)

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()

    def tool(name: str, body: str) -> None:
        path = fake_bin / name
        path.write_text(body)
        path.chmod(0o700)

    tool(
        "age",
        """#!/bin/bash
set -eu
out=
input=
while (($#)); do
  case "$1" in
    --output) out=$2; shift 2 ;;
    --recipients-file|--identity) shift 2 ;;
    --decrypt) shift ;;
    *) input=$1; shift ;;
  esac
done
if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then
  printf 'age\n' >> "$FAKE_TOOL_TRACE"
fi
cp "$input" "$out"
if [[ -n ${FAKE_DECRYPT_DATABASE_BYTES:-} && "$input" = *database.dump.age ]]; then
  python3 - "$out" "$FAKE_DECRYPT_DATABASE_BYTES" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("r+b") as output:
    output.truncate(int(sys.argv[2]))
PY
fi
""",
    )
    tool(
        "openssl",
        """#!/bin/bash
set -eu
mode=
key=
signature=
output=
input=
while (($#)); do
  case "$1" in
    dgst|-sha256) shift ;;
    -sign) mode=sign; key=$2; shift 2 ;;
    -verify) mode=verify; key=$2; shift 2 ;;
    -signature) signature=$2; shift 2 ;;
    -out) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
case "$mode" in
  sign)
    [[ "$key" = */backup_signing_private_key ]]
    sha256sum "$input" | awk '{print $1}' > "$output"
    ;;
  verify)
    case "$key" in
      */backup_signing_public_key)
        expected=$(sha256sum "$input" | awk '{print $1}')
        actual=$(cat "$signature")
        [[ "$actual" = "$expected" ]]
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 2 ;;
esac
""",
    )
    tool(
        "pg_dump",
        """#!/bin/bash
set -eu
for argument in "$@"; do
  case "$argument" in --file=*) output=${argument#--file=} ;; esac
done
if [[ -n ${FAKE_DUMP_BYTES:-} ]]; then
  python3 - "$output" "$FAKE_DUMP_BYTES" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("wb") as output:
    output.truncate(int(sys.argv[2]))
PY
else
  printf FAKE_DATABASE_DUMP > "$output"
fi
""",
    )
    tool(
        "psql",
        """#!/bin/bash
set -eu
if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then
  printf 'psql\n' >> "$FAKE_TOOL_TRACE"
fi
arguments="$*"
case "$arguments" in
  *pg_database_size*) printf '%s\n' "${FAKE_DATABASE_BYTES:-18}" ;;
  *current_database*) printf '%s\n' "${FAKE_TARGET_DB:-source_db}" ;;
  *information_schema.tables*) printf '0\n' ;;
  *version_num*) printf '0003_notification_delivery\n' ;;
  *"SELECT site_id"*) printf 'site-1\n' ;;
  *) exit 2 ;;
esac
""",
    )
    tool(
        "pg_restore",
        """#!/bin/bash
set -eu
if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then
  printf 'pg_restore\n' >> "$FAKE_TOOL_TRACE"
fi
case " $* " in *" --list "*) printf 'fixture archive\n' ;; *) : ;; esac
""",
    )
    tool(
        "aws",
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

arguments = sys.argv[1:]
if "list-objects-v2" in arguments:
    assert arguments[arguments.index("--prefix") + 1] == "pilot-evidence/site-1/"
    key = os.environ.get("FAKE_INVENTORY_KEY", "event.mp4")
    print(json.dumps({"Contents": [{"Key": f"pilot-evidence/site-1/{key}", "Size": 5}]}))
elif "sync" in arguments:
    index = arguments.index("sync")
    assert arguments[index + 1] == "s3://pilot-evidence/pilot-evidence/site-1/"
    destination = pathlib.Path(arguments[index + 2])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "event.mp4").write_bytes(b"video")
else:
    raise SystemExit(2)
""",
    )

    fixture_scripts = tmp_path / "scripts"
    fixture_scripts.mkdir()
    for name in ("backup.sh", "restore.sh"):
        source = REPO_ROOT / "scripts/pilot" / name
        fixture = fixture_scripts / name
        fixture.write_text(source.read_text().replace("/run/secrets", str(secret_root)))
        fixture.chmod(0o700)

    backup_target = tmp_path / "encrypted-backups"
    backup_target.mkdir()
    (backup_target / ".kuzet-pilot-backup-target.v1").write_text(
        "schema=kuzet-pilot-backup-target.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (backup_target / ".kuzet-pilot-backup-target.v1.sig").write_text("fixture-signature\n")
    config = tmp_path / "site.yaml"
    model = tmp_path / "model-register.json"
    config.write_text("site: site-1\n")
    model.write_text('{"model":"person-v1"}\n')
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PILOT_SITE_ID": "site-1",
        "PILOT_BACKUP_TARGET": str(backup_target),
        "PILOT_KZ_OBJECT_ENDPOINT": "https://objects.example.kz",
        "PILOT_EVIDENCE_BUCKET": "pilot-evidence",
        "PILOT_EVIDENCE_PREFIX": "pilot-evidence",
        "PILOT_CONFIG_MANIFEST": str(config),
        "PILOT_MODEL_MANIFEST": str(model),
    }
    mismatch_target = tmp_path / "mismatch-backups"
    mismatch_target.mkdir()
    (mismatch_target / ".kuzet-pilot-backup-target.v1").write_text(
        "schema=kuzet-pilot-backup-target.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (mismatch_target / ".kuzet-pilot-backup-target.v1.sig").write_text(
        "fixture-signature\n"
    )
    mismatch = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(mismatch_target),
            "FAKE_INVENTORY_KEY": "same-size-substitute.mp4",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "does not match inventory" in mismatch.stderr
    assert not list(mismatch_target.glob("backup-*"))

    reserved_target = tmp_path / "reserved-key-backups"
    reserved_target.mkdir()
    (reserved_target / ".kuzet-pilot-backup-target.v1").write_text(
        "schema=kuzet-pilot-backup-target.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (reserved_target / ".kuzet-pilot-backup-target.v1.sig").write_text(
        "fixture-signature\n"
    )
    reserved = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(reserved_target),
            "FAKE_INVENTORY_KEY": "evidence-files.sha256",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert reserved.returncode != 0
    assert "reserved" in reserved.stderr

    oversized_database_target = tmp_path / "oversized-database-backups"
    oversized_database_target.mkdir()
    (oversized_database_target / ".kuzet-pilot-backup-target.v1").write_text(
        "schema=kuzet-pilot-backup-target.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (oversized_database_target / ".kuzet-pilot-backup-target.v1.sig").write_text(
        "fixture-signature\n"
    )
    oversized_database = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(oversized_database_target),
            "FAKE_DATABASE_BYTES": "10737418241",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_database.returncode != 0
    assert "database size exceeds" in oversized_database.stderr
    assert not list(oversized_database_target.glob("backup-*"))

    oversized_dump_target = tmp_path / "oversized-dump-backups"
    oversized_dump_target.mkdir()
    (oversized_dump_target / ".kuzet-pilot-backup-target.v1").write_text(
        "schema=kuzet-pilot-backup-target.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (oversized_dump_target / ".kuzet-pilot-backup-target.v1.sig").write_text(
        "fixture-signature\n"
    )
    oversized_dump = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(oversized_dump_target),
            "PILOT_BACKUP_MAX_DATABASE_BYTES": "16",
            "FAKE_DATABASE_BYTES": "16",
            "FAKE_DUMP_BYTES": "17",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_dump.returncode != 0
    assert "database dump exceeds" in oversized_dump.stderr
    assert not list(oversized_dump_target.glob("backup-*"))

    backup = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert backup.returncode == 0, backup.stderr
    assert "acceptance remains pending" in backup.stdout
    backup_runs = list(backup_target.glob("backup-*"))
    assert len(backup_runs) == 1
    assert {path.name for path in backup_runs[0].iterdir()} == {
        "backup-receipt.txt.age",
        "checksums.sha256",
        "checksums.sha256.sig",
        "config-manifest.age",
        "database.dump.age",
        "evidence.tar.age",
        "manifest.txt.age",
        "model-manifest.age",
    }
    assert "pending_fresh_target_restore" in (
        backup_runs[0] / "backup-receipt.txt.age"
    ).read_text()

    volume = tmp_path / "encrypted-volume"
    volume.mkdir()
    (volume / ".kuzet-pilot-encrypted-volume.v1").write_text(
        "schema=kuzet-pilot-encrypted-volume.v1\n"
        "site_id=site-1\n"
        "country=KZ\n"
        "encrypted=true\n"
    )
    (volume / ".kuzet-pilot-encrypted-volume.v1.sig").write_text("fixture-signature\n")
    receipts = tmp_path / "restore-receipts"
    receipts.mkdir()
    (receipts / ".kuzet-pilot-restore-receipts.v1").write_text(
        "schema=kuzet-pilot-restore-receipts.v1\nsite_id=site-1\n"
    )
    (receipts / ".kuzet-pilot-restore-receipts.v1.sig").write_text("fixture-signature\n")
    restore_environment = {
        **environment,
        "FAKE_TARGET_DB": "fresh_restore",
        "PILOT_RESTORE_SOURCE": str(backup_runs[0]),
        "PILOT_RESTORE_DATABASE_NAME": "fresh_restore",
        "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "restored-site-1"),
        "PILOT_RESTORE_RECEIPT_TARGET": str(receipts),
        "PILOT_EXPECTED_SCHEMA_REVISION": "0003_notification_delivery",
        "PILOT_EXPECTED_CONFIG_SHA256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "PILOT_EXPECTED_MODEL_SHA256": hashlib.sha256(model.read_bytes()).hexdigest(),
    }

    forged_backup = tmp_path / "forged-backup"
    shutil.copytree(backup_runs[0], forged_backup)
    canonical_artifacts = (
        "database.dump.age",
        "evidence.tar.age",
        "manifest.txt.age",
        "backup-receipt.txt.age",
        "config-manifest.age",
        "model-manifest.age",
    )
    for artifact in canonical_artifacts:
        (forged_backup / artifact).write_bytes(f"attacker-replaced-{artifact}".encode())
    (forged_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((forged_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    forged_trace = tmp_path / "forged-restore-tools.log"
    forged_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(forged_trace),
            "PILOT_RESTORE_SOURCE": str(forged_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-forged"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert forged_restore.returncode != 0
    assert "signature" in forged_restore.stderr
    assert not forged_trace.exists()
    assert not (volume / "rejected-forged").exists()

    oversized_ciphertext_backup = tmp_path / "oversized-ciphertext-backup"
    shutil.copytree(backup_runs[0], oversized_ciphertext_backup)
    with (oversized_ciphertext_backup / "database.dump.age").open("r+b") as artifact:
        artifact.truncate(1_048_593)
    (oversized_ciphertext_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((oversized_ciphertext_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (oversized_ciphertext_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (oversized_ciphertext_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    oversized_ciphertext_trace = tmp_path / "oversized-ciphertext-tools.log"
    oversized_ciphertext_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(oversized_ciphertext_trace),
            "PILOT_RESTORE_SOURCE": str(oversized_ciphertext_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-oversized-ciphertext"
            ),
            "PILOT_RESTORE_MAX_DATABASE_BYTES": "16",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_ciphertext_restore.returncode != 0
    assert "encrypted database dump exceeds" in oversized_ciphertext_restore.stderr
    assert not oversized_ciphertext_trace.exists()
    assert not (volume / "rejected-oversized-ciphertext").exists()

    oversized_plaintext_trace = tmp_path / "oversized-plaintext-tools.log"
    oversized_plaintext_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(oversized_plaintext_trace),
            "FAKE_DECRYPT_DATABASE_BYTES": "33",
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-oversized-plaintext"
            ),
            "PILOT_RESTORE_MAX_DATABASE_BYTES": "32",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_plaintext_restore.returncode != 0
    assert "decrypted database dump exceeds" in oversized_plaintext_restore.stderr
    assert set(oversized_plaintext_trace.read_text().splitlines()) == {"age"}
    assert not (volume / "rejected-oversized-plaintext").exists()

    inconsistent_manifest_backup = tmp_path / "inconsistent-manifest-backup"
    shutil.copytree(backup_runs[0], inconsistent_manifest_backup)
    (inconsistent_manifest_backup / "config-manifest.age").write_text(
        "site: attacker-replacement\n"
    )
    (inconsistent_manifest_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((inconsistent_manifest_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (inconsistent_manifest_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (inconsistent_manifest_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    inconsistent_trace = tmp_path / "inconsistent-manifest-tools.log"
    inconsistent_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(inconsistent_trace),
            "PILOT_RESTORE_SOURCE": str(inconsistent_manifest_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-inconsistent-manifest"
            ),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert inconsistent_restore.returncode != 0
    assert "configuration/model manifest integrity" in inconsistent_restore.stderr
    assert set(inconsistent_trace.read_text().splitlines()) == {"age"}
    assert not (volume / "rejected-inconsistent-manifest").exists()

    malicious_backup = tmp_path / "malicious-backup"
    shutil.copytree(backup_runs[0], malicious_backup)
    unpacked = tmp_path / "malicious-evidence"
    unpacked.mkdir()
    with tarfile.open(malicious_backup / "evidence.tar.age") as archive:
        archive.extractall(unpacked, filter="data")
    (unpacked / "unexpected-same-bound.mp4").write_bytes(b"")
    with tarfile.open(malicious_backup / "evidence.tar.age", "w") as archive:
        archive.add(unpacked, arcname=".")
    (malicious_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((malicious_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (malicious_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (malicious_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    rejected = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "PILOT_RESTORE_SOURCE": str(malicious_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-extra"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "file set does not match" in rejected.stderr
    assert not (volume / "rejected-extra").exists()

    member_bomb_backup = tmp_path / "member-bomb-backup"
    shutil.copytree(backup_runs[0], member_bomb_backup)
    member_bomb = tmp_path / "member-bomb-evidence"
    member_bomb.mkdir()
    with tarfile.open(member_bomb_backup / "evidence.tar.age") as archive:
        archive.extractall(member_bomb, filter="data")
    for index in range(40):
        (member_bomb / f"empty-{index:02d}").mkdir()
    with tarfile.open(member_bomb_backup / "evidence.tar.age", "w") as archive:
        archive.add(member_bomb, arcname=".")
    (member_bomb_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((member_bomb_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (member_bomb_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (member_bomb_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    member_bomb_result = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "PILOT_RESTORE_SOURCE": str(member_bomb_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-member-bomb"),
            "PILOT_RESTORE_MAX_EVIDENCE_OBJECTS": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert member_bomb_result.returncode != 0
    assert "member bound" in member_bomb_result.stderr
    assert not (volume / "rejected-member-bomb").exists()

    restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env=restore_environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert restore.returncode == 0, restore.stderr
    assert (volume / "restored-site-1/event.mp4").read_bytes() == b"video"
    restore_receipts = list(receipts.glob("restore-drill-*/restore-drill-receipt.age"))
    assert len(restore_receipts) == 1
    assert "status=verified_fresh_target_restore" in restore_receipts[0].read_text()
    assert restore_receipts[0].with_suffix(".age.sha256").exists()


def test_deployment_and_backup_artifacts_are_hardened_and_secret_free() -> None:
    compose = (REPO_ROOT / "deploy/pilot/docker-compose.yml").read_text()
    dockerfile = (REPO_ROOT / "deploy/pilot/Dockerfile.api").read_text()
    prometheus = (REPO_ROOT / "deploy/pilot/prometheus.yml").read_text()
    backup = (REPO_ROOT / "scripts/pilot/backup.sh").read_text()
    restore = (REPO_ROOT / "scripts/pilot/restore.sh").read_text()
    nginx = (REPO_ROOT / "deploy/pilot/nginx.conf").read_text()
    api_lock = (REPO_ROOT / "deploy/pilot/api-requirements.lock").read_text()
    parsed = yaml.safe_load(compose)

    assert "network_mode: host" not in compose
    assert "privileged: true" not in compose
    assert "/var/run/docker.sock" not in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "@sha256:" in compose
    assert "PILOT_API_IMAGE_SHA256" in compose
    assert "internal: true" in compose
    assert "/run/secrets" in compose
    assert "resources:" in compose
    assert "max-size:" in compose
    assert "0.0.0.0:" not in compose
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "api-requirements.lock" in dockerfile
    assert "@sha256:" in dockerfile
    assert "retention" in prometheus
    assert "credentials_file" in prometheus
    assert parsed["services"]["tls-proxy"]["ports"]
    assert set(parsed["services"]) == {"postgres", "api", "tls-proxy", "prometheus"}
    assert all(
        service.get("pids_limit", 0) > 0 for service in parsed["services"].values()
    )
    assert "TLSv1.2 TLSv1.3" in nginx
    assert "location ^~ /internal/" in nginx
    assert "X-Forwarded-Proto https" in nginx
    assert "torch==" not in api_lock
    assert "opencv" not in api_lock
    assert "gradio" not in api_lock
    assert "pg_dump" in backup and "--format=custom" in backup
    assert "--page-size 1000" in backup
    assert "--query" in backup
    assert "age" in backup and "sha256sum" in backup
    assert "openssl dgst -sha256 -verify" in backup
    assert "pg_restore" in restore and "--exit-on-error" in restore
    assert "openssl dgst -sha256 -verify" in restore
    assert "--single-transaction" in restore
    assert "restore-drill-receipt" in restore
    assert 'runtime_lock_path="/tmp/kuzet-api.lock"' in (
        REPO_ROOT / "protector/pilot/api/production.py"
    ).read_text()
    combined = "\n".join((compose, dockerfile, prometheus, backup, restore))
    assert "POSTGRES_PASSWORD=" not in combined
    assert "PILOT_SESSION_SECRET=" not in combined
    assert "AKIA" not in combined

    for script in ("backup.sh", "restore.sh"):
        syntax = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / "scripts/pilot" / script)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr
