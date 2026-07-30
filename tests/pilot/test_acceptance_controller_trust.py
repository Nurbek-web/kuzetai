from __future__ import annotations

import inspect
import json
import os
import sqlite3
import subprocess
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

import protector.pilot.api.acceptance_controller as controller_module
import scripts.pilot.replay_20 as replay_module
from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    source_profiles_sha256,
)
from protector.pilot.acceptance_authority import (
    AcceptanceAuthority,
    AcceptanceAuthorityTrustContextV2,
    AcceptanceTrustBindingV2,
    SQLiteAcceptanceAuthorityJournal,
    build_authority_trust_context,
)
from protector.pilot.api.acceptance_controller import (
    OpenSSLAcceptanceRunSigner,
    build_production_acceptance_authority,
    create_acceptance_controller_app,
)
from scripts.pilot.replay_20 import AuthenticatedTargetCollector
from tests.pilot.acceptance_trust_helpers import (
    authority_trust_context as _context,
)
from tests.pilot.test_acceptance_authority import (
    AdapterBackedEffectExecutor,
    ControlledClock,
    NonDestructiveObservedAdapter,
    _binding,
    _execution,
    _protected_journal_namespace,
    _workloads,
)
from tests.pilot.test_acceptance_report import _manifest, _run
from tests.pilot.test_acceptance_trust import (
    _bundle,
    _Key,
    _verify,
)

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)


def _verified_controller_context(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> AcceptanceAuthorityTrustContextV2:
    trust_root = tmp_path / "verified-controller-chain"
    trust_root.mkdir()
    trust = _verify(_bundle(trust_root, key_material))
    return build_authority_trust_context(
        trust=trust,
        configured_site_id=trust.policy.site_id,
        configured_campaign_id=trust.policy.campaign_id,
        configured_gate="8h",
    )


@pytest.fixture(scope="session")
def controller_key_material(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, _Key]:
    root = tmp_path_factory.mktemp("controller-trust-keys")
    material: dict[str, _Key] = {}
    for name in (
        "root",
        "manifest",
        "capacity",
        "run",
        "report",
        "conditional",
    ):
        private = root / f"{name}.private.pem"
        public = root / f"{name}.public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(public),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        material[name] = _Key(
            private=private.read_bytes(),
            public=public.read_bytes(),
            spki_sha256=__import__("hashlib").sha256(der).hexdigest(),
        )
    return material


def _start_payload(
    manifest: AcceptanceManifestV2,
    context,
    *,
    collector_id: str = "collector-trusted",
) -> dict[str, object]:
    schedule = context.fault_schedule
    launch = manifest.launch
    return {
        "schema_version": "acceptance-collector-start.v2",
        **_binding(
            collector_id=collector_id,
            manifest_sha256=manifest.manifest_sha256,
            launch=launch,
            schedule=schedule,
        ),
        "trust_binding": context.binding.model_dump(mode="json"),
        "sample_interval_seconds": 60,
        "camera_ids": list(context.camera_ids),
        "workloads": [item.model_dump(mode="json") for item in context.workloads],
        "launch": launch.model_dump(mode="json"),
        "execution": _execution(launch).model_dump(mode="json"),
        "fault_schedule": [item.model_dump(mode="json") for item in schedule],
    }


def test_trust_binding_and_manifest_projection_are_exact_and_immutable(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)

    assert context.binding == AcceptanceTrustBindingV2(
        schema_version="acceptance-trust-binding.v2",
        offline_root_spki_sha256=context.trust.root_spki_sha256,
        policy_id=context.trust.policy.policy_id,
        policy_sha256=context.trust.policy_sha256,
        campaign_id=context.trust.policy.campaign_id,
        manifest_payload_sha256=context.trust.manifest_payload_sha256,
    )
    assert context.camera_ids == tuple(source.camera_id for source in manifest.sources)
    assert context.launch == manifest.launch
    assert tuple(context.workloads) == _workloads(manifest)
    with pytest.raises(TypeError):
        context.workloads[0].analytics_hz["person"] = 29.0


def test_authority_trust_context_requires_verified_builder_and_bound_receipt(
    tmp_path: Path,
    controller_key_material: dict[str, _Key],
) -> None:
    context = _verified_controller_context(tmp_path, controller_key_material)
    public_fields = {
        field.name: getattr(context, field.name)
        for field in fields(AcceptanceAuthorityTrustContextV2)
        if not field.name.startswith("_")
    }
    with pytest.raises(TypeError, match="builder"):
        AcceptanceAuthorityTrustContextV2(**public_fields)

    forged = object.__new__(AcceptanceAuthorityTrustContextV2)
    for field in fields(AcceptanceAuthorityTrustContextV2):
        object.__setattr__(forged, field.name, getattr(context, field.name))
    object.__setattr__(
        forged,
        "_context_receipt",
        context._context_receipt,
    )
    object.__setattr__(forged, "configured_site_id", "attacker-site")
    with pytest.raises(ValueError, match="provenance"):
        AcceptanceAuthority(
            journal=SQLiteAcceptanceAuthorityJournal(tmp_path / "forged-context.sqlite3"),
            trust_context=forged,
            monotonic_clock=lambda: 0.0,
        )


def test_target_collector_rejects_altered_verified_trust_before_journal_io(
    tmp_path: Path,
    controller_key_material: dict[str, _Key],
) -> None:
    context = _verified_controller_context(tmp_path, controller_key_material)
    forged = object.__new__(type(context.trust))
    for field in fields(type(context.trust)):
        object.__setattr__(
            forged,
            field.name,
            getattr(context.trust, field.name),
        )
    object.__setattr__(
        forged,
        "_verification_receipt",
        context.trust._verification_receipt,
    )
    object.__setattr__(forged, "policy_sha256", "0" * 64)
    token = tmp_path / "controller-token"
    token.write_text("controller-token-is-separate", encoding="utf-8")
    journal_path = tmp_path / "must-not-exist.sqlite3"

    with pytest.raises(ValueError, match="provenance"):
        AuthenticatedTargetCollector(
            base_url="http://127.0.0.1:8765",
            acceptance_controller_token_file=token,
            verified_trust=forged,
            configured_site_id=context.configured_site_id,
            configured_campaign_id=context.configured_campaign_id,
            configured_gate=context.configured_gate,
            journal_path=journal_path,
        )
    assert not journal_path.exists()


def test_target_collector_requires_trust_before_token_or_journal_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "must-not-exist.sqlite3"
    token_reads = 0

    def forbidden_token_read(_path: Path) -> str:
        nonlocal token_reads
        token_reads += 1
        raise AssertionError("missing trust must fail before token reads")

    monkeypatch.setattr(
        replay_module,
        "read_machine_token",
        forbidden_token_read,
    )
    with pytest.raises(TypeError, match="verified_trust"):
        AuthenticatedTargetCollector(
            base_url="http://127.0.0.1:8765",
            acceptance_controller_token_file=tmp_path / "missing-token",
            journal_path=journal_path,
        )
    assert token_reads == 0
    assert not journal_path.exists()


def test_target_start_rejects_self_consistent_nonmanifest_payload_before_mutation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "trusted-start.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        trust_context=context,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 10.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    payload = _start_payload(manifest, context)
    changed_sources = (
        manifest.sources[0].model_copy(
            update={"bitrate_kbps": manifest.sources[0].bitrate_kbps + 1}
        ),
        *manifest.sources[1:],
    )
    changed_launch = manifest.launch.model_copy(
        update={"source_profiles_sha256": source_profiles_sha256(changed_sources)}
    )
    changed_manifest = manifest.model_copy(
        update={"sources": changed_sources, "launch": changed_launch}
    )
    changed_context = _context(tmp_path, changed_manifest)
    changed_payload = _start_payload(
        changed_manifest,
        changed_context,
        collector_id=str(payload["collector_id"]),
    )
    changed_payload["trust_binding"] = context.binding.model_dump(mode="json")

    with pytest.raises(RuntimeError, match="signed manifest"):
        authority.start(changed_payload)
    assert journal.total_entry_count() == 0


def test_target_start_samples_wall_once_persists_full_gate_and_retries_after_expiry(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "trusted-retry.sqlite3")
    wall_calls = 0

    def wall() -> datetime:
        nonlocal wall_calls
        wall_calls += 1
        return START if wall_calls == 1 else START + timedelta(days=2)

    authority = AcceptanceAuthority(
        journal=journal,
        trust_context=context,
        wall_clock=wall,
        monotonic_clock=lambda: 10.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    payload = _start_payload(manifest, context)
    response = authority.start(payload)
    entry_count = journal.total_entry_count()
    assert response["trust_binding"] == context.binding.model_dump(mode="json")
    assert wall_calls == 1

    restarted = AcceptanceAuthority(
        journal=journal,
        trust_context=context,
        wall_clock=wall,
        monotonic_clock=lambda: 99.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    assert restarted.start(payload) == response
    assert wall_calls == 1
    assert journal.total_entry_count() == entry_count
    stored = journal.entries(str(payload["collector_id"]), kind="start")[0]
    assert stored["started_at"] == START.isoformat()
    assert stored["execution_ends_at"] == (START + timedelta(hours=8)).isoformat()


def test_target_authority_requires_exact_binding_on_every_request_and_boot_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "trusted-binding.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        trust_context=context,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    start = _start_payload(manifest, context)
    authority.start(start)
    sample = {
        "schema_version": "acceptance-collector-sample.v2",
        **{
            key: value
            for key, value in start.items()
            if key
            in {
                "collector_id",
                "site_id",
                "manifest_sha256",
                "gate",
                "launch_attestation_sha256",
                "execution_binding_sha256",
                "fault_schedule_sha256",
            }
        },
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0,
    }
    with pytest.raises(RuntimeError, match="trust binding"):
        authority.sample(sample)

    changed_context = _context(
        tmp_path,
        manifest,
        policy_id="policy-2026-002",
    )
    restarted = AcceptanceAuthority(
        journal=journal,
        trust_context=changed_context,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    with pytest.raises(RuntimeError, match="trust binding"):
        restarted.start(start)


def test_target_start_enforces_full_gate_boundary_before_journal_mutation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    exact = _context(
        tmp_path,
        manifest,
        valid_until=START + timedelta(hours=8),
    )
    exact_journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "exact-boundary.sqlite3")
    AcceptanceAuthority(
        journal=exact_journal,
        trust_context=exact,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    ).start(_start_payload(manifest, exact))
    assert exact_journal.total_entry_count() == 17

    short = _context(
        tmp_path,
        manifest,
        policy_id="policy-short",
        valid_until=START + timedelta(hours=8) - timedelta(seconds=1),
    )
    short_journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "short-boundary.sqlite3")
    with pytest.raises(ValueError, match="full gate"):
        AcceptanceAuthority(
            journal=short_journal,
            trust_context=short,
            wall_clock=lambda: START,
            monotonic_clock=lambda: 0.0,
            host_boot_id_provider=lambda: "boot-1",
        ).start(_start_payload(manifest, short))
    assert short_journal.total_entry_count() == 0


def test_trusted_authority_rejects_legacy_unbound_session(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "legacy-session.sqlite3")
    portable_start = _start_payload(manifest, context)
    portable_start.pop("trust_binding")
    AcceptanceAuthority(
        journal=journal,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    ).start(portable_start)

    with pytest.raises(RuntimeError, match="trust binding"):
        AcceptanceAuthority(
            journal=journal,
            trust_context=context,
            wall_clock=lambda: START,
            monotonic_clock=lambda: 0.0,
            host_boot_id_provider=lambda: "boot-1",
        ).start(_start_payload(manifest, context))


def test_persisted_execution_end_tamper_fails_even_with_rehashed_chain(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    path = tmp_path / "end-tamper.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(path)
    payload = _start_payload(manifest, context)
    authority = AcceptanceAuthority(
        journal=journal,
        trust_context=context,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    authority.start(payload)

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT entry_id, collector_id, kind, identity, payload_json, "
            "created_at FROM acceptance_entries ORDER BY entry_id"
        ).fetchall()
        previous = ""
        for entry_id, collector_id, kind, identity, encoded, created_at in rows:
            if kind == "start":
                document = json.loads(encoded)
                document["execution_ends_at"] = (START + timedelta(hours=8, seconds=1)).isoformat()
                encoded = json.dumps(
                    document,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            digest = SQLiteAcceptanceAuthorityJournal._entry_sha256(
                collector_id=collector_id,
                kind=kind,
                identity=identity,
                payload_json=encoded,
                created_at=created_at,
                previous_entry_sha256=previous,
            )
            connection.execute(
                "UPDATE acceptance_entries SET payload_json = ?, "
                "previous_entry_sha256 = ?, entry_sha256 = ? "
                "WHERE entry_id = ?",
                (encoded, previous, digest, entry_id),
            )
            previous = digest

    restarted = AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(path),
        trust_context=context,
        wall_clock=lambda: START + timedelta(days=2),
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "boot-1",
    )
    with pytest.raises(RuntimeError, match="interval changed"):
        restarted.start(payload)


def test_target_collector_transmits_verified_binding_on_every_operation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    schedule = context.fault_schedule
    clock = ControlledClock()
    observer = NonDestructiveObservedAdapter(
        _run(manifest, hours=8).model_copy(update={"gate": "8h"}),
        clock,
    )
    token = tmp_path / "controller-token"
    token.write_text("controller-token-is-separate", encoding="utf-8")
    collector = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=context.trust,
        configured_site_id=context.configured_site_id,
        configured_campaign_id=context.configured_campaign_id,
        configured_gate=context.configured_gate,
        fault_executor=AdapterBackedEffectExecutor(observer),
        observer=observer,
        journal_path=tmp_path / "collector.sqlite3",
    )
    captured: list[tuple[str, dict[str, object]]] = []

    def post(
        path: str,
        payload: dict[str, object],
        *,
        limit: int,
    ) -> dict[str, object]:
        del limit
        captured.append((path, payload))
        response = {
            key: payload[key]
            for key in (
                "collector_id",
                "site_id",
                "manifest_sha256",
                "gate",
                "launch_attestation_sha256",
                "execution_binding_sha256",
                "fault_schedule_sha256",
                "trust_binding",
            )
        }
        if path.endswith("/start"):
            return {
                "schema_version": "acceptance-collector-start-response.v2",
                **response,
            }
        if path.endswith("/sample"):
            return {
                "schema_version": "acceptance-collector-sample-response.v2",
                **response,
                "observed_records": 1,
            }
        if path.endswith("/prepare"):
            return {
                "schema_version": "acceptance-fault-prepare-response.v2",
                **response,
                "fault_id": payload["fault"]["fault_id"],
                "phase": payload["phase"],
                "commanded_monotonic_offset_seconds": (
                    payload["commanded_monotonic_offset_seconds"]
                ),
                "command_id": "command-" + "a" * 64,
                "state": "CLAIMED",
            }
        if path.endswith("/ack"):
            observation = payload["observation"]
            return {
                "schema_version": "acceptance-fault-ack-response.v2",
                **response,
                "fault_id": payload["fault_id"],
                "phase": payload["phase"],
                "commanded_monotonic_offset_seconds": (schedule[0].offset_seconds),
                "command_id": payload["command_id"],
                "state": observation["state"],
                "runtime_boot_id": observation["runtime_boot_id"],
                "api_boot_id": observation["api_boot_id"],
                "execution_binding_sha256": payload[
                    "execution_binding_sha256"
                ],
                "observed_at": "2026-07-30T00:00:00Z",
            }
        return {"invalid": "final envelope deliberately omitted"}

    collector._post = post  # type: ignore[method-assign]
    collector.start(
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        gate="8h",
        camera_ids=context.camera_ids,
        workloads=context.workloads,
        sample_interval_seconds=60,
        launch=manifest.launch,
        execution=_execution(manifest.launch),
        schedule=schedule,
    )
    collector.collect(
        process_healthy=True,
        scheduled_monotonic_offset_seconds=0,
    )
    clock.offset = schedule[0].offset_seconds
    collector.command_fault(
        fault_id=schedule[0].fault_id,
        phase="inject",
        at_offset=schedule[0].offset_seconds,
    )
    collector._observations = 1
    collector._fault_acknowledgements = {
        (fault.fault_id, phase): {
            "command_id": f"command-{index:064x}",
            "commanded_monotonic_offset_seconds": (
                fault.offset_seconds
                if phase == "inject"
                else fault.offset_seconds + fault.duration_seconds
            ),
        }
        for index, (fault, phase) in enumerate(
            ((fault, phase) for fault in schedule for phase in ("inject", "recover")),
            start=1,
        )
    }
    with pytest.raises(ValueError):
        collector.finish()

    assert {path.rsplit("/", maxsplit=1)[-1] for path, _payload in captured} == {
        "start",
        "sample",
        "prepare",
        "ack",
        "finalize",
    }
    expected = context.binding.model_dump(mode="json")
    assert all(payload["trust_binding"] == expected for _path, payload in captured)


def test_target_collector_rejects_changed_verified_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    context = _context(tmp_path, manifest)
    token = tmp_path / "controller-token"
    token.write_text("controller-token-is-separate", encoding="utf-8")
    state = tmp_path / "changed.sqlite3"
    original = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=context.trust,
        configured_site_id=context.configured_site_id,
        configured_campaign_id=context.configured_campaign_id,
        configured_gate=context.configured_gate,
        journal_path=state,
    )
    original._post = lambda _path, payload, **_kwargs: {
        "schema_version": "acceptance-collector-start-response.v2",
        **{
            key: payload[key]
            for key in (
                "collector_id",
                "site_id",
                "manifest_sha256",
                "gate",
                "launch_attestation_sha256",
                "execution_binding_sha256",
                "fault_schedule_sha256",
                "trust_binding",
            )
        },
    }
    original.start(
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        gate="8h",
        camera_ids=context.camera_ids,
        workloads=context.workloads,
        sample_interval_seconds=60,
        launch=manifest.launch,
        execution=_execution(manifest.launch),
        schedule=context.fault_schedule,
    )
    changed_context = _context(
        tmp_path,
        manifest,
        policy_id="policy-changed",
    )
    changed = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=changed_context.trust,
        configured_site_id=changed_context.configured_site_id,
        configured_campaign_id=changed_context.configured_campaign_id,
        configured_gate=changed_context.configured_gate,
        journal_path=state,
    )
    with pytest.raises(RuntimeError, match="retry payload changed"):
        changed.start(
            site_id=manifest.site_id,
            manifest_sha256=manifest.manifest_sha256,
            gate="8h",
            camera_ids=context.camera_ids,
            workloads=context.workloads,
            sample_interval_seconds=60,
            launch=manifest.launch,
            execution=_execution(manifest.launch),
            schedule=context.fault_schedule,
        )


def test_controller_ready_is_authenticated_and_nonmutating(tmp_path: Path) -> None:
    class ReadyAuthority:
        def readiness_probe(self) -> None:
            return None

    app = create_acceptance_controller_app(
        authority=ReadyAuthority(),
        controller_token="controller-token-is-separate",
        runtime_lock_path=tmp_path / "ready.lock",
    )
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 401
        response = client.get(
            "/ready",
            headers={"Authorization": "Bearer controller-token-is-separate"},
        )
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def _generate_private_key(
    path: Path,
    *,
    algorithm: str = "ED25519",
) -> Path:
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", algorithm, "-out", str(path)],
        check=True,
        capture_output=True,
    )
    path.chmod(0o600)
    return path


def _public_spki_sha256(private_key: Path) -> str:
    output = subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    return __import__("hashlib").sha256(output).hexdigest()


def test_run_signer_full_consumes_one_canonical_ed25519_pkcs8_key(
    tmp_path: Path,
) -> None:
    private_key = _generate_private_key(tmp_path / "run-private.pem")
    signer = OpenSSLAcceptanceRunSigner(
        private_key,
        expected_public_key_spki_sha256=_public_spki_sha256(private_key),
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
    )
    assert len(signer.sign(b"bounded acceptance payload")) == 64

    private_key.write_bytes(private_key.read_bytes() + private_key.read_bytes())
    with pytest.raises(ValueError, match="PKCS#8"):
        OpenSSLAcceptanceRunSigner(
            private_key,
            expected_public_key_spki_sha256="0" * 64,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "mode",
        "uid",
        "gid",
        "hardlink",
        "symlink",
        "garbage",
        "rsa",
        "ec",
        "public",
        "encrypted",
    ),
)
def test_run_signer_rejects_untrusted_metadata_or_key_shape(
    tmp_path: Path,
    mutation: str,
) -> None:
    private_key = _generate_private_key(tmp_path / "run-private.pem")
    candidate = private_key
    uid = os.geteuid()
    gid = os.getegid()
    if mutation == "mode":
        private_key.chmod(0o640)
    elif mutation == "uid":
        uid += 1
    elif mutation == "gid":
        gid += 1
    elif mutation == "hardlink":
        os.link(private_key, tmp_path / "second-link.pem")
    elif mutation == "symlink":
        candidate = tmp_path / "symlink.pem"
        candidate.symlink_to(private_key)
    elif mutation == "garbage":
        private_key.write_bytes(private_key.read_bytes() + b"garbage")
    elif mutation == "rsa":
        private_key = _generate_private_key(
            tmp_path / "rsa-private.pem",
            algorithm="RSA",
        )
        candidate = private_key
    elif mutation == "ec":
        private_key = tmp_path / "ec-private.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        private_key.chmod(0o600)
        candidate = private_key
    elif mutation == "public":
        public_key = tmp_path / "public.pem"
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
        public_key.chmod(0o600)
        candidate = public_key
    elif mutation == "encrypted":
        encrypted_key = tmp_path / "encrypted.pem"
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-aes-256-cbc",
                "-passout",
                "pass:test-only-password",
                "-out",
                str(encrypted_key),
            ],
            check=True,
            capture_output=True,
        )
        encrypted_key.chmod(0o600)
        candidate = encrypted_key

    with pytest.raises(ValueError):
        OpenSSLAcceptanceRunSigner(
            candidate,
            expected_public_key_spki_sha256="0" * 64,
            expected_uid=uid,
            expected_gid=gid,
        )


def test_production_builder_exposes_no_dependency_or_path_overrides() -> None:
    assert tuple(inspect.signature(build_production_acceptance_authority).parameters) == ()


def test_production_boot_verifies_offline_root_run_key_then_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    controller_key_material: dict[str, _Key],
) -> None:
    key_material = controller_key_material
    trust_root = tmp_path / "trust"
    trust_root.mkdir()
    bundle = _bundle(trust_root, key_material)
    private_key = tmp_path / "run-private.pem"
    private_key.write_bytes(key_material["run"].private)
    private_key.chmod(0o600)
    journal_path = tmp_path / "journal" / "authority.sqlite3"
    proof_root = tmp_path / "proofs"
    proof_root.mkdir(mode=0o700)

    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_RUNTIME_UID",
        os.geteuid(),
    )
    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_RUNTIME_GID",
        os.getegid(),
    )
    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_OWNER_UID",
        os.geteuid(),
    )
    monkeypatch.setattr(
        controller_module,
        "_OFFLINE_ROOT_PUBLIC_KEY_PATH",
        bundle.root_public_key,
    )
    monkeypatch.setattr(
        controller_module,
        "_TRUST_POLICY_PATH",
        bundle.policy,
    )
    monkeypatch.setattr(
        controller_module,
        "_TRUST_POLICY_SIGNATURE_PATH",
        bundle.policy_signature,
    )
    monkeypatch.setattr(
        controller_module,
        "_ROLE_PUBLIC_KEY_PATHS",
        bundle.role_keys,
    )
    monkeypatch.setattr(
        controller_module,
        "_ACCEPTANCE_MANIFEST_PATH",
        bundle.manifest,
    )
    monkeypatch.setattr(
        controller_module,
        "_ACCEPTANCE_MANIFEST_SIGNATURE_PATH",
        bundle.manifest_signature,
    )
    monkeypatch.setattr(
        controller_module,
        "_RUN_SIGNING_KEY_PATH",
        private_key,
    )
    monkeypatch.setenv("PILOT_SITE_ID", "school-01")
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        "campaign-2026-001",
    )
    monkeypatch.setenv("PILOT_ACCEPTANCE_GATE", "8h")
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256",
        bundle.expected_root_spki_sha256,
    )
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_JOURNAL_PATH",
        str(journal_path),
    )
    monkeypatch.setenv("PILOT_ACCEPTANCE_PROOF_DIR", str(proof_root))

    with _protected_journal_namespace(journal_path):
        authority = build_production_acceptance_authority()
        authority.readiness_probe()
        assert authority.trust_context is not None
        assert authority.signer is not None
        assert authority.journal.total_entry_count() == 0


def test_invalid_production_trust_and_legacy_fingerprint_never_open_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_RUNTIME_UID",
        os.geteuid(),
    )
    monkeypatch.setenv("PILOT_SITE_ID", "school-01")
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        "campaign-2026-001",
    )
    monkeypatch.setenv("PILOT_ACCEPTANCE_GATE", "8h")
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256",
        "0" * 64,
    )
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_JOURNAL_PATH",
        str(journal_path),
    )
    with pytest.raises(RuntimeError, match="trust"):
        build_production_acceptance_authority()
    assert not journal_path.exists()

    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_RUN_PUBLIC_KEY_SHA256",
        "1" * 64,
    )
    with pytest.raises(RuntimeError, match="unsupported override"):
        build_production_acceptance_authority()
    assert not journal_path.exists()


def test_compose_mounts_complete_fixed_trust_chain_and_private_key_as_binds() -> None:
    compose = yaml.safe_load(Path("deploy/pilot/docker-compose.yml").read_text(encoding="utf-8"))
    controller = compose["services"]["acceptance-controller"]
    environment = controller["environment"]
    assert set(environment) == {
        "PILOT_SITE_ID",
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        "PILOT_ACCEPTANCE_GATE",
        "PILOT_ACCEPTANCE_JOURNAL_PATH",
        "PILOT_ACCEPTANCE_PROOF_DIR",
        "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256",
    }
    assert "PILOT_ACCEPTANCE_RUN_PUBLIC_KEY_SHA256" not in str(controller)
    assert controller["secrets"] == ["acceptance_controller_token"]
    targets = {volume["target"]: volume for volume in controller["volumes"]}
    readonly_targets = {
        "/run/config/acceptance/offline-root-public.pem",
        "/run/config/acceptance/trust-policy.json",
        "/run/config/acceptance/trust-policy.sig",
        "/run/config/acceptance/acceptance-manifest.json",
        "/run/config/acceptance/acceptance-manifest.sig",
        "/run/config/acceptance/manifest-role-public.pem",
        "/run/config/acceptance/capacity-role-public.pem",
        "/run/config/acceptance/run-role-public.pem",
        "/run/config/acceptance/report-role-public.pem",
        "/run/config/acceptance/conditional-role-public.pem",
        "/run/keys/acceptance/run-private.pem",
    }
    writable_targets = {
        "/var/lib/kuzet/acceptance/authority.sqlite3",
        "/var/lib/kuzet/acceptance/authority.sqlite3-wal",
        "/var/lib/kuzet/acceptance/authority.sqlite3-shm",
        "/var/lib/kuzet/acceptance-proofs",
    }
    assert set(targets) == readonly_targets | writable_targets
    assert all(targets[target]["read_only"] for target in readonly_targets)
    assert all(targets[target]["read_only"] is False for target in writable_targets)
    assert all(
        volume["type"] == "bind" and volume["bind"] == {"create_host_path": False}
        for volume in targets.values()
    )
    healthcheck = controller["healthcheck"]["test"]
    assert healthcheck[:3] == ["CMD", "python", "-c"]
    assert healthcheck.count("python") == 1
    assert "/ready" in " ".join(healthcheck)
    assert controller["networks"] == ["acceptance-loopback"]
    assert compose["networks"]["acceptance-loopback"] == {
        "internal": True,
    }
    assert [
        service_name
        for service_name, service in compose["services"].items()
        if "acceptance-loopback" in service.get("networks", ())
    ] == ["acceptance-controller"]
