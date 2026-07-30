from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import protector.pilot.acceptance_proof as acceptance_proof_module
from protector.pilot.acceptance import (
    ExecutionBindingV2,
    LaunchAttestationV2,
    build_canonical_fault_schedule,
    canonical_fault_schedule_sha256,
)
from protector.pilot.acceptance_proof import (
    MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
    AcceptanceJournalProofEntryV2,
    AcceptanceJournalProofHeaderV2,
    AcceptanceJournalProofTrailerV2,
    AcceptanceProofStore,
    JournalKindCountsV2,
    TargetRunAttestationV2,
    canonical_proof_line,
    journal_entry_sha256,
    verify_acceptance_journal_proof,
)
from tests.pilot.test_acceptance_authority import _execution
from tests.pilot.test_acceptance_report import _manifest

_DIGESTS = tuple(hashlib.sha256(f"digest-{index}".encode()).hexdigest() for index in range(20))


def _kind_counts(*, gate: str = "8h") -> JournalKindCountsV2:
    return JournalKindCountsV2(
        start=1,
        sample=481 if gate == "8h" else 4_321,
        fault_intent=16,
        fault_claim=16,
        fault_ack=16,
        finalize=1,
    )


@pytest.fixture(scope="module")
def proof_contract(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[LaunchAttestationV2, ExecutionBindingV2, tuple[str, ...]]:
    root = tmp_path_factory.mktemp("proof-contract")
    manifest = _manifest(root)
    return (
        manifest.launch,
        _execution(manifest.launch),
        tuple(source.camera_id for source in manifest.sources),
    )


def _write_valid_proof(
    path: Path,
    *,
    proof_contract: tuple[
        LaunchAttestationV2,
        ExecutionBindingV2,
        tuple[str, ...],
    ],
    gate: str = "8h",
) -> TargetRunAttestationV2:
    payload_schemas = {
        "start": "acceptance-collector-start.v2",
        "sample": "acceptance-sample-observation.v2",
        "fault_intent": "acceptance-fault-intent.v2",
        "fault_claim": "acceptance-fault-claim.v2",
        "fault_ack": "acceptance-fault-acknowledgement.v2",
        "finalize": "acceptance-run-record.v2",
    }
    counts = _kind_counts(gate=gate)
    launch, execution, camera_ids = proof_contract
    fault_schedule = build_canonical_fault_schedule(camera_ids)
    header = AcceptanceJournalProofHeaderV2(
        schema_version="acceptance-journal-proof-header.v2",
        collector_id="collector-01",
        site_id="school-01",
        manifest_sha256=_DIGESTS[0],
        gate=gate,
        journal_namespace_mode="protected",
        offline_root_spki_sha256=_DIGESTS[1],
        policy_id="policy-01",
        policy_sha256=_DIGESTS[2],
        campaign_id="campaign-01",
        manifest_payload_sha256=_DIGESTS[3],
        launch_attestation_sha256=launch.attestation_sha256,
        execution_binding_sha256=execution.binding_sha256,
        fault_schedule_sha256=canonical_fault_schedule_sha256(fault_schedule),
        public_run_authority_spki_sha256=launch.run_authority_public_key_spki_sha256,
        sample_interval_seconds=60,
        camera_ids=camera_ids,
        launch=launch,
        execution=execution,
        fault_schedule=fault_schedule,
    )
    kind_sequence = (
        ("start",)
        + ("fault_intent",) * 16
        + ("sample",) * counts.sample
        + ("fault_claim",) * 16
        + ("fault_ack",) * 16
        + ("finalize",)
    )
    previous = ""
    lines = [canonical_proof_line(header)]
    for ordinal, kind in enumerate(kind_sequence, start=1):
        identity = f"{kind}-{ordinal:05}"
        payload = (
            {"schema_version": "acceptance-run-record.v2", "record": "final"}
            if kind == "finalize"
            else {
                "schema_version": payload_schemas[kind],
                "ordinal": ordinal,
                "kind": kind,
            }
        )
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        created_at = f"2026-07-22T00:{ordinal % 60:02}:00+00:00"
        entry_sha256 = journal_entry_sha256(
            collector_id=header.collector_id,
            kind=kind,
            identity=identity,
            payload_json=payload_json,
            created_at=created_at,
            previous_entry_sha256=previous,
        )
        lines.append(
            canonical_proof_line(
                AcceptanceJournalProofEntryV2(
                    schema_version="acceptance-journal-proof-entry.v2",
                    ordinal=ordinal,
                    collector_id=header.collector_id,
                    kind=kind,
                    identity=identity,
                    payload=payload,
                    created_at=created_at,
                    previous_entry_sha256=previous,
                    entry_sha256=entry_sha256,
                )
            )
        )
        previous = entry_sha256
    run_payload = json.dumps(
        {"schema_version": "acceptance-run-record.v2", "record": "final"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    trailer = AcceptanceJournalProofTrailerV2(
        schema_version="acceptance-journal-proof-trailer.v2",
        collector_id=header.collector_id,
        entry_count=counts.total,
        kind_counts=counts,
        journal_final_root_sha256=previous,
        run_record_sha256=hashlib.sha256(run_payload).hexdigest(),
    )
    lines.append(canonical_proof_line(trailer))
    payload = b"".join(lines)
    path.write_bytes(payload)
    return TargetRunAttestationV2(
        schema_version="target-run-attestation.v2",
        journal_namespace_mode="protected",
        collector_id=header.collector_id,
        site_id=header.site_id,
        manifest_sha256=header.manifest_sha256,
        gate=gate,
        offline_root_spki_sha256=header.offline_root_spki_sha256,
        policy_id=header.policy_id,
        policy_sha256=header.policy_sha256,
        campaign_id=header.campaign_id,
        manifest_payload_sha256=header.manifest_payload_sha256,
        launch_attestation_sha256=header.launch_attestation_sha256,
        execution_binding_sha256=header.execution_binding_sha256,
        fault_schedule_sha256=header.fault_schedule_sha256,
        run_record_sha256=trailer.run_record_sha256,
        journal_root_sha256=trailer.journal_final_root_sha256,
        journal_entry_count=trailer.entry_count,
        public_key_spki_sha256=header.public_run_authority_spki_sha256,
        journal_proof_sha256=hashlib.sha256(payload).hexdigest(),
        journal_proof_bytes=len(payload),
        journal_proof_lines=len(lines),
        journal_kind_counts=counts,
    )


def test_streaming_proof_verifier_accepts_exact_8h_inventory(
    tmp_path: Path,
    proof_contract: tuple[LaunchAttestationV2, ExecutionBindingV2, tuple[str, ...]],
) -> None:
    proof = tmp_path / "proof.jsonl"
    attestation = _write_valid_proof(proof, proof_contract=proof_contract)
    result = verify_acceptance_journal_proof(
        proof,
        expected_attestation=attestation,
    )
    assert result.entry_count == 531
    assert result.line_count == 533
    assert result.kind_counts == _kind_counts()
    assert result.proof_bytes == proof.stat().st_size


def test_proof_header_rejects_hash_consistent_malformed_embedded_contracts(
    tmp_path: Path,
    proof_contract: tuple[LaunchAttestationV2, ExecutionBindingV2, tuple[str, ...]],
) -> None:
    proof = tmp_path / "malformed-proof.jsonl"
    _write_valid_proof(proof, proof_contract=proof_contract)
    lines = proof.read_bytes().splitlines(keepends=True)
    header = json.loads(lines[0])
    header["launch"] = {
        "schema_version": "acceptance-launch-attestation.v2",
        "binding": _DIGESTS[4],
    }
    header["launch_attestation_sha256"] = hashlib.sha256(
        json.dumps(
            header["launch"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    proof.write_bytes(b"".join(lines))
    with pytest.raises(ValueError, match="schema|contract|launch|execution"):
        verify_acceptance_journal_proof(
            proof,
            expected_attestation=_write_valid_proof(
                tmp_path / "expected-proof.jsonl",
                proof_contract=proof_contract,
            ),
        )


def test_proof_contract_rejects_wrong_exact_gate_inventory() -> None:
    with pytest.raises(ValueError, match="exact gate inventory"):
        TargetRunAttestationV2(
            schema_version="target-run-attestation.v2",
            journal_namespace_mode="protected",
            collector_id="collector-01",
            site_id="school-01",
            manifest_sha256=_DIGESTS[0],
            gate="8h",
            offline_root_spki_sha256=_DIGESTS[1],
            policy_id="policy-01",
            policy_sha256=_DIGESTS[2],
            campaign_id="campaign-01",
            manifest_payload_sha256=_DIGESTS[3],
            launch_attestation_sha256=_DIGESTS[4],
            execution_binding_sha256=_DIGESTS[5],
            fault_schedule_sha256=_DIGESTS[6],
            run_record_sha256=_DIGESTS[8],
            journal_root_sha256=_DIGESTS[9],
            journal_entry_count=530,
            public_key_spki_sha256=_DIGESTS[7],
            journal_proof_sha256=_DIGESTS[10],
            journal_proof_bytes=1,
            journal_proof_lines=532,
            journal_kind_counts=_kind_counts().model_copy(update={"sample": 480}),
        )


@pytest.mark.parametrize("mutation", ["reorder", "delete", "append", "truncate", "invalid_utf8"])
def test_streaming_proof_verifier_rejects_chain_and_framing_mutations(
    tmp_path: Path,
    mutation: str,
    proof_contract: tuple[LaunchAttestationV2, ExecutionBindingV2, tuple[str, ...]],
) -> None:
    proof = tmp_path / "proof.jsonl"
    attestation = _write_valid_proof(proof, proof_contract=proof_contract)
    lines = proof.read_bytes().splitlines(keepends=True)
    if mutation == "reorder":
        lines[20], lines[21] = lines[21], lines[20]
        payload = b"".join(lines)
    elif mutation == "delete":
        payload = b"".join(lines[:20] + lines[21:])
    elif mutation == "append":
        payload = b"".join(lines) + b"{}\n"
    elif mutation == "truncate":
        payload = b"".join(lines)[:-1]
    else:
        payload = b"".join(lines[:20]) + b"\xff\n" + b"".join(lines[21:])
    proof.write_bytes(payload)
    with pytest.raises(ValueError):
        verify_acceptance_journal_proof(proof, expected_attestation=attestation)


def test_proof_verifier_never_uses_whole_file_path_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof_contract: tuple[LaunchAttestationV2, ExecutionBindingV2, tuple[str, ...]],
) -> None:
    proof = tmp_path / "proof.jsonl"
    attestation = _write_valid_proof(proof, proof_contract=proof_contract)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _self: pytest.fail("proof verifier used a whole-file read"),
    )
    result = verify_acceptance_journal_proof(proof, expected_attestation=attestation)
    assert result.proof_bytes < MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES


def test_private_proof_store_publishes_no_replace_and_replays_exact_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "proof-store"
    root.mkdir(mode=0o700)
    store = AcceptanceProofStore(root)
    payload = b'{"schema_version":"proof-test"}\n'

    first = store.publish_bytes("collector-01", payload)
    second = store.publish_bytes("collector-01", payload)

    assert first == second
    assert first.path.read_bytes() == payload
    assert first.path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(RuntimeError, match="differs"):
        store.publish_bytes("collector-01", payload + b"{}\n")


def test_private_proof_store_rejects_redirected_or_multilink_artifacts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "proof-store"
    root.mkdir(mode=0o700)
    store = AcceptanceProofStore(root)
    published = store.publish_bytes("collector-01", b"proof\n")
    alias = tmp_path / "alias"
    alias.hardlink_to(published.path)
    with pytest.raises(RuntimeError, match="unsafe"):
        store.open_verified("collector-01")

    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    moved = tmp_path / "moved"
    root.rename(moved)
    replacement.rename(root)
    with pytest.raises(RuntimeError, match="identity changed"):
        store.publish_bytes("collector-02", b"proof\n")


def test_private_proof_store_rejects_mutation_while_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "proof-store"
    root.mkdir(mode=0o700)
    store = AcceptanceProofStore(root)
    payload = b"A" * (2 * 1024 * 1024 + 17)
    published = store.publish_bytes("collector-01", payload)
    original_read = acceptance_proof_module.os.read
    read_count = 0

    def mutate_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal read_count
        chunk = original_read(descriptor, size)
        if chunk:
            read_count += 1
            if read_count == 1:
                published.path.write_bytes(b"B" * len(payload))
        return chunk

    monkeypatch.setattr(
        acceptance_proof_module.os,
        "read",
        mutate_after_first_chunk,
    )
    with pytest.raises(RuntimeError, match="changed while hashing"):
        store.open_verified("collector-01")
