from __future__ import annotations

import copy
import json
import os
import pickle
from pathlib import Path

import pytest

from protector.pilot.acceptance_work import (
    TargetUniqueWorkProjectionV2,
    derive_target_unique_work_plan,
    verify_target_unique_work_projection,
)
from protector.pilot.runtime import work_authority
from protector.pilot.runtime.work_authority import TargetUniqueWorkRuntimeLedger
from tests.pilot.test_acceptance_work import _prewarm, _target_inputs


def _record_all(
    ledger: TargetUniqueWorkRuntimeLedger,
    plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [ledger.measurement_started_monotonic_ns]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    for slot in plan.slots:
        clock[0] = ledger.measurement_started_monotonic_ns + slot.scheduled_offset_ns
        ledger.record_post_shared_analytics_completion(
            work_id=slot.work_id,
            runtime_epoch=plan.runtime_epoch,
            runtime_epoch_started_generation=plan.runtime_epoch_started_generation,
            camera_id=slot.camera_id,
            source_index=slot.source_index,
            module=slot.module,
            slot_index=slot.slot_index,
            detection_count=0,
        )
    clock[0] = ledger.measurement_started_monotonic_ns + plan.measurement_duration_ns


def test_runtime_ledger_records_each_planned_post_analytics_completion_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    monkeypatch.setattr(
        work_authority,
        "_monotonic_ns",
        lambda: prewarm.ready_at_monotonic_ns + 1_000_000_000,
    )
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    _record_all(ledger, plan, monkeypatch)
    output = tmp_path / "unique-work.json"

    projection = ledger.publish_projection(output)
    captured, capability = verify_target_unique_work_projection(
        output,
        plan_authority=authority,
        native_prewarm=prewarm,
    )

    assert projection == captured
    assert type(captured) is TargetUniqueWorkProjectionV2
    assert captured.authorizing is False
    assert captured.offered_work_units == len(plan.slots)
    assert captured.completed_unique_work_units == len(plan.slots)
    assert captured.effective_rate_numerator == 8
    assert captured.effective_rate_denominator == 3
    assert captured.headroom_numerator == 1
    assert captured.headroom_denominator == 3
    assert all(item.detection_count == 0 for item in captured.completions)
    assert not hasattr(captured, "accepted")
    assert not hasattr(capability, "accepted")
    assert output.read_bytes() == captured.canonical_bytes
    assert os.stat(output).st_mode & 0o777 == 0o600
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises((TypeError, pickle.PickleError), match="copy|serial|capability"):
            operation(capability)

    last = plan.slots[-1]
    with pytest.raises(ValueError, match="bounded|capacity|exhausted"):
        ledger.record_post_shared_analytics_completion(
            work_id=last.work_id,
            runtime_epoch=plan.runtime_epoch,
            runtime_epoch_started_generation=plan.runtime_epoch_started_generation,
            camera_id=last.camera_id,
            source_index=last.source_index,
            module=last.module,
            slot_index=last.slot_index,
            detection_count=0,
        )


@pytest.mark.parametrize(
    ("change", "match"),
    (
        ({"runtime_epoch": 8}, "epoch"),
        ({"runtime_epoch_started_generation": 12}, "generation|epoch"),
        ({"camera_id": "camera-19"}, "camera|work"),
        ({"source_index": 19}, "source|work"),
        ({"module": "weapon"}, "module|work"),
        ({"slot_index": 1}, "slot|order|work"),
    ),
)
def test_runtime_ledger_rejects_wrong_replayed_or_unknown_work(
    tmp_path: Path,
    change: dict[str, object],
    match: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    clock = [prewarm.ready_at_monotonic_ns + 1_000_000_000]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    slot = plan.slots[0]
    arguments: dict[str, object] = {
        "work_id": slot.work_id,
        "runtime_epoch": plan.runtime_epoch,
        "runtime_epoch_started_generation": plan.runtime_epoch_started_generation,
        "camera_id": slot.camera_id,
        "source_index": slot.source_index,
        "module": slot.module,
        "slot_index": slot.slot_index,
        "detection_count": 0,
    }
    arguments.update(change)

    with pytest.raises(ValueError, match=match):
        ledger.record_post_shared_analytics_completion(**arguments)

    ledger.record_post_shared_analytics_completion(
        **{
            **arguments,
            **{
                "work_id": slot.work_id,
                "runtime_epoch": plan.runtime_epoch,
                "runtime_epoch_started_generation": plan.runtime_epoch_started_generation,
                "camera_id": slot.camera_id,
                "source_index": slot.source_index,
                "module": slot.module,
                "slot_index": slot.slot_index,
            },
        }
    )
    with pytest.raises(ValueError, match="duplicate|order|already"):
        ledger.record_post_shared_analytics_completion(
            **{
                **arguments,
                **{
                    "work_id": slot.work_id,
                    "runtime_epoch": plan.runtime_epoch,
                    "runtime_epoch_started_generation": plan.runtime_epoch_started_generation,
                    "camera_id": slot.camera_id,
                    "source_index": slot.source_index,
                    "module": slot.module,
                    "slot_index": slot.slot_index,
                },
            }
        )


def test_runtime_ledger_rejects_before_prewarm_nonmonotonic_and_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    clock = [prewarm.ready_at_monotonic_ns - 1]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    with pytest.raises(ValueError, match="prewarm|measurement"):
        TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    clock[0] = prewarm.ready_at_monotonic_ns + 1_000_000_000
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    first = plan.slots[0]
    clock[0] = ledger.measurement_started_monotonic_ns - 1
    with pytest.raises(ValueError, match="scheduled|monotonic|slot"):
        ledger.record_post_shared_analytics_completion(
            work_id=first.work_id,
            runtime_epoch=plan.runtime_epoch,
            runtime_epoch_started_generation=plan.runtime_epoch_started_generation,
            camera_id=first.camera_id,
            source_index=first.source_index,
            module=first.module,
            slot_index=first.slot_index,
            detection_count=0,
        )
    clock[0] = ledger.measurement_started_monotonic_ns
    with pytest.raises(ValueError, match="unknown|work|slot"):
        ledger.record_post_shared_analytics_completion(
            work_id="f" * 64,
            runtime_epoch=plan.runtime_epoch,
            runtime_epoch_started_generation=plan.runtime_epoch_started_generation,
            camera_id=first.camera_id,
            source_index=first.source_index,
            module=first.module,
            slot_index=first.slot_index,
            detection_count=0,
        )


def test_partial_or_changed_ledger_cannot_mint_verified_work_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    clock = [prewarm.ready_at_monotonic_ns + 1_000_000_000]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    first = plan.slots[0]
    ledger.record_post_shared_analytics_completion(
        work_id=first.work_id,
        runtime_epoch=plan.runtime_epoch,
        runtime_epoch_started_generation=plan.runtime_epoch_started_generation,
        camera_id=first.camera_id,
        source_index=first.source_index,
        module=first.module,
        slot_index=first.slot_index,
        detection_count=0,
    )
    clock[0] = ledger.measurement_started_monotonic_ns + plan.measurement_duration_ns
    partial = tmp_path / "partial.json"
    ledger.publish_projection(partial)
    with pytest.raises(ValueError, match="complete|planned|headroom|work"):
        verify_target_unique_work_projection(
            partial,
            plan_authority=authority,
            native_prewarm=prewarm,
        )

    payload = json.loads(partial.read_bytes())
    payload["completed_unique_work_units"] = len(plan.slots)
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    changed.chmod(0o600)
    with pytest.raises(ValueError, match="canonical|ledger|completion|work"):
        verify_target_unique_work_projection(
            changed,
            plan_authority=authority,
            native_prewarm=prewarm,
        )


def test_projection_publication_is_no_replace_symlink_safe_and_handles_short_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    clock = [prewarm.ready_at_monotonic_ns + 1_000_000_000]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    clock[0] = ledger.measurement_started_monotonic_ns + plan.measurement_duration_ns
    output = tmp_path / "work.json"
    output.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        ledger.publish_projection(output)
    assert output.read_bytes() == b"keep"

    target = tmp_path / "target.json"
    target.write_bytes(b"keep-target")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises((FileExistsError, ValueError, OSError)):
        ledger.publish_projection(link)
    assert target.read_bytes() == b"keep-target"

    original_write = work_authority.os.write

    def short_write(descriptor: int, payload: bytes) -> int:
        return original_write(descriptor, payload[: max(1, len(payload) // 3)])

    monkeypatch.setattr(work_authority.os, "write", short_write)
    short = tmp_path / "short.json"
    projection = ledger.publish_projection(short)
    assert short.read_bytes() == projection.canonical_bytes


def test_publication_baseexception_removes_only_its_partial_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    clock = [prewarm.ready_at_monotonic_ns + 1_000_000_000]
    monkeypatch.setattr(work_authority, "_monotonic_ns", lambda: clock[0])
    ledger = TargetUniqueWorkRuntimeLedger(plan=plan, native_prewarm=prewarm)
    clock[0] = ledger.measurement_started_monotonic_ns + plan.measurement_duration_ns
    output = tmp_path / "interrupt.json"

    def interrupted_write(_descriptor: int, _payload: bytes) -> int:
        raise KeyboardInterrupt("stop")

    monkeypatch.setattr(work_authority.os, "write", interrupted_write)
    with pytest.raises(KeyboardInterrupt, match="stop"):
        ledger.publish_projection(output)
    assert not output.exists()
