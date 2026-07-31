from __future__ import annotations

import copy
import json
import pickle
from pathlib import Path

import pytest

import protector.pilot.acceptance_c2 as acceptance_c2
from protector.pilot.acceptance_c2 import (
    TargetC2AuthorityV3,
    TargetEpochEvidenceV3,
)
from protector.pilot.acceptance_channel import (
    ControllerAcceptanceChannelV3,
    RuntimeAcceptanceChannelV3,
)
from protector.pilot.acceptance_work import _require_verified_target_work
from tests.pilot.test_acceptance_work import _prewarm, _target_inputs
from tests.pilot.test_work_authority import _record_all


def test_protected_channel_is_launch_bound_one_claim_and_one_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path / "inputs")
    plan, _plan_authority = __import__(
        "protector.pilot.acceptance_work",
        fromlist=["derive_target_unique_work_plan"],
    ).derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    root = tmp_path / "channels"
    root.mkdir(mode=0o700)

    controller = ControllerAcceptanceChannelV3.create(
        root=root,
        collector_id="collector-01",
        launch_request=request,
    )
    runtime = RuntimeAcceptanceChannelV3.claim_path(controller.runtime_claim_path)
    with pytest.raises(RuntimeError, match="claim|consum"):
        RuntimeAcceptanceChannelV3.claim(controller.runtime_claim)

    controller.publish_grant(runtime_identity=identity, unique_work_plan=plan)
    grant = runtime.consume_grant()
    assert grant.collector_id == "collector-01"
    assert grant.launch_request_sha256 == request.request_sha256
    assert grant.runtime_identity_sha256 == identity.identity_sha256
    assert grant.unique_work_plan_sha256 == plan.plan_sha256

    prewarm = _prewarm(request, identity)
    runtime_work = __import__(
        "protector.pilot.runtime.work_authority",
        fromlist=["TargetUniqueWorkRuntimeLedger"],
    )
    monkeypatch.setattr(
        runtime_work,
        "_monotonic_ns",
        lambda: prewarm.ready_at_monotonic_ns + 1,
    )
    ledger = runtime_work.TargetUniqueWorkRuntimeLedger(
        plan=plan,
        native_prewarm=prewarm,
    )
    _record_all(ledger, plan, monkeypatch)
    projection = ledger.publish_projection(tmp_path / "channel-work.json")
    runtime.publish_result(native_prewarm=prewarm, unique_work_projection=projection)
    with pytest.raises(RuntimeError, match="result|completion"):
        controller.publish_directive(action="restart")
    result, receipt = controller.consume_result()
    assert result.analytics_publication_enabled is False
    assert result.runtime_epoch == request.runtime_epoch
    directive = controller.publish_directive(action="restart")
    assert directive.result_sha256 == result.result_sha256
    assert runtime.consume_directive() == directive
    ack = runtime.publish_ack()
    assert ack.action == "restart"
    assert controller.consume_ack() == ack
    with pytest.raises(RuntimeError, match="consum|ack"):
        controller.consume_ack()
    with pytest.raises(RuntimeError, match="consum|result"):
        controller.consume_result()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises((TypeError, pickle.PickleError), match="copy|serial|capability"):
            operation(receipt)


def test_verified_work_has_a_private_single_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    work = __import__(
        "protector.pilot.acceptance_work",
        fromlist=[
            "derive_target_unique_work_plan",
            "verify_target_unique_work_projection",
        ],
    )
    plan, authority = work.derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    prewarm = _prewarm(request, identity)
    runtime_work = __import__(
        "protector.pilot.runtime.work_authority",
        fromlist=["TargetUniqueWorkRuntimeLedger"],
    )
    monkeypatch.setattr(
        runtime_work,
        "_monotonic_ns",
        lambda: prewarm.ready_at_monotonic_ns + 1,
    )
    ledger = runtime_work.TargetUniqueWorkRuntimeLedger(
        plan=plan,
        native_prewarm=prewarm,
    )
    _record_all(ledger, plan, monkeypatch)
    projection_path = tmp_path / "work.json"
    projection = ledger.publish_projection(projection_path)
    captured, capability = work.verify_target_unique_work_projection(
        projection_path,
        plan_authority=authority,
        native_prewarm=prewarm,
    )

    assert _require_verified_target_work(capability) == (plan, captured)
    with pytest.raises(RuntimeError, match="consum"):
        _require_verified_target_work(capability)
    with pytest.raises((TypeError, ValueError), match="verified|capability|provenance"):
        _require_verified_target_work(object())
    with pytest.raises((TypeError, ValueError), match="verified|capability|provenance"):
        _require_verified_target_work(projection)


def test_c2_requires_ordered_fresh_restart_epochs_and_private_receipts() -> None:
    assert not hasattr(acceptance_c2, "_issue_target_authority")
    assert not hasattr(acceptance_c2, "_require_verified_target_authority")
    authority = TargetC2AuthorityV3(
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
    )
    with pytest.raises((TypeError, ValueError), match="runtime|channel|work|capability"):
        authority.add_epoch(
            TargetEpochEvidenceV3.model_construct(
                schema_version="target-epoch-evidence.v3",
                collector_id="collector-01",
                runtime_epoch=1,
            ),
            runtime_capability=object(),
            channel_receipt=object(),
            verified_work=object(),
        )
    with pytest.raises(RuntimeError, match="restart|epoch|complete"):
        authority.finalize()


def test_channel_controller_key_is_outside_runtime_mount_and_runtime_secret_is_consumed(
    tmp_path: Path,
) -> None:
    _context, request, _identity, _graph = _target_inputs(tmp_path / "inputs")
    root = tmp_path / "channels"
    root.mkdir(mode=0o700)
    controller = ControllerAcceptanceChannelV3.create(
        root=root,
        collector_id="collector-01",
        launch_request=request,
    )
    channel = controller.runtime_claim_path

    assert not (channel / "controller.key").exists()
    controller_key = next(
        path for path in root.iterdir() if path.name.startswith(".controller-key-")
    )
    runtime_material = json.loads((channel / "runtime.key").read_bytes())
    assert runtime_material["schema_version"] == "acceptance-runtime-key-material.v3"
    assert "private" not in runtime_material
    assert controller_key.read_bytes()[:32].hex() not in json.dumps(runtime_material)
    RuntimeAcceptanceChannelV3.claim_path(channel)
    assert not (channel / "runtime.key").exists()
