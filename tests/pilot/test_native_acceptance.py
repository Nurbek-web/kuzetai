from __future__ import annotations

import copy
import json
import os
import pickle

import pytest

from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
)
from protector.pilot.runtime import native_acceptance
from protector.pilot.runtime.native_acceptance import (
    NativePrewarmProjectorV2,
    load_native_prewarm_projection,
)
from protector.pilot.runtime.source_probe import (
    Exact20NativePrewarmReceiptV1,
    VerifiedExact20NativePrewarmV1,
)
from tests.pilot.test_acceptance_target import _identity, _request


class _FailingFstatOs:
    def __getattr__(self, name: str):
        return getattr(os, name)

    @staticmethod
    def fstat(descriptor: int):
        del descriptor
        raise RuntimeError("parent fstat failure")


def _receipt(
    *,
    site_id: str = "school-01",
    epoch: int = 1,
    epoch_started_generation: int = 1,
    ready_at_monotonic_ns: int = 61_000_000_000,
) -> Exact20NativePrewarmReceiptV1:
    receipt = object.__new__(Exact20NativePrewarmReceiptV1)
    values: dict[str, object] = {
        "_claim_authority": object(),
        "_schema": "kuzet.exact-20-native-prewarm-receipt.v1",
        "_site_id": site_id,
        "_epoch": epoch,
        "_epoch_started_generation": epoch_started_generation,
        "_ready_at_monotonic_ns": ready_at_monotonic_ns,
        "_source_identity_commitments_sha256": "8" * 64,
        "_native_claims_sha256": "9" * 64,
        "_proof_key_id": "source-proof-key",
        "_proof_public_key_sha256": "a" * 64,
        "_proof_milestone_authenticator_key_id": "milestone-key",
        "_proof_milestone_authentication_tag": "b" * 64,
        "_proof_snapshot_sha256": "c" * 64,
        "_proof_final_head": "d" * 64,
        "_proof_signature_sha256": "e" * 64,
        "_proof_sha256": "f" * 64,
    }
    for name, value in values.items():
        object.__setattr__(receipt, name, value)
    return receipt


def _verified_receipt_capability() -> VerifiedExact20NativePrewarmV1:
    return object.__new__(VerifiedExact20NativePrewarmV1)


def test_projector_consumes_native_receipt_once_and_publishes_no_replace(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    receipt = _receipt()
    consumed: set[int] = set()

    def consume_once(candidate, **pins):
        assert type(candidate) is Exact20NativePrewarmReceiptV1
        assert pins["expected_site_id"] == request.launch.site_id
        assert pins["expected_epoch"] == request.runtime_epoch
        assert tuple(pins["expected_source_identity_commitments"]) == tuple(
            binding.source_identity_commitment for binding in request.source_bindings
        )
        if id(candidate) in consumed:
            raise ValueError("receipt capability was already consumed")
        consumed.add(id(candidate))
        return _verified_receipt_capability()

    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        consume_once,
    )
    output = tmp_path / "native-prewarm.json"
    projector = NativePrewarmProjectorV2(output)
    projection = projector.project(
        receipt=receipt,
        launch_request=request,
        runtime_identity=identity,
    )

    assert type(projection) is TargetNativePrewarmProjectionV2
    assert projection.authorizing is False
    assert not hasattr(projection, "accepted")
    assert projection.prewarm_duration_seconds == 60.0
    assert (
        projection.source_identity_commitments_sha256 == receipt.source_identity_commitments_sha256
    )
    assert projection.native_claims_sha256 == receipt.native_claims_sha256
    assert projection.source_profile_proof_sha256 == receipt.proof_sha256
    assert output.read_bytes() == projection.canonical_bytes
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert (
        load_native_prewarm_projection(
            output,
            launch_request=request,
            runtime_identity=identity,
        )
        == projection
    )

    with pytest.raises(RuntimeError, match="already used"):
        projector.project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )
    with pytest.raises(FileExistsError):
        NativePrewarmProjectorV2(output).project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )
    assert output.read_bytes() == projection.canonical_bytes

    second_output = tmp_path / "second.json"
    with pytest.raises(ValueError, match="already consumed"):
        NativePrewarmProjectorV2(second_output).project(
            receipt=receipt,
            launch_request=request,
            runtime_identity=identity,
        )
    assert not second_output.exists()


def test_projector_capability_is_single_use_nonserializable_and_noncopyable(tmp_path) -> None:
    projector = NativePrewarmProjectorV2(tmp_path / "native-prewarm.json")
    with pytest.raises(TypeError, match="copy|capability|serialize"):
        copy.copy(projector)
    with pytest.raises(TypeError, match="copy|capability|serialize"):
        copy.deepcopy(projector)
    with pytest.raises((TypeError, pickle.PickleError), match="pickle|serialize|capability"):
        pickle.dumps(projector)


def test_caller_constructed_canonical_projection_remains_non_authorizing() -> None:
    request = _request()
    identity = _identity(request)
    projection = TargetNativePrewarmProjectionV2(
        schema_version="target-native-prewarm-projection.v2",
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        site_id=request.launch.site_id,
        campaign_id=request.campaign_id,
        launch_nonce=request.launch_nonce,
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=identity.runtime_epoch_started_monotonic_ns,
        ready_at_monotonic_ns=61_000_000_000,
        source_bindings=request.source_bindings,
        source_identity_commitments_sha256="8" * 64,
        native_claims_sha256="9" * 64,
        source_profile_proof_sha256="b" * 64,
    )

    assert projection.authorizing is False
    assert not hasattr(projection, "accepted")
    assert not hasattr(projection, "authorize")


@pytest.mark.parametrize(
    ("site_id", "epoch", "ready_at"),
    (
        ("other-site", 1, 61_000_000_000),
        ("school-01", 2, 61_000_000_000),
        ("school-01", 1, 60_999_999_999),
    ),
)
def test_projection_fails_closed_on_mismatch_or_short_prewarm(
    tmp_path,
    monkeypatch,
    site_id,
    epoch,
    ready_at,
) -> None:
    request = _request()
    identity = _identity(request)
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: _verified_receipt_capability(),
    )

    with pytest.raises((ValueError, RuntimeError), match="site|epoch|60|prewarm|identity"):
        NativePrewarmProjectorV2(tmp_path / f"{site_id}-{epoch}.json").project(
            receipt=_receipt(
                site_id=site_id,
                epoch=epoch,
                ready_at_monotonic_ns=ready_at,
            ),
            launch_request=request,
            runtime_identity=identity,
        )


def test_loader_rejects_replaced_noncanonical_or_oversized_projection(tmp_path) -> None:
    request = _request()
    identity = _identity(request)
    path = tmp_path / "native-prewarm.json"
    path.write_text(json.dumps({"schema_version": "target-native-prewarm-projection.v2"}))

    with pytest.raises(ValueError, match="canonical|projection|invalid"):
        load_native_prewarm_projection(
            path,
            launch_request=request,
            runtime_identity=identity,
        )
    path.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="bounded|large|projection"):
        load_native_prewarm_projection(
            path,
            launch_request=request,
            runtime_identity=identity,
        )


def test_output_and_loader_reject_symlink_and_nonregular_paths(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    receipt = _receipt()
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: _verified_receipt_capability(),
    )
    real = tmp_path / "real.json"
    real.write_bytes(b"do-not-replace")
    link = tmp_path / "projection.json"
    link.symlink_to(real)

    with pytest.raises((FileExistsError, ValueError, OSError)):
        NativePrewarmProjectorV2(link).project(
            receipt=receipt,
            launch_request=request,
            runtime_identity=identity,
        )
    assert real.read_bytes() == b"do-not-replace"

    directory = tmp_path / "directory.json"
    directory.mkdir()
    with pytest.raises((FileExistsError, ValueError, OSError)):
        NativePrewarmProjectorV2(directory).project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )
    with pytest.raises(ValueError, match="regular|projection|bounded"):
        load_native_prewarm_projection(
            directory,
            launch_request=request,
            runtime_identity=identity,
        )

    parent = tmp_path / "real-parent"
    parent.mkdir()
    parent_link = tmp_path / "linked-parent"
    parent_link.symlink_to(parent, target_is_directory=True)
    with pytest.raises(ValueError, match="canonical|path"):
        NativePrewarmProjectorV2(parent_link / "projection.json").project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )


def test_loader_rejects_leaf_replacement_after_single_descriptor_capture(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: _verified_receipt_capability(),
    )
    path = tmp_path / "native-prewarm.json"
    projection = NativePrewarmProjectorV2(path).project(
        receipt=_receipt(),
        launch_request=request,
        runtime_identity=identity,
    )
    forged = projection.model_copy(update={"native_claims_sha256": "0" * 64})
    forged_payload = forged.canonical_bytes
    real_open = native_acceptance.os.open
    replaced = False

    def replace_after_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        descriptor = real_open(file, flags, mode, dir_fd=dir_fd)
        if (
            not replaced
            and file == path.name
            and dir_fd is not None
            and flags & (os.O_WRONLY | os.O_RDWR) == 0
        ):
            replaced = True
            os.rename(
                path.name,
                "captured-original.json",
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            replacement = real_open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                os.write(replacement, forged_payload)
                os.fsync(replacement)
            finally:
                os.close(replacement)
        return descriptor

    monkeypatch.setattr(native_acceptance.os, "open", replace_after_open)
    with pytest.raises(ValueError, match="replaced"):
        load_native_prewarm_projection(
            path,
            launch_request=request,
            runtime_identity=identity,
        )
    assert replaced is True


def test_projector_preserves_primary_and_cleanup_baseexceptions(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("primary receipt failure")),
    )
    monkeypatch.setattr(
        native_acceptance,
        "_cleanup_created_leaf",
        lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt("cleanup abort")),
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        NativePrewarmProjectorV2(tmp_path / "native-prewarm.json").project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )
    assert [type(error) for error in raised.value.exceptions] == [
        RuntimeError,
        KeyboardInterrupt,
    ]


def test_projector_attempts_all_closes_without_masking_primary_failure(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("primary receipt failure")),
    )
    real_close = native_acceptance.os.close
    closed: list[int] = []

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)
        if len(closed) == 1:
            raise KeyboardInterrupt("output close abort")
        raise RuntimeError("parent close failure")

    monkeypatch.setattr(
        native_acceptance,
        "_close_descriptor",
        close_then_fail,
        raising=False,
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        NativePrewarmProjectorV2(tmp_path / "native-prewarm.json").project(
            receipt=_receipt(),
            launch_request=request,
            runtime_identity=identity,
        )

    assert len(closed) == 2
    assert [type(error) for error in raised.value.exceptions] == [
        RuntimeError,
        KeyboardInterrupt,
        RuntimeError,
    ]


def test_loader_attempts_all_closes_when_descriptor_closes_fail(
    tmp_path,
    monkeypatch,
) -> None:
    request = _request()
    identity = _identity(request)
    monkeypatch.setattr(
        native_acceptance,
        "_consume_native_prewarm_receipt",
        lambda *_args, **_kwargs: _verified_receipt_capability(),
    )
    path = tmp_path / "native-prewarm.json"
    NativePrewarmProjectorV2(path).project(
        receipt=_receipt(),
        launch_request=request,
        runtime_identity=identity,
    )
    real_close = native_acceptance.os.close
    closed: list[int] = []

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)
        if len(closed) == 1:
            raise KeyboardInterrupt("input close abort")
        raise RuntimeError("parent close failure")

    monkeypatch.setattr(
        native_acceptance,
        "_close_descriptor",
        close_then_fail,
        raising=False,
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        load_native_prewarm_projection(
            path,
            launch_request=request,
            runtime_identity=identity,
        )

    assert len(closed) == 2
    assert [type(error) for error in raised.value.exceptions] == [
        KeyboardInterrupt,
        RuntimeError,
    ]


def test_open_parent_closes_descriptor_when_fstat_fails(
    tmp_path,
    monkeypatch,
) -> None:
    real_close = os.close
    closed: list[int] = []

    def record_close(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)

    monkeypatch.setattr(native_acceptance, "os", _FailingFstatOs())
    monkeypatch.setattr(native_acceptance, "_close_descriptor", record_close)

    with pytest.raises(RuntimeError, match="parent fstat failure"):
        native_acceptance._open_parent(tmp_path / "native-prewarm.json")

    assert len(closed) == 1


def test_open_parent_preserves_fstat_and_close_failures(
    tmp_path,
    monkeypatch,
) -> None:
    real_close = os.close
    closed: list[int] = []

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)
        raise KeyboardInterrupt("parent close abort")

    monkeypatch.setattr(native_acceptance, "os", _FailingFstatOs())
    monkeypatch.setattr(native_acceptance, "_close_descriptor", close_then_fail)

    with pytest.raises(BaseExceptionGroup) as raised:
        native_acceptance._open_parent(tmp_path / "native-prewarm.json")

    assert len(closed) == 1
    assert [type(error) for error in raised.value.exceptions] == [
        RuntimeError,
        KeyboardInterrupt,
    ]
