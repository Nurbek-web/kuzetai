from __future__ import annotations

import hashlib
import json
import os
import subprocess
import traceback
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from protector.pilot.acceptance_trust import (
    MAX_ACCEPTANCE_MANIFEST_BYTES,
    MAX_STRUCTURED_NODES,
    MAX_STRUCTURED_SCALAR_BYTES,
    MAX_TRUST_POLICY_BYTES,
    AcceptanceRolePinsV2,
    AcceptanceRolePublicKeyPathsV2,
    AcceptanceTrustPolicyV2,
    ExecutionTrustGrantV2,
    HistoricalTrustVerificationV2,
    VerifiedAcceptanceTrustV2,
    authorize_acceptance_execution,
    canonical_json_bytes,
    load_canonical_json_bytes,
    load_canonical_json_path,
    load_restricted_yaml_bytes,
    verify_acceptance_trust_chain,
    verify_historical_acceptance_trust,
)
from protector.pilot.config import FrozenModel
from protector.pilot.trusted_artifacts import (
    ed25519_public_key_spki_sha256,
    read_regular_bounded,
    verify_detached_artifact,
)
from tests.pilot.test_acceptance_report import (
    _manifest as _acceptance_manifest_fixture,
)

UTC = timezone.utc
NOW = datetime(2026, 7, 30, 12, tzinfo=UTC)
ROLE_NAMES = ("manifest", "capacity", "run", "report", "conditional")
FINGERPRINTS = tuple(f"{index:x}" * 64 for index in range(1, 7))


class _TinyDocument(FrozenModel):
    schema_version: str
    nested: dict[str, int]


class _ArbitraryDocument(FrozenModel):
    payload: Any


class _NonStringMappingDocument(FrozenModel):
    payload: dict[Any, Any]


def _role_pins(**updates: str) -> dict[str, str]:
    values = {
        "schema_version": "acceptance-role-pins.v2",
        **{f"{role}_spki_sha256": FINGERPRINTS[index + 1] for index, role in enumerate(ROLE_NAMES)},
    }
    values.update(updates)
    return values


def _policy(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": "acceptance-trust-policy.v2",
        "policy_id": "policy-2026-001",
        "campaign_id": "campaign-2026-001",
        "site_id": "school-01",
        "signature_algorithm": "Ed25519",
        "root_spki_sha256": FINGERPRINTS[0],
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=30),
        "allowed_gates": ("8h", "72h"),
        "manifest_payload_sha256": "a" * 64,
        "roles": _role_pins(),
    }
    values.update(updates)
    return values


def _chain_policy_bytes_for_canonical_test() -> bytes:
    return _fixture_canonical_json(
        _policy(
            valid_from="2026-07-29T12:00:00Z",
            valid_until="2026-08-29T12:00:00Z",
            allowed_gates=["8h", "72h"],
        )
    )


def test_canonical_json_encoding_is_utf8_sorted_compact_and_has_no_newline() -> None:
    assert canonical_json_bytes({"z": "Күзет", "a": 1}) == (
        b'{"a":1,"z":"\xd0\x9a\xd2\xaf\xd0\xb7\xd0\xb5\xd1\x82"}'
    )


@pytest.mark.parametrize(
    "value",
    [
        {"\ud800DO_NOT_DISCLOSE_ATTACKER_SECRET": 1},
        {"value": "\ud800DO_NOT_DISCLOSE_ATTACKER_SECRET"},
    ],
)
def test_canonical_json_encoder_suppresses_attacker_value_context(
    value: object,
) -> None:
    try:
        canonical_json_bytes(value)
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert "DO_NOT_DISCLOSE_ATTACKER_SECRET" not in rendered
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
    else:
        raise AssertionError("invalid canonical JSON value unexpectedly encoded")


@pytest.mark.parametrize(
    "value",
    [
        {1: "integer"},
        {None: "null"},
        {True: "boolean"},
        {"nested": [{1: "integer"}]},
        [{"nested": {None: "null"}}],
    ],
)
def test_canonical_json_encoder_rejects_non_string_keys_recursively(
    value: object,
) -> None:
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_json_bytes(value)


def test_canonical_json_encoder_rejects_non_string_keys_inside_models() -> None:
    document = _NonStringMappingDocument(payload={"nested": [{1: "integer"}]})
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_json_bytes(document)


def test_canonical_json_key_encoding_is_injective_and_errors_are_redacted() -> None:
    assert canonical_json_bytes({"1": "string", "null": "null", "true": "boolean"}) == (
        b'{"1":"string","null":"null","true":"boolean"}'
    )
    attacker = {1: {"value": "DO_NOT_DISCLOSE_ATTACKER_SECRET"}}
    try:
        canonical_json_bytes(attacker)
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert str(exc) == "value cannot be represented as canonical JSON"
        assert "DO_NOT_DISCLOSE_ATTACKER_SECRET" not in rendered
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
    else:
        raise AssertionError("non-string canonical JSON key unexpectedly encoded")


def test_canonical_json_loader_validates_a_frozen_model_and_forbids_extra_fields() -> None:
    document = load_canonical_json_bytes(
        b'{"nested":{"count":2},"schema_version":"tiny.v1"}',
        _TinyDocument,
    )
    assert document == _TinyDocument(schema_version="tiny.v1", nested={"count": 2})

    with pytest.raises(ValueError):
        load_canonical_json_bytes(
            b'{"extra":true,"nested":{"count":2},"schema_version":"tiny.v1"}',
            _TinyDocument,
        )


@pytest.mark.parametrize("value", ['"2"', "2.0", "true"])
def test_canonical_json_loader_rejects_pydantic_scalar_coercion(value: str) -> None:
    payload = (f'{{"nested":{{"count":{value}}},"schema_version":"tiny.v1"}}').encode()
    with pytest.raises(ValueError):
        load_canonical_json_bytes(payload, _TinyDocument)


def test_canonical_json_loader_requires_validated_datetime_spelling() -> None:
    policy = _chain_policy_bytes_for_canonical_test()
    alternate_utc = policy.replace(b"2026-07-29T12:00:00Z", b"2026-07-29T12:00:00+00:00")
    with pytest.raises(ValueError, match="canonical"):
        load_canonical_json_bytes(
            alternate_utc,
            AcceptanceTrustPolicyV2,
            max_bytes=64 * 1024,
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"nested":{"count":1,"count":2},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":1},"schema_version":"tiny.v1","schema_version":"other"}',
    ],
)
def test_canonical_json_rejects_duplicate_keys_at_every_depth(payload: bytes) -> None:
    with pytest.raises(ValueError, match="duplicate"):
        load_canonical_json_bytes(payload, _TinyDocument)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":"tiny.v1","nested":{"count":2}}',
        b'{ "nested":{"count":2},"schema_version":"tiny.v1"}',
        b'{"nested": {"count":2},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":2},"schema_version":"tiny.v1"}\n',
        b'{"nested":{"count":2},"schema_version":"tiny.v1"} ',
    ],
)
def test_canonical_json_rejects_order_whitespace_and_newline_variants(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError, match="canonical"):
        load_canonical_json_bytes(payload, _TinyDocument)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xef\xbb\xbf{}",
        b'{"nested":{"count":\xff},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":NaN},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":Infinity},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":-Infinity},"schema_version":"tiny.v1"}',
        b'{"nested":{"count":2},"schema_version":"tiny.v1"}{}',
        b"[]",
    ],
)
def test_canonical_json_rejects_bom_invalid_utf8_nonfinite_trailing_and_nonobject(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError):
        load_canonical_json_bytes(payload, _TinyDocument)


def test_canonical_json_enforces_byte_bound_and_descriptor_safe_paths(
    tmp_path: Path,
) -> None:
    payload = b'{"nested":{"count":2},"schema_version":"tiny.v1"}'
    regular = tmp_path / "document.json"
    regular.write_bytes(payload)
    regular.chmod(0o600)
    assert load_canonical_json_path(regular, _TinyDocument) == _TinyDocument(
        schema_version="tiny.v1",
        nested={"count": 2},
    )
    with pytest.raises(ValueError):
        load_canonical_json_path(regular, _TinyDocument, max_bytes=len(payload) - 1)

    symlink = tmp_path / "document-link.json"
    symlink.symlink_to(regular)
    with pytest.raises(ValueError):
        load_canonical_json_path(symlink, _TinyDocument)

    fifo = tmp_path / "document.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        load_canonical_json_path(fifo, _TinyDocument)


def test_bounded_capture_rejects_hardlinks_and_symlinked_components(
    tmp_path: Path,
) -> None:
    payload = _write_secure(tmp_path / "artifact", b"captured")
    hardlink = tmp_path / "artifact-hardlink"
    os.link(payload, hardlink)
    with pytest.raises(ValueError):
        read_regular_bounded(hardlink, max_bytes=64, label="artifact")

    real_directory = tmp_path / "real"
    real_directory.mkdir()
    nested = _write_secure(real_directory / "artifact", b"captured")
    link_directory = tmp_path / "linked"
    link_directory.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError):
        read_regular_bounded(
            link_directory / nested.name,
            max_bytes=64,
            label="artifact",
        )


def test_bounded_capture_rejects_symlink_leaf_and_each_component_depth(
    tmp_path: Path,
) -> None:
    real_outer = tmp_path / "real-outer"
    real_inner = real_outer / "real-inner"
    real_inner.mkdir(parents=True)
    artifact = _write_secure(real_inner / "artifact", b"captured")

    leaf_link = real_inner / "leaf-link"
    leaf_link.symlink_to(artifact)
    outer_link = tmp_path / "outer-link"
    outer_link.symlink_to(real_outer, target_is_directory=True)
    inner_link = real_outer / "inner-link"
    inner_link.symlink_to(real_inner, target_is_directory=True)

    for linked_path in (
        leaf_link,
        outer_link / real_inner.name / artifact.name,
        real_outer / inner_link.name / artifact.name,
    ):
        with pytest.raises(ValueError):
            read_regular_bounded(
                linked_path,
                max_bytes=64,
                label="artifact",
            )


def test_bounded_capture_requires_one_absolute_canonical_path(
    tmp_path: Path,
) -> None:
    canonical = _write_secure(tmp_path / "artifact", b"captured")
    assert read_regular_bounded(canonical, max_bytes=64, label="artifact") == b"captured"
    for unsafe in (
        Path("relative/artifact"),
        Path("/private/sub/../artifact"),
        Path(f"//{str(canonical).lstrip('/')}"),
    ):
        with pytest.raises(ValueError):
            read_regular_bounded(unsafe, max_bytes=64, label="artifact")
    if Path("/tmp").is_symlink():
        with pytest.raises(ValueError):
            read_regular_bounded(
                Path("/tmp/kuzet-artifact-does-not-exist"),
                max_bytes=64,
                label="artifact",
            )


def test_bounded_capture_rejects_nonsticky_writable_ancestor_and_allows_sticky(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir()
    child = ancestor / "private"
    child.mkdir(mode=0o700)
    artifact = _write_secure(child / "artifact", b"captured")
    ancestor.chmod(0o777)
    with pytest.raises(ValueError, match="unsafe directory"):
        read_regular_bounded(artifact, max_bytes=64, label="artifact")

    ancestor.chmod(0o1777)
    assert read_regular_bounded(artifact, max_bytes=64, label="artifact") == b"captured"


@pytest.mark.parametrize(
    ("mode", "accepted"),
    [
        (0o600, True),
        (0o644, True),
        (0o400, True),
        (0o444, True),
        (0o620, False),
        (0o602, False),
    ],
)
def test_bounded_capture_enforces_leaf_write_modes(
    tmp_path: Path,
    mode: int,
    accepted: bool,
) -> None:
    artifact = _write_secure(tmp_path / "artifact", b"captured")
    artifact.chmod(mode)
    if accepted:
        assert read_regular_bounded(artifact, max_bytes=64, label="artifact") == b"captured"
    else:
        with pytest.raises(ValueError):
            read_regular_bounded(artifact, max_bytes=64, label="artifact")


def test_bounded_capture_rejects_foreign_owned_leaf_when_root_can_exercise_it(
    tmp_path: Path,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("foreign-owner capture requires a root test runner")
    artifact = _write_secure(tmp_path / "artifact", b"captured")
    os.chown(artifact, 65_534, 65_534)
    with pytest.raises(ValueError):
        read_regular_bounded(artifact, max_bytes=64, label="artifact")


def test_bounded_capture_accepts_safe_root_owned_hosts_file() -> None:
    candidates = (Path("/private/etc/hosts"), Path("/etc/hosts"))
    artifact = next(
        (
            candidate
            for candidate in candidates
            if candidate.exists()
            and not candidate.is_symlink()
            and candidate.stat().st_uid == 0
            and candidate.stat().st_nlink == 1
            and not candidate.stat().st_mode & 0o022
        ),
        None,
    )
    if artifact is None:
        pytest.skip("no safe root-owned hosts file is available")
    assert read_regular_bounded(
        artifact,
        max_bytes=1024 * 1024,
        label="hosts artifact",
    )


def test_bounded_capture_opens_fifo_once_with_nonblocking_and_generic_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)
    original_open = os.open
    leaf_flags: list[int] = []

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if str(path) == fifo.name:
            leaf_flags.append(flags)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)
    with pytest.raises(ValueError) as raised:
        read_regular_bounded(fifo, max_bytes=64, label="fifo artifact")
    assert len(leaf_flags) == 1
    assert leaf_flags[0] & os.O_NONBLOCK
    assert str(fifo) not in str(raised.value)


def test_bounded_capture_loops_one_byte_short_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_secure(tmp_path / "artifact", b"captured-original")
    original_read = os.read
    original_payload = path.read_bytes()

    def short_read(descriptor: int, count: int) -> bytes:
        return original_read(descriptor, min(count, 1))

    monkeypatch.setattr(os, "read", short_read)
    assert read_regular_bounded(path, max_bytes=64, label="artifact") == original_payload


def test_bounded_capture_rejects_path_swap_during_short_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_secure(tmp_path / "artifact", b"captured-original")
    original_read = os.read
    original_open = os.open
    swapped = False
    leaf_open_count = 0

    def recording_open(
        opened_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal leaf_open_count
        if str(opened_path) == path.name:
            leaf_open_count += 1
        return original_open(opened_path, flags, mode, dir_fd=dir_fd)

    def short_read_and_swap(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, min(count, 1))
        if chunk and not swapped:
            swapped = True
            path.rename(tmp_path / "artifact-opened")
            _write_secure(path, b"attacker-replacement")
        return chunk

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "read", short_read_and_swap)
    with pytest.raises(ValueError, match="changed"):
        read_regular_bounded(path, max_bytes=64, label="artifact")
    assert leaf_open_count == 1


def test_bounded_capture_rejects_opened_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ancestor = tmp_path / "opened"
    ancestor.mkdir()
    path = _write_secure(ancestor / "artifact", b"captured-original")
    original_read = os.read
    swapped = False

    def short_read_and_swap_ancestor(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, min(count, 3))
        if chunk and not swapped:
            swapped = True
            ancestor.rename(tmp_path / "opened-original")
            ancestor.mkdir()
            _write_secure(ancestor / "artifact", b"attacker-replacement")
        return chunk

    monkeypatch.setattr(os, "read", short_read_and_swap_ancestor)
    with pytest.raises(ValueError, match="changed"):
        read_regular_bounded(path, max_bytes=64, label="artifact")


def test_bounded_capture_rejects_ctime_change_even_if_size_and_mtime_are_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_secure(tmp_path / "artifact", b"0123456789")
    before = path.stat()
    original_read = os.read
    mutated = False

    def same_size_mutating_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, min(count, 1))
        if chunk and not mutated:
            mutated = True
            with path.open("r+b") as handle:
                handle.write(b"X")
            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
        return chunk

    monkeypatch.setattr(os, "read", same_size_mutating_read)
    with pytest.raises(ValueError, match="changed"):
        read_regular_bounded(path, max_bytes=64, label="artifact")


def test_bounded_capture_rejects_excessive_path_bytes_or_components() -> None:
    with pytest.raises(ValueError, match="path"):
        read_regular_bounded(
            Path("/" + "/".join("component" for _ in range(80))),
            max_bytes=64,
            label="artifact",
        )
    with pytest.raises(ValueError, match="path"):
        read_regular_bounded(
            Path("/" + "x" * 5000),
            max_bytes=64,
            label="artifact",
        )


@pytest.mark.parametrize("mutation", ["grow", "shrink", "overwrite", "chmod"])
def test_bounded_capture_rejects_size_or_mtime_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = _write_secure(tmp_path / "artifact", b"0123456789")
    original_read = os.read
    mutated = False

    def mutating_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, min(count, 3))
        if chunk and not mutated:
            mutated = True
            if mutation == "grow":
                with path.open("ab") as handle:
                    handle.write(b"grow")
            elif mutation == "shrink":
                os.truncate(path, 2)
            elif mutation == "overwrite":
                with path.open("r+b") as handle:
                    handle.write(b"XX")
            else:
                path.chmod(0o400)
        return chunk

    monkeypatch.setattr(os, "read", mutating_read)
    with pytest.raises(ValueError, match="changed"):
        read_regular_bounded(path, max_bytes=64, label="artifact")


def test_bounded_capture_enforces_empty_exact_and_over_limit_sizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = _write_secure(tmp_path / "empty", b"")
    with pytest.raises(ValueError):
        read_regular_bounded(empty, max_bytes=10, label="artifact")
    exact = _write_secure(tmp_path / "exact", b"0123456789")
    assert read_regular_bounded(exact, max_bytes=10, label="artifact") == b"0123456789"
    over = _write_secure(tmp_path / "over", b"01234567890")
    with pytest.raises(ValueError):
        read_regular_bounded(over, max_bytes=10, label="artifact")

    growing = _write_secure(tmp_path / "growing", b"0123456789")
    original_read = os.read
    grew = False

    def growing_read(descriptor: int, count: int) -> bytes:
        nonlocal grew
        chunk = original_read(descriptor, min(count, 3))
        if chunk and not grew:
            grew = True
            with growing.open("ab") as handle:
                handle.write(b"x")
        return chunk

    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(ValueError):
        read_regular_bounded(growing, max_bytes=10, label="artifact")


def test_bounded_capture_errors_suppress_runtime_path_and_os_context(
    tmp_path: Path,
) -> None:
    secret_marker = "DO_NOT_DISCLOSE_RUNTIME_SECRET"
    missing = tmp_path / secret_marker / "artifact"
    try:
        read_regular_bounded(missing, max_bytes=64, label="artifact")
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert secret_marker not in rendered
        assert str(tmp_path) not in rendered
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
    else:
        raise AssertionError("missing artifact unexpectedly captured")


def test_bounded_capture_allows_harmless_unrelated_ancestor_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    artifact = _write_secure(nested / "artifact", b"captured-original")
    original_read = os.read
    changed = False

    def short_read_with_unrelated_churn(descriptor: int, count: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, min(count, 1))
        if chunk and not changed:
            changed = True
            _write_secure(nested / "unrelated", b"harmless")
        return chunk

    monkeypatch.setattr(os, "read", short_read_with_unrelated_churn)
    assert read_regular_bounded(artifact, max_bytes=64, label="artifact") == b"captured-original"


def test_bounded_capture_malformed_path_encoding_is_generic() -> None:
    secret_marker = "DO_NOT_DISCLOSE_\ud800"
    malformed = Path(f"/tmp/{secret_marker}")
    try:
        read_regular_bounded(malformed, max_bytes=64, label="artifact")
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert "DO_NOT_DISCLOSE" not in rendered
        assert str(exc) == "artifact path or bound is invalid"
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
    else:
        raise AssertionError("malformed path unexpectedly captured")


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o400, 0o444])
def test_bounded_capture_preserves_exact_pem_crlf_and_trailing_newline(
    tmp_path: Path,
    key_material: dict[str, _Key],
    mode: int,
) -> None:
    payload = key_material["manifest"].public.replace(b"\n", b"\r\n") + b"\r\n"
    artifact = _write_secure(tmp_path / "authority.pem", payload)
    artifact.chmod(mode)
    assert (
        read_regular_bounded(
            artifact,
            max_bytes=64 * 1024,
            label="public key",
        )
        == payload
    )


def test_canonical_json_rejects_excessive_depth_nodes_and_scalar_bytes() -> None:
    nested: object = "end"
    for _ in range(40):
        nested = [nested]
    with pytest.raises(ValueError, match="depth"):
        load_canonical_json_bytes(
            _fixture_canonical_json({"payload": nested}),
            _ArbitraryDocument,
        )

    with pytest.raises(ValueError, match="nodes"):
        load_canonical_json_bytes(
            _fixture_canonical_json({"payload": [None] * (MAX_STRUCTURED_NODES + 1)}),
            _ArbitraryDocument,
        )

    with pytest.raises(ValueError, match="scalar"):
        load_canonical_json_bytes(
            _fixture_canonical_json({"payload": "x" * (MAX_STRUCTURED_SCALAR_BYTES + 1)}),
            _ArbitraryDocument,
        )


def test_restricted_operational_yaml_loads_only_plain_string_keyed_data() -> None:
    assert load_restricted_yaml_bytes(
        b"site_id: school-01\ngates:\n  - 8h\n  - 72h\nenabled: true\n",
    ) == {
        "site_id": "school-01",
        "gates": ["8h", "72h"],
        "enabled": True,
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"outer:\n  key: one\n  key: two\n",
        b"value: &shared one\nother: *shared\n",
        b"value: &unused one\n",
        b"base: &base\n  key: one\nmerged:\n  <<: *base\n",
        b"value: !custom tagged\n",
        b"value: !!str tagged\n",
        b"1: value\n",
        b"first: document\n---\nsecond: document\n",
        b"\xef\xbb\xbfsite: school-01\n",
        b"value: .nan\n",
        b"value: .inf\n",
        b"value: -.Inf\n",
        b"value: yes\n",
        b"value: NO\n",
        b"value: 012\n",
        b"value: 1:20\n",
        b"value: 2026-07-30\n",
        b"value: 2026-07-30T12:00:00Z\n",
    ],
)
def test_restricted_operational_yaml_rejects_ambiguous_or_nonfinite_input(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError):
        load_restricted_yaml_bytes(payload)


@pytest.mark.parametrize(
    "plain_value",
    [
        "",
        "Null",
        "NULL",
        "True",
        "TRUE",
        "False",
        "FALSE",
        "y",
        "Y",
        "n",
        "N",
        "t",
        "T",
        "f",
        "F",
        "+1",
        "+0.5",
        "1_000",
        "0_1",
        "1.",
        ".5",
        "1.e2",
        "1e",
        "Infinity",
        "+Infinity",
        "-Infinity",
        "NaN",
        "None",
        "nil",
        "2001-12-15 2:59:43.10 -5",
    ],
)
def test_restricted_operational_yaml_rejects_every_ambiguous_plain_scalar(
    plain_value: str,
) -> None:
    with pytest.raises(ValueError):
        load_restricted_yaml_bytes(f"value: {plain_value}\n".encode())


def test_restricted_operational_yaml_only_implicitly_types_exact_json_scalars() -> None:
    assert load_restricted_yaml_bytes(
        (
            b"null_value: null\n"
            b"truth: true\n"
            b"falsehood: false\n"
            b"zero: 0\n"
            b"negative_zero: -0\n"
            b"integer: -12\n"
            b"decimal: 1.25\n"
            b"exponent: 1e+2\n"
            b'quoted_true: "TRUE"\n'
            b"quoted_null: 'Null'\n"
            b'quoted_number: "+1"\n'
            b"gate: 8h\n"
        )
    ) == {
        "null_value": None,
        "truth": True,
        "falsehood": False,
        "zero": 0,
        "negative_zero": 0,
        "integer": -12,
        "decimal": 1.25,
        "exponent": 100.0,
        "quoted_true": "TRUE",
        "quoted_null": "Null",
        "quoted_number": "+1",
        "gate": "8h",
    }


def test_restricted_yaml_rejects_leading_dot_exponent_and_underscore_family() -> None:
    variants = {
        f"{outer_sign}{mantissa}{marker}{exponent_sign}{exponent_digits}"
        for outer_sign in ("", "+", "-")
        for mantissa in (".5", ".5_")
        for marker in ("e", "E")
        for exponent_sign in ("", "+", "-")
        for exponent_digits in ("2", "02", "_2", "2_")
    }
    variants.update(
        {
            ".5e2",
            "+.5e2",
            "-.5e2",
            ".5e02",
            ".5E2",
            "-.5E02",
            "+.5E+2",
            "-.5e-2",
            ".5_e2",
            ".5e_2",
            ".5e2_",
        }
    )
    for scalar in sorted(variants):
        with pytest.raises(ValueError):
            load_restricted_yaml_bytes(f"value: {scalar}\n".encode())
        assert load_restricted_yaml_bytes(f'value: "{scalar}"\n'.encode()) == {"value": scalar}
    assert load_restricted_yaml_bytes(b"value: 1e2\n") == {"value": 100.0}


def test_restricted_operational_yaml_rejects_excessive_depth_nodes_and_scalar_bytes() -> None:
    nested_lines = ["value:"]
    indentation = 2
    for _ in range(40):
        nested_lines.append(f"{' ' * indentation}-")
        indentation += 2
    nested_lines.append(f"{' ' * indentation}end")
    with pytest.raises(ValueError, match="depth"):
        load_restricted_yaml_bytes(("\n".join(nested_lines) + "\n").encode())
    with pytest.raises(ValueError, match="nodes"):
        load_restricted_yaml_bytes(
            ("values:\n" + "".join("  - null\n" for _ in range(MAX_STRUCTURED_NODES + 1))).encode()
        )
    with pytest.raises(ValueError, match="scalar"):
        load_restricted_yaml_bytes(f'value: "{"x" * (MAX_STRUCTURED_SCALAR_BYTES + 1)}"\n'.encode())


def test_acceptance_trust_policy_accepts_exact_six_role_separated_fingerprints() -> None:
    policy = AcceptanceTrustPolicyV2.model_validate(_policy())
    assert isinstance(policy.roles, AcceptanceRolePinsV2)
    assert policy.allowed_gates == ("8h", "72h")


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_id", "../policy"),
        ("campaign_id", "https://campaign"),
        ("site_id", " school-01"),
        ("signature_algorithm", "RSA"),
        ("allowed_gates", ()),
        ("allowed_gates", ("72h", "8h")),
        ("allowed_gates", ("8h", "8h")),
        ("allowed_gates", ("contract",)),
    ],
)
def test_acceptance_trust_policy_rejects_unsafe_identity_algorithm_or_gate_order(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError):
        AcceptanceTrustPolicyV2.model_validate(_policy(**{field: value}))


def test_acceptance_trust_policy_rejects_validity_longer_than_366_days() -> None:
    with pytest.raises(ValueError):
        AcceptanceTrustPolicyV2.model_validate(
            _policy(
                valid_from=NOW,
                valid_until=NOW + timedelta(days=366, microseconds=1),
            )
        )


def test_acceptance_trust_policy_rejects_subsecond_validity() -> None:
    with pytest.raises(ValueError, match="second"):
        AcceptanceTrustPolicyV2.model_validate(_policy(valid_from=NOW.replace(microsecond=1)))


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("root", "manifest"),
        ("root", "capacity"),
        ("root", "run"),
        ("root", "report"),
        ("root", "conditional"),
        ("manifest", "capacity"),
        ("manifest", "run"),
        ("manifest", "report"),
        ("manifest", "conditional"),
        ("capacity", "run"),
        ("capacity", "report"),
        ("capacity", "conditional"),
        ("run", "report"),
        ("run", "conditional"),
        ("report", "conditional"),
    ],
)
def test_acceptance_trust_policy_rejects_every_root_or_role_collision(
    left: str,
    right: str,
) -> None:
    field_by_role = {role: f"{role}_spki_sha256" for role in ROLE_NAMES}
    role_values = _role_pins()
    root = FINGERPRINTS[0]
    if left == "root":
        role_values[field_by_role[right]] = root
    else:
        role_values[field_by_role[right]] = role_values[field_by_role[left]]
    with pytest.raises(ValueError, match="distinct"):
        AcceptanceTrustPolicyV2.model_validate(_policy(roles=role_values))


@dataclass(frozen=True)
class _Key:
    private: bytes
    public: bytes
    spki_sha256: str


def _run_openssl(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["openssl", *arguments],
        check=True,
        capture_output=True,
        timeout=30,
    )


@pytest.fixture(scope="session")
def key_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, _Key]:
    if subprocess.run(["openssl", "version"], check=False, capture_output=True).returncode:
        pytest.skip("OpenSSL is required for acceptance trust-chain tests")
    root = tmp_path_factory.mktemp("acceptance-trust-keys")
    material: dict[str, _Key] = {}
    names = (
        "root",
        *ROLE_NAMES,
        "attacker-root",
        *(f"attacker-{role}" for role in ROLE_NAMES),
    )
    for name in names:
        private = root / f"{name}.private.pem"
        public = root / f"{name}.public.pem"
        _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(private)])
        _run_openssl(["pkey", "-in", str(private), "-pubout", "-out", str(public)])
        der = _run_openssl(
            [
                "pkey",
                "-pubin",
                "-in",
                str(public),
                "-outform",
                "DER",
            ]
        ).stdout
        assert len(der) == 44
        material[name] = _Key(
            private=private.read_bytes(),
            public=public.read_bytes(),
            spki_sha256=hashlib.sha256(der).hexdigest(),
        )

    rsa_private = root / "rsa.private.pem"
    rsa_public = root / "rsa.public.pem"
    _run_openssl(
        [
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(rsa_private),
        ]
    )
    _run_openssl(["pkey", "-in", str(rsa_private), "-pubout", "-out", str(rsa_public)])
    material["rsa"] = _Key(
        private=rsa_private.read_bytes(),
        public=rsa_public.read_bytes(),
        spki_sha256="0" * 64,
    )
    return material


def _write_secure(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _sign(
    tmp_path: Path,
    *,
    name: str,
    payload: bytes,
    private_key: bytes,
) -> bytes:
    payload_path = _write_secure(tmp_path / f"{name}.payload", payload)
    private_path = _write_secure(tmp_path / f"{name}.private.pem", private_key)
    signature_path = tmp_path / f"{name}.sig"
    _run_openssl(
        [
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_path),
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ]
    )
    return signature_path.read_bytes()


def _fixture_canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _chain_policy(
    keys: dict[str, _Key],
    *,
    prefix: str = "",
    manifest_payload: bytes,
    **updates: object,
) -> dict[str, Any]:
    key_name = lambda role: f"{prefix}{role}"  # noqa: E731
    values: dict[str, Any] = {
        "schema_version": "acceptance-trust-policy.v2",
        "policy_id": "policy-2026-001",
        "campaign_id": "campaign-2026-001",
        "site_id": "school-01",
        "signature_algorithm": "Ed25519",
        "root_spki_sha256": keys[key_name("root")].spki_sha256,
        "valid_from": _iso(NOW - timedelta(days=1)),
        "valid_until": _iso(NOW + timedelta(days=30)),
        "allowed_gates": ["8h", "72h"],
        "manifest_payload_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "roles": {
            "schema_version": "acceptance-role-pins.v2",
            **{f"{role}_spki_sha256": keys[key_name(role)].spki_sha256 for role in ROLE_NAMES},
        },
    }
    values.update(updates)
    return values


@dataclass(frozen=True)
class _Bundle:
    expected_root_spki_sha256: str
    root_public_key: Path
    policy: Path
    policy_signature: Path
    role_keys: AcceptanceRolePublicKeyPathsV2
    manifest: Path
    manifest_signature: Path
    policy_payload: bytes
    manifest_payload: bytes


def _bundle(
    tmp_path: Path,
    keys: dict[str, _Key],
    *,
    prefix: str = "",
    external_root_name: str | None = None,
    policy_updates: dict[str, object] | None = None,
    manifest_payload: bytes | None = None,
    policy_signer: str | None = None,
    manifest_signer: str | None = None,
    rewrite_manifest_role_pins: bool = True,
) -> _Bundle:
    if manifest_payload is None:
        fixture_root = tmp_path / "acceptance-manifest-fixtures"
        fixture_root.mkdir()
        manifest_payload = _fixture_canonical_json(
            _acceptance_manifest_fixture(fixture_root).model_dump(mode="json")
        )
    key_name = lambda role: f"{prefix}{role}"  # noqa: E731
    if rewrite_manifest_role_pins:
        manifest_document = json.loads(manifest_payload)
        manifest_document["launch"]["capacity_trust_key_spki_sha256"] = keys[
            key_name("capacity")
        ].spki_sha256
        manifest_document["launch"]["run_authority_public_key_spki_sha256"] = keys[
            key_name("run")
        ].spki_sha256
        manifest_payload = _fixture_canonical_json(manifest_document)
    policy_payload = _fixture_canonical_json(
        _chain_policy(
            keys,
            prefix=prefix,
            manifest_payload=manifest_payload,
            **(policy_updates or {}),
        )
    )
    root_public = _write_secure(
        tmp_path / "root.public.pem",
        keys[key_name("root")].public,
    )
    policy = _write_secure(tmp_path / "policy.json", policy_payload)
    policy_signature = _write_secure(
        tmp_path / "policy.sig",
        _sign(
            tmp_path,
            name="policy-signing",
            payload=policy_payload,
            private_key=keys[policy_signer or key_name("root")].private,
        ),
    )
    role_paths = {
        role: _write_secure(
            tmp_path / f"{role}.public.pem",
            keys[key_name(role)].public,
        )
        for role in ROLE_NAMES
    }
    manifest = _write_secure(tmp_path / "manifest.json", manifest_payload)
    manifest_signature = _write_secure(
        tmp_path / "manifest.sig",
        _sign(
            tmp_path,
            name="manifest-signing",
            payload=manifest_payload,
            private_key=keys[manifest_signer or key_name("manifest")].private,
        ),
    )
    external_name = external_root_name or key_name("root")
    return _Bundle(
        expected_root_spki_sha256=keys[external_name].spki_sha256,
        root_public_key=root_public,
        policy=policy,
        policy_signature=policy_signature,
        role_keys=AcceptanceRolePublicKeyPathsV2(**role_paths),
        manifest=manifest,
        manifest_signature=manifest_signature,
        policy_payload=policy_payload,
        manifest_payload=manifest_payload,
    )


def _verify(bundle: _Bundle) -> VerifiedAcceptanceTrustV2:
    return verify_acceptance_trust_chain(
        expected_offline_root_spki_sha256=bundle.expected_root_spki_sha256,
        root_public_key_path=bundle.root_public_key,
        policy_path=bundle.policy,
        policy_signature_path=bundle.policy_signature,
        role_public_key_paths=bundle.role_keys,
        manifest_path=bundle.manifest,
        manifest_signature_path=bundle.manifest_signature,
    )


def _grant(
    bundle: _Bundle,
    **updates: object,
) -> ExecutionTrustGrantV2:
    arguments: dict[str, object] = {
        "expected_site_id": "school-01",
        "expected_campaign_id": "campaign-2026-001",
        "expected_gate": "8h",
        "execution_started_at": NOW,
    }
    arguments.update(updates)
    return authorize_acceptance_execution(
        _verify(bundle),
        **arguments,  # type: ignore[arg-type]
    )


def test_trust_chain_returns_only_captured_policy_manifest_and_pinned_keys(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(tmp_path, key_material)
    verified = _verify(bundle)
    assert verified.policy.policy_id == "policy-2026-001"
    assert verified.manifest.site_id == "school-01"
    assert verified.policy_payload == bundle.policy_payload
    assert verified.manifest_payload == bundle.manifest_payload
    assert verified.manifest_payload_sha256 == hashlib.sha256(bundle.manifest_payload).hexdigest()
    assert verified.role_public_keys.manifest == key_material["manifest"].public
    grant = _grant(bundle)
    assert grant.execution_ends_at == NOW + timedelta(hours=8)


def test_verified_trust_cannot_be_minted_through_public_constructor(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    verified = _verify(_bundle(tmp_path, key_material))
    public_fields = {
        field.name: getattr(verified, field.name)
        for field in fields(VerifiedAcceptanceTrustV2)
        if not field.name.startswith("_")
    }
    with pytest.raises(TypeError, match="verifier"):
        VerifiedAcceptanceTrustV2(**public_fields)


def test_verified_trust_receipt_is_bound_to_every_exact_field(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    verified = _verify(_bundle(tmp_path, key_material))
    forged = object.__new__(VerifiedAcceptanceTrustV2)
    for field in fields(VerifiedAcceptanceTrustV2):
        object.__setattr__(forged, field.name, getattr(verified, field.name))
    object.__setattr__(forged, "policy_sha256", "0" * 64)

    with pytest.raises(ValueError, match="provenance"):
        authorize_acceptance_execution(
            forged,
            expected_site_id="school-01",
            expected_campaign_id="campaign-2026-001",
            expected_gate="8h",
            execution_started_at=NOW,
        )


def test_historical_verification_after_expiry_cannot_authorize_new_execution(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(tmp_path, key_material)
    verified = _verify(bundle)
    historical = verify_historical_acceptance_trust(
        verified,
        expected_site_id="school-01",
        expected_campaign_id="campaign-2026-001",
        expected_gate="8h",
        execution_started_at=NOW,
        verified_at=NOW + timedelta(days=90),
    )
    assert isinstance(historical, HistoricalTrustVerificationV2)
    assert not isinstance(historical, ExecutionTrustGrantV2)
    with pytest.raises(ValueError, match="valid"):
        authorize_acceptance_execution(
            verified,
            expected_site_id="school-01",
            expected_campaign_id="campaign-2026-001",
            expected_gate="8h",
            execution_started_at=NOW + timedelta(days=90),
        )


@pytest.mark.parametrize(
    "verified_at",
    [
        NOW - timedelta(seconds=1),
        NOW,
        NOW + timedelta(hours=4),
        NOW + timedelta(hours=8) - timedelta(microseconds=1),
    ],
)
def test_historical_verification_rejects_before_execution_has_finished(
    tmp_path: Path,
    key_material: dict[str, _Key],
    verified_at: datetime,
) -> None:
    verified = _verify(_bundle(tmp_path, key_material))
    with pytest.raises(ValueError, match="finished"):
        verify_historical_acceptance_trust(
            verified,
            expected_site_id="school-01",
            expected_campaign_id="campaign-2026-001",
            expected_gate="8h",
            execution_started_at=NOW,
            verified_at=verified_at,
        )


def test_historical_verification_accepts_the_exact_execution_end(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    verified = _verify(_bundle(tmp_path, key_material))
    historical = verify_historical_acceptance_trust(
        verified,
        expected_site_id="school-01",
        expected_campaign_id="campaign-2026-001",
        expected_gate="8h",
        execution_started_at=NOW,
        verified_at=NOW + timedelta(hours=8),
    )
    assert historical.verified_at == historical.execution_ends_at


def test_execution_grant_requires_the_full_gate_to_fit_policy_validity(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(
        tmp_path,
        key_material,
        policy_updates={"valid_until": _iso(NOW + timedelta(hours=4))},
    )
    with pytest.raises(ValueError, match="full gate"):
        _grant(bundle)


def test_fully_self_signed_attacker_chain_is_rejected_by_offline_root_fingerprint(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    attacker = _bundle(
        tmp_path,
        key_material,
        prefix="attacker-",
        external_root_name="root",
    )
    with pytest.raises(ValueError, match="offline root"):
        _verify(attacker)


@pytest.mark.parametrize(
    ("target_timestamp", "message"),
    [
        (NOW - timedelta(days=2), "valid"),
        (NOW + timedelta(days=31), "valid"),
    ],
)
def test_trust_chain_rejects_future_or_expired_policy(
    tmp_path: Path,
    key_material: dict[str, _Key],
    target_timestamp: datetime,
    message: str,
) -> None:
    bundle = _bundle(tmp_path, key_material)
    with pytest.raises(ValueError, match=message):
        _grant(bundle, execution_started_at=target_timestamp)


def test_trust_chain_rejects_policy_over_366_days(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(
        tmp_path,
        key_material,
        policy_updates={
            "valid_from": _iso(NOW),
            "valid_until": _iso(NOW + timedelta(days=367)),
        },
    )
    with pytest.raises(ValueError):
        _verify(bundle)


@pytest.mark.parametrize("artifact", ["policy", "manifest", "role-key"])
def test_trust_chain_enforces_policy_manifest_and_key_byte_caps(
    tmp_path: Path,
    key_material: dict[str, _Key],
    artifact: str,
) -> None:
    bundle = _bundle(tmp_path, key_material)
    if artifact == "policy":
        _write_secure(bundle.policy, b"x" * (MAX_TRUST_POLICY_BYTES + 1))
    elif artifact == "manifest":
        _write_secure(
            bundle.manifest,
            b"x" * (MAX_ACCEPTANCE_MANIFEST_BYTES + 1),
        )
    else:
        _write_secure(bundle.role_keys.run, b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="bound"):
        _verify(bundle)


@pytest.mark.parametrize(
    ("argument", "value"),
    [
        ("expected_site_id", "other-site"),
        ("expected_campaign_id", "other-campaign"),
        ("expected_gate", "72h"),
    ],
)
def test_trust_chain_rejects_wrong_site_campaign_or_gate(
    tmp_path: Path,
    key_material: dict[str, _Key],
    argument: str,
    value: str,
) -> None:
    bundle = _bundle(
        tmp_path,
        key_material,
        policy_updates=({"allowed_gates": ["8h"]} if argument == "expected_gate" else None),
    )
    with pytest.raises(ValueError, match="context"):
        _grant(bundle, **{argument: value})


def test_trust_chain_rejects_wrong_policy_root_pin(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(
        tmp_path,
        key_material,
        policy_updates={
            "root_spki_sha256": key_material["attacker-root"].spki_sha256,
        },
    )
    with pytest.raises(ValueError, match="root"):
        _verify(bundle)


def test_trust_chain_rejects_changed_manifest_even_when_resigned_by_manifest_role(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(tmp_path, key_material)
    changed = b'{"schema_version":"acceptance-manifest.v2","site_id":"other-site"}'
    _write_secure(bundle.manifest, changed)
    _write_secure(
        bundle.manifest_signature,
        _sign(
            tmp_path,
            name="changed-manifest",
            payload=changed,
            private_key=key_material["manifest"].private,
        ),
    )
    with pytest.raises(ValueError, match="manifest"):
        _verify(bundle)


def test_trust_chain_rejects_typed_manifest_for_a_different_policy_site(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    fixture_root = tmp_path / "different-site-fixtures"
    fixture_root.mkdir()
    manifest = _acceptance_manifest_fixture(fixture_root).model_dump(mode="json")
    manifest["site_id"] = "other-site"
    manifest["launch"]["site_id"] = "other-site"
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle = _bundle(
        bundle_root,
        key_material,
        manifest_payload=_fixture_canonical_json(manifest),
    )
    with pytest.raises(ValueError, match="site"):
        _verify(bundle)


def test_trust_chain_rejects_policy_hash_field_inside_target_manifest(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    fixture_root = tmp_path / "cycle-fixtures"
    fixture_root.mkdir()
    manifest = _acceptance_manifest_fixture(fixture_root).model_dump(mode="json")
    manifest["policy_sha256"] = "a" * 64
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle = _bundle(
        bundle_root,
        key_material,
        manifest_payload=_fixture_canonical_json(manifest),
    )
    with pytest.raises(ValueError, match="manifest"):
        _verify(bundle)


@pytest.mark.parametrize(
    ("role", "launch_field"),
    [
        ("run", "run_authority_public_key_spki_sha256"),
        ("capacity", "capacity_trust_key_spki_sha256"),
    ],
)
def test_trust_chain_rejects_manifest_launch_role_pin_conflicts(
    tmp_path: Path,
    key_material: dict[str, _Key],
    role: str,
    launch_field: str,
) -> None:
    fixture_root = tmp_path / "launch-pin-fixtures"
    fixture_root.mkdir()
    manifest = _acceptance_manifest_fixture(fixture_root).model_dump(mode="json")
    manifest["launch"]["run_authority_public_key_spki_sha256"] = key_material["run"].spki_sha256
    manifest["launch"]["capacity_trust_key_spki_sha256"] = key_material["capacity"].spki_sha256
    manifest["launch"][launch_field] = key_material[f"attacker-{role}"].spki_sha256
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle = _bundle(
        bundle_root,
        key_material,
        manifest_payload=_fixture_canonical_json(manifest),
        rewrite_manifest_role_pins=False,
    )
    with pytest.raises(ValueError, match=role):
        _verify(bundle)


def test_trust_chain_rejects_nonnull_conditional_role_pin_conflict(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    fixture_root = tmp_path / "conditional-pin-fixtures"
    fixture_root.mkdir()
    manifest = _acceptance_manifest_fixture(fixture_root).model_dump(mode="json")
    manifest["launch"]["run_authority_public_key_spki_sha256"] = key_material["run"].spki_sha256
    manifest["launch"]["capacity_trust_key_spki_sha256"] = key_material["capacity"].spki_sha256
    weapon = next(module for module in manifest["modules"] if module["module"] == "weapon")
    weapon["gate_trust_key_spki_sha256"] = key_material["attacker-conditional"].spki_sha256
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle = _bundle(
        bundle_root,
        key_material,
        manifest_payload=_fixture_canonical_json(manifest),
        rewrite_manifest_role_pins=False,
    )
    with pytest.raises(ValueError, match="conditional"):
        _verify(bundle)


@pytest.mark.parametrize("signature_name", ["policy", "manifest"])
def test_trust_chain_rejects_invalid_policy_or_manifest_signature(
    tmp_path: Path,
    key_material: dict[str, _Key],
    signature_name: str,
) -> None:
    bundle = _bundle(tmp_path, key_material)
    signature_path = (
        bundle.policy_signature if signature_name == "policy" else bundle.manifest_signature
    )
    signature = bytearray(signature_path.read_bytes())
    signature[0] ^= 0x01
    _write_secure(signature_path, bytes(signature))
    with pytest.raises(ValueError, match="signature"):
        _verify(bundle)


@pytest.mark.parametrize("signature_name", ["policy", "manifest"])
@pytest.mark.parametrize("size", [63, 65])
def test_trust_chain_rejects_wrong_ed25519_signature_lengths(
    tmp_path: Path,
    key_material: dict[str, _Key],
    signature_name: str,
    size: int,
) -> None:
    bundle = _bundle(tmp_path, key_material)
    signature_path = (
        bundle.policy_signature if signature_name == "policy" else bundle.manifest_signature
    )
    _write_secure(signature_path, b"x" * size)
    with pytest.raises(ValueError, match="signature"):
        _verify(bundle)


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_trust_chain_rejects_substitution_of_every_role_key(
    tmp_path: Path,
    key_material: dict[str, _Key],
    role: str,
) -> None:
    bundle = _bundle(tmp_path, key_material)
    role_path = getattr(bundle.role_keys, role)
    _write_secure(role_path, key_material[f"attacker-{role}"].public)
    with pytest.raises(ValueError, match="role"):
        _verify(bundle)


def test_pem_formatting_variants_have_the_same_canonical_spki_identity(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(tmp_path, key_material)
    _write_secure(
        bundle.root_public_key,
        key_material["root"].public.replace(b"\n", b"\r\n"),
    )
    _write_secure(
        bundle.role_keys.capacity,
        b"\n" + key_material["capacity"].public + b"\n",
    )
    verified = _verify(bundle)
    assert verified.root_spki_sha256 == key_material["root"].spki_sha256
    assert verified.policy.roles.capacity_spki_sha256 == key_material["capacity"].spki_sha256
    assert verified.root_public_key == key_material["root"].public
    assert verified.role_public_keys.capacity == key_material["capacity"].public


@pytest.mark.parametrize(
    "suffix",
    [
        b"trailing-garbage",
        b"\n-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
    ],
)
def test_ed25519_public_key_parser_rejects_trailing_non_whitespace(
    key_material: dict[str, _Key],
    suffix: bytes,
) -> None:
    with pytest.raises(ValueError, match="public key"):
        ed25519_public_key_spki_sha256(key_material["root"].public + suffix)


def test_ed25519_public_key_parser_rejects_appended_second_public_key(
    key_material: dict[str, _Key],
) -> None:
    with pytest.raises(ValueError, match="public key"):
        ed25519_public_key_spki_sha256(
            key_material["root"].public + key_material["manifest"].public
        )


def test_verified_detached_artifact_retains_only_canonical_key_material(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    payload = b"signed acceptance artifact"
    payload_path = _write_secure(tmp_path / "artifact", payload)
    signature_path = _write_secure(
        tmp_path / "artifact.sig",
        _sign(
            tmp_path,
            name="artifact-signing",
            payload=payload,
            private_key=key_material["manifest"].private,
        ),
    )
    variant = b"\r\n" + key_material["manifest"].public.replace(b"\n", b"\r\n") + b"\r\n"
    key_path = _write_secure(tmp_path / "artifact.public.pem", variant)
    verified = verify_detached_artifact(
        payload_path=payload_path,
        signature_path=signature_path,
        trusted_public_key_path=key_path,
        expected_payload_sha256=hashlib.sha256(payload).hexdigest(),
        max_payload_bytes=1024,
        label="acceptance artifact",
    )
    assert verified.trust_key == key_material["manifest"].public
    assert verified.trust_key != variant


def test_verified_trust_graph_has_no_mutable_container_reachable_from_it(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    verified = _verify(_bundle(tmp_path, key_material))
    source = verified.manifest.sources[0]
    assert isinstance(source.analytics_hz, MappingProxyType)
    with pytest.raises(TypeError):
        source.analytics_hz["person"] = 0.0  # type: ignore[index]
    assert canonical_json_bytes(verified.manifest) == verified.manifest_payload

    def assert_deeply_immutable(value: object) -> None:
        assert not isinstance(value, (dict, list, set))
        if isinstance(value, FrozenModel):
            for field_name in type(value).model_fields:
                assert_deeply_immutable(getattr(value, field_name))
        elif dataclass_is_instance(value):
            for field_name in value.__dataclass_fields__:
                assert_deeply_immutable(getattr(value, field_name))
        elif isinstance(value, tuple):
            for nested in value:
                assert_deeply_immutable(nested)
        elif isinstance(value, Mapping):
            assert isinstance(value, MappingProxyType)
            for key, nested in value.items():
                assert_deeply_immutable(key)
                assert_deeply_immutable(nested)

    assert_deeply_immutable(verified)


def dataclass_is_instance(value: object) -> bool:
    return hasattr(value, "__dataclass_fields__") and not isinstance(value, type)


@pytest.mark.parametrize(
    ("loader", "payload"),
    [
        (
            lambda payload: load_canonical_json_bytes(payload, _TinyDocument),
            (
                b'{"nested":{"DO_NOT_DISCLOSE_ATTACKER_SECRET":1,'
                b'"DO_NOT_DISCLOSE_ATTACKER_SECRET":2},'
                b'"schema_version":"tiny.v1"}'
            ),
        ),
        (
            lambda payload: load_canonical_json_bytes(payload, _TinyDocument),
            (
                b'{"nested":{"count":"DO_NOT_DISCLOSE_ATTACKER_SECRET\\nline"},'
                b'"schema_version":"tiny.v1"}'
            ),
        ),
        (
            load_restricted_yaml_bytes,
            (
                b"outer:\n"
                b"  DO_NOT_DISCLOSE_ATTACKER_SECRET: first\n"
                b"  DO_NOT_DISCLOSE_ATTACKER_SECRET: second\n"
            ),
        ),
        (
            load_restricted_yaml_bytes,
            b"value: [DO_NOT_DISCLOSE_ATTACKER_SECRET\n",
        ),
        (
            lambda payload: load_canonical_json_bytes(payload, _TinyDocument),
            (
                b'{"nested":{"count":"\\ud800DO_NOT_DISCLOSE_ATTACKER_SECRET"},'
                b'"schema_version":"tiny.v1"}'
            ),
        ),
        (
            load_restricted_yaml_bytes,
            b"value: DO_NOT_DISCLOSE_ATTACKER_SECRET\xff\n",
        ),
    ],
)
def test_attacker_artifact_errors_are_constant_and_suppress_parser_context(
    loader: Any,
    payload: bytes,
) -> None:
    try:
        loader(payload)
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert "DO_NOT_DISCLOSE_ATTACKER_SECRET" not in rendered
        assert "first" not in str(exc)
        assert "second" not in str(exc)
        assert "\n" not in str(exc)
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
    else:
        raise AssertionError("attacker artifact unexpectedly loaded")


@pytest.mark.parametrize(
    "payloads",
    [
        (
            b'{"nested":{"secret-a":1,"secret-a":2},"schema_version":"tiny.v1"}',
            b'{"nested":{"secret-b":1,"secret-b":2},"schema_version":"tiny.v1"}',
        ),
        (
            b'{"nested":{"count":"secret-a"},"schema_version":"tiny.v1"}',
            b'{"nested":{"count":"secret-b"},"schema_version":"tiny.v1"}',
        ),
    ],
)
def test_json_artifact_error_messages_do_not_depend_on_attacker_content(
    payloads: tuple[bytes, bytes],
) -> None:
    errors: list[ValueError] = []
    for payload in payloads:
        with pytest.raises(ValueError) as caught:
            load_canonical_json_bytes(payload, _TinyDocument)
        errors.append(caught.value)
    assert str(errors[0]) == str(errors[1])


def test_trust_chain_rejects_non_ed25519_public_key(
    tmp_path: Path,
    key_material: dict[str, _Key],
) -> None:
    bundle = _bundle(tmp_path, key_material)
    _write_secure(bundle.role_keys.report, key_material["rsa"].public)
    with pytest.raises(ValueError, match="Ed25519"):
        _verify(bundle)
