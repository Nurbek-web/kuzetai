from __future__ import annotations

import pytest

from protector.pilot.trusted_yaml import StrictYAMLError, load_strict_yaml


def _load(
    payload: bytes | str,
    *,
    max_bytes: int = 4096,
    max_nodes: int = 128,
    max_depth: int = 16,
    require_mapping: bool = True,
) -> object:
    return load_strict_yaml(
        payload,
        max_bytes=max_bytes,
        max_nodes=max_nodes,
        max_depth=max_depth,
        require_mapping=require_mapping,
    )


def test_strict_yaml_preserves_standard_mapping_values() -> None:
    assert _load(
        b"""
site:
  enabled: true
  retries: 3
  threshold: 0.75
  modules:
    - person
    - fire
"""
    ) == {
        "site": {
            "enabled": True,
            "retries": 3,
            "threshold": 0.75,
            "modules": ["person", "fire"],
        }
    }


def test_strict_yaml_rejects_duplicate_keys_at_any_mapping_depth() -> None:
    with pytest.raises(StrictYAMLError, match="duplicate YAML mapping key: enabled"):
        _load(
            """
site:
  enabled: true
  enabled: false
"""
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        ("defaults: &defaults\n  enabled: true\n", "anchors"),
        (
            "defaults: &defaults\n  enabled: true\nsite: *defaults\n",
            "anchors|aliases",
        ),
        ("site:\n  <<: {enabled: true}\n", "merge keys"),
        ("site: !unsafe-tag value\n", "explicit YAML tags"),
        ("site: !!python/object:builtins.object {}\n", "explicit YAML tags"),
    ),
)
def test_strict_yaml_rejects_references_merges_and_explicit_tags(
    payload: str,
    message: str,
) -> None:
    with pytest.raises(StrictYAMLError, match=message):
        _load(payload)


@pytest.mark.parametrize(
    "payload",
    (
        "1: value\n",
        "true: value\n",
        "? [compound, key]\n: value\n",
    ),
)
def test_strict_yaml_rejects_non_string_mapping_keys(payload: str) -> None:
    with pytest.raises(StrictYAMLError, match="mapping keys must be strings"):
        _load(payload)


@pytest.mark.parametrize("payload", ("- one\n- two\n", "scalar\n", "null\n"))
def test_strict_yaml_can_require_a_mapping_root(payload: str) -> None:
    with pytest.raises(StrictYAMLError, match="root must be a mapping"):
        _load(payload)


def test_strict_yaml_rejects_invalid_utf8_and_nul() -> None:
    with pytest.raises(StrictYAMLError, match="valid UTF-8"):
        _load(b"site: \xff\n")
    with pytest.raises(StrictYAMLError, match="must not contain NUL"):
        _load(b"site: before\x00after\n")


def test_strict_yaml_enforces_byte_node_and_depth_limits() -> None:
    with pytest.raises(StrictYAMLError, match="byte limit exceeded"):
        _load("site: value\n", max_bytes=4)
    with pytest.raises(StrictYAMLError, match="node limit exceeded"):
        _load("a: 1\nb: 2\n", max_nodes=4)
    with pytest.raises(StrictYAMLError, match="depth limit exceeded"):
        _load("a:\n  b:\n    c: value\n", max_depth=3)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("max_bytes", True),
        ("max_nodes", 0),
        ("max_depth", 129),
    ),
)
def test_strict_yaml_rejects_invalid_resource_bounds(
    name: str,
    value: int,
) -> None:
    arguments = {
        "max_bytes": 4096,
        "max_nodes": 128,
        "max_depth": 16,
    }
    arguments[name] = value
    with pytest.raises(ValueError, match=name):
        load_strict_yaml("site: value\n", **arguments)
