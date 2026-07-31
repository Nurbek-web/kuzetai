"""Bounded YAML parsing for reviewed, security-sensitive configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml
from yaml.events import AliasEvent, NodeEvent
from yaml.nodes import MappingNode, ScalarNode

_MAX_ALLOWED_BYTES = 16 * 1024 * 1024
_MAX_ALLOWED_NODES = 100_000
_MAX_ALLOWED_DEPTH = 128
_YAML_STRING_TAG = "tag:yaml.org,2002:str"
_YAML_MERGE_TAG = "tag:yaml.org,2002:merge"


class StrictYAMLError(ValueError):
    """Reviewed YAML violated a deterministic syntax or resource bound."""


def _bounded_integer(
    value: int,
    *,
    label: str,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= maximum
    ):
        raise ValueError(f"{label} must be an integer between 1 and {maximum}")
    return value


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader with composition-time resource and reference controls."""

    def __init__(
        self,
        stream: str,
        *,
        max_nodes: int,
        max_depth: int,
    ) -> None:
        super().__init__(stream)
        self._strict_max_nodes = max_nodes
        self._strict_max_depth = max_depth
        self._strict_node_count = 0
        self._strict_depth = 0

    def compose_node(
        self,
        parent: Any,
        index: Any,
    ) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent):
            raise StrictYAMLError("YAML aliases are not allowed")
        if isinstance(event, NodeEvent):
            if event.anchor is not None:
                raise StrictYAMLError("YAML anchors are not allowed")
            if event.tag is not None:
                raise StrictYAMLError("explicit YAML tags are not allowed")

        self._strict_node_count += 1
        if self._strict_node_count > self._strict_max_nodes:
            raise StrictYAMLError("YAML node limit exceeded")
        self._strict_depth += 1
        if self._strict_depth > self._strict_max_depth:
            self._strict_depth -= 1
            raise StrictYAMLError("YAML depth limit exceeded")
        try:
            return super().compose_node(parent, index)
        finally:
            self._strict_depth -= 1

    def construct_mapping(
        self,
        node: MappingNode,
        deep: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(node, MappingNode):
            raise StrictYAMLError("YAML mapping node is invalid")
        seen: set[str] = set()
        for key_node, _ in node.value:
            if (
                not isinstance(key_node, ScalarNode)
                or key_node.tag != _YAML_STRING_TAG
            ):
                if (
                    isinstance(key_node, ScalarNode)
                    and (
                        key_node.tag == _YAML_MERGE_TAG
                        or key_node.value == "<<"
                    )
                ):
                    raise StrictYAMLError("YAML merge keys are not allowed")
                raise StrictYAMLError("YAML mapping keys must be strings")
            key = key_node.value
            if key == "<<":
                raise StrictYAMLError("YAML merge keys are not allowed")
            if key in seen:
                raise StrictYAMLError(f"duplicate YAML mapping key: {key}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_strict_yaml(
    payload: bytes | str,
    *,
    max_bytes: int,
    max_nodes: int,
    max_depth: int,
    require_mapping: bool = False,
) -> Any:
    """Parse one YAML document under explicit, finite trust boundaries."""

    byte_limit = _bounded_integer(
        max_bytes,
        label="max_bytes",
        maximum=_MAX_ALLOWED_BYTES,
    )
    node_limit = _bounded_integer(
        max_nodes,
        label="max_nodes",
        maximum=_MAX_ALLOWED_NODES,
    )
    depth_limit = _bounded_integer(
        max_depth,
        label="max_depth",
        maximum=_MAX_ALLOWED_DEPTH,
    )
    if not isinstance(require_mapping, bool):
        raise TypeError("require_mapping must be a boolean")

    if isinstance(payload, bytes):
        encoded = payload
        try:
            document = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictYAMLError("YAML input must be valid UTF-8") from exc
    elif isinstance(payload, str):
        document = payload
        try:
            encoded = payload.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise StrictYAMLError("YAML input must be valid UTF-8") from exc
    else:
        raise TypeError("YAML input must be bytes or text")
    if len(encoded) > byte_limit:
        raise StrictYAMLError("YAML byte limit exceeded")
    if "\x00" in document:
        raise StrictYAMLError("YAML input must not contain NUL")

    loader = _StrictSafeLoader(
        document,
        max_nodes=node_limit,
        max_depth=depth_limit,
    )
    try:
        result = loader.get_single_data()
    except StrictYAMLError:
        raise
    except yaml.YAMLError as exc:
        raise StrictYAMLError("YAML syntax is invalid") from exc
    finally:
        loader.dispose()
    if require_mapping and not isinstance(result, Mapping):
        raise StrictYAMLError("YAML document root must be a mapping")
    return result
