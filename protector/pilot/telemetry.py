"""Authenticated, bounded telemetry publishers for isolated pilot processes."""

from __future__ import annotations

import json
import math
import os
import queue
import shutil
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from protector.pilot.runtime.supervisor import CameraHealth

ComponentState = Literal["healthy", "degraded", "failed"]
_MAX_RESPONSE_BYTES = 4_096
_MAX_TOKEN_BYTES = 16 * 1024


class TelemetryPublishError(RuntimeError):
    """A bounded machine telemetry request was not accepted."""


class TelemetryClient(Protocol):
    def post(self, path: str, payload: dict[str, object]) -> None: ...


class AuthenticatedTelemetryClient:
    """Post small JSON envelopes without exposing the bearer credential."""

    def __init__(
        self,
        *,
        base_url: str,
        machine_token: str,
        timeout_seconds: float = 2.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.hostname != "api"
            or parsed.port != 8000
        ):
            raise ValueError("telemetry base URL must be the reviewed internal API origin")
        if parsed.path not in {"", "/"}:
            raise ValueError("telemetry base URL must not contain a path")
        if len(machine_token) < 16 or len(machine_token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            raise ValueError("machine token must contain 16 to 16384 encoded bytes")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("telemetry timeout must be between 0 and 30 seconds")
        self._base_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "", "", "")
        )
        self._machine_token = machine_token
        self._timeout_seconds = timeout_seconds
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args: object, **_kwargs: object) -> None:
                return None

        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(base_url={self._base_url!r}, "
            f"timeout_seconds={self._timeout_seconds!r})"
        )

    def post(self, path: str, payload: dict[str, object]) -> None:
        if not path.startswith("/api/internal/") or "//" in path:
            raise ValueError("telemetry path must be a fixed internal API path")
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._machine_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                encoded = response.read(_MAX_RESPONSE_BYTES + 1)
                final = urllib.parse.urlsplit(response.geturl())
                if (
                    not 200 <= response.status < 300
                    or len(encoded) > _MAX_RESPONSE_BYTES
                    or (final.scheme, final.hostname, final.port or 80)
                    != ("http", "api", 8000)
                ):
                    raise TelemetryPublishError("telemetry endpoint rejected the request")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise TelemetryPublishError("telemetry publication failed") from exc


def read_machine_token(path: str | Path) -> str:
    """Read one regular, non-linked Docker secret with a fixed upper bound."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(Path(path), flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_TOKEN_BYTES:
            raise TelemetryPublishError("machine credential is unavailable")
        payload = os.read(descriptor, _MAX_TOKEN_BYTES + 1)
    except OSError as exc:
        raise TelemetryPublishError("machine credential is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        token = payload.decode("utf-8").strip()
    except UnicodeError as exc:
        raise TelemetryPublishError("machine credential is unavailable") from exc
    if len(token) < 16:
        raise TelemetryPublishError("machine credential is unavailable")
    return token


class RuntimeTelemetryPublisher:
    """Publish source health plus shared-runtime metrics under one session epoch."""

    def __init__(
        self,
        *,
        client: TelemetryClient,
        runtime_session_id: str,
        publisher_generation: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not runtime_session_id or len(runtime_session_id) > 128:
            raise ValueError("runtime session identity must be non-empty and bounded")
        if not callable(getattr(client, "post", None)):
            raise ValueError("telemetry client must provide post")
        if clock is not None and not callable(clock):
            raise ValueError("telemetry clock must be callable")
        generation = time.time_ns() if publisher_generation is None else publisher_generation
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= 9_223_372_036_854_775_807
        ):
            raise ValueError("runtime publisher generation is invalid")
        self._client = client
        self.runtime_session_id = runtime_session_id
        self.publisher_generation = generation
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sequence = 0

    def publish(
        self,
        health: Sequence[CameraHealth],
        *,
        analytics_state: ComponentState,
        evidence_state: ComponentState,
        extra_runtime_metrics: Mapping[str, object] | None = None,
    ) -> None:
        rows = tuple(health)
        camera_ids = [row.camera_id for row in rows]
        if len(rows) != 20 or len(set(camera_ids)) != 20:
            raise ValueError("runtime telemetry requires exactly 20 unique camera samples")
        if analytics_state not in {"healthy", "degraded", "failed"}:
            raise ValueError("analytics state is invalid")
        if evidence_state not in {"healthy", "degraded", "failed"}:
            raise ValueError("evidence state is invalid")
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("telemetry clock must return UTC-aware time")
        observed_at = observed_at.astimezone(UTC)
        timestamp = observed_at.isoformat()
        health_payload = [
            {
                "camera_id": row.camera_id,
                "runtime_session_id": self.runtime_session_id,
                "observed_at": timestamp,
                "state": row.state,
                "last_frame_at": (
                    row.last_frame_at.astimezone(UTC).isoformat()
                    if row.last_frame_at is not None
                    else None
                ),
                "reconnect_count": row.reconnect_count,
                "dropped_samples": row.dropped_samples,
                "degraded_reason": row.degraded_reason,
            }
            for row in rows
        ]
        next_sequence = self._sequence + 1
        envelope: dict[str, object] = {
            "publisher": "runtime",
            "runtime_session_id": self.runtime_session_id,
            "publisher_generation": self.publisher_generation,
            "sequence": next_sequence,
            "observed_at": timestamp,
            "components": [
                {"name": "analytics", "state": analytics_state},
                {"name": "evidence", "state": evidence_state},
            ],
            "health": health_payload,
            "samples": [
                {
                    "camera_id": row.camera_id,
                    "module": "person",
                    "scheduled_total": row.scheduled_samples,
                    "processed_total": max(0, row.scheduled_samples - row.dropped_samples),
                    "dropped_total": row.dropped_samples,
                }
                for row in rows
            ],
        }
        queue_ages = [
            row.queue_age_seconds
            for row in rows
            if row.queue_age_seconds is not None
        ]
        if queue_ages:
            envelope["queues"] = [
                {"name": "analytics", "age_seconds": max(queue_ages)}
            ]
        if extra_runtime_metrics is not None:
            allowed = {
                "model_latencies",
                "candidate_totals",
                "evidence_results",
                "evidence_latencies_seconds",
                "gpu",
                "disk",
            }
            if set(extra_runtime_metrics) - allowed:
                raise ValueError("runtime metric extension contains unsupported fields")
            envelope.update(extra_runtime_metrics)
        self._client.post("/api/internal/telemetry", envelope)
        self._sequence = next_sequence


class NotificationTelemetryPublisher:
    """Publish cumulative delivery outcomes under one worker session epoch."""

    def __init__(
        self,
        *,
        client: TelemetryClient,
        worker_session_id: str,
        publisher_generation: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_session_id or len(worker_session_id) > 128:
            raise ValueError("notification worker session identity is invalid")
        if not callable(getattr(client, "post", None)):
            raise ValueError("telemetry client must provide post")
        if clock is not None and not callable(clock):
            raise ValueError("telemetry clock must be callable")
        generation = time.time_ns() if publisher_generation is None else publisher_generation
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= 9_223_372_036_854_775_807
        ):
            raise ValueError("notification publisher generation is invalid")
        self._client = client
        self.worker_session_id = worker_session_id
        self.publisher_generation = generation
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sequence = 0
        self._previous = {
            "attempted": 0,
            "delivered": 0,
            "failed": 0,
            "dead_letter": 0,
        }

    def publish(
        self,
        *,
        state: ComponentState,
        attempted: int,
        delivered: int,
        failed: int,
        dead_letter: int,
    ) -> None:
        totals = {
            "attempted": attempted,
            "delivered": delivered,
            "failed": failed,
            "dead_letter": dead_letter,
        }
        if state not in {"healthy", "degraded", "failed"}:
            raise ValueError("notification component state is invalid")
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < self._previous[result]
            for result, value in totals.items()
        ):
            raise ValueError("notification result counters must be cumulative")
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("telemetry clock must return UTC-aware time")
        next_sequence = self._sequence + 1
        self._client.post(
            "/api/internal/telemetry",
            {
                "publisher": "notifications",
                "runtime_session_id": self.worker_session_id,
                "publisher_generation": self.publisher_generation,
                "sequence": next_sequence,
                "observed_at": observed_at.astimezone(UTC).isoformat(),
                "components": [{"name": "notifications", "state": state}],
                "notification_results": [
                    {"result": result, "total": value}
                    for result, value in totals.items()
                ],
            },
        )
        self._sequence = next_sequence
        self._previous = totals


@dataclass(frozen=True, slots=True)
class _RuntimeSnapshot:
    health: tuple[CameraHealth, ...]
    analytics_state: ComponentState
    evidence_state: ComponentState
    extra_runtime_metrics: Mapping[str, object] | None


class AsyncRuntimeTelemetryPublisher:
    """Keep synchronous control-plane I/O off the DeepStream main loop."""

    def __init__(
        self,
        *,
        publisher: RuntimeTelemetryPublisher,
        extra_metrics_provider: Callable[[], Mapping[str, object]] | None = None,
        shutdown_timeout_seconds: float = 5.0,
    ) -> None:
        if not callable(getattr(publisher, "publish", None)):
            raise ValueError("runtime telemetry publisher is invalid")
        if extra_metrics_provider is not None and not callable(extra_metrics_provider):
            raise ValueError("runtime metrics provider must be callable")
        if not 0 < shutdown_timeout_seconds <= 10:
            raise ValueError("telemetry shutdown timeout must be between 0 and 10 seconds")
        self._publisher = publisher
        self._extra_metrics_provider = extra_metrics_provider
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._queue: queue.Queue[_RuntimeSnapshot | None] = queue.Queue(maxsize=1)
        self._closed = threading.Event()
        self._failures = 0
        self._thread = threading.Thread(
            target=self._run,
            name="kuzet-runtime-telemetry",
            daemon=True,
        )
        self._thread.start()

    @property
    def failures(self) -> int:
        return self._failures

    @property
    def worker_alive(self) -> bool:
        return self._thread.is_alive()

    def enqueue(
        self,
        health: Sequence[CameraHealth],
        *,
        analytics_state: ComponentState,
        evidence_state: ComponentState,
        extra_runtime_metrics: Mapping[str, object] | None = None,
    ) -> None:
        if self._closed.is_set():
            return
        snapshot = _RuntimeSnapshot(
            health=tuple(health),
            analytics_state=analytics_state,
            evidence_state=evidence_state,
            extra_runtime_metrics=(
                deepcopy(dict(extra_runtime_metrics))
                if extra_runtime_metrics is not None
                else None
            ),
        )
        try:
            self._queue.put_nowait(snapshot)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(snapshot)
            except queue.Full:
                pass

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
        self._thread.join(timeout=self._shutdown_timeout_seconds)
        if self._thread.is_alive():
            raise TelemetryPublishError(
                "runtime telemetry worker exceeded its finite shutdown bound"
            )

    def _run(self) -> None:
        while True:
            snapshot = self._queue.get()
            if snapshot is None:
                return
            try:
                probe_failed = False
                try:
                    probed = (
                        dict(self._extra_metrics_provider())
                        if self._extra_metrics_provider is not None
                        else {}
                    )
                except BaseException as exc:
                    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                        raise
                    probe_failed = True
                    probed = {}
                if snapshot.extra_runtime_metrics is not None:
                    probed.update(snapshot.extra_runtime_metrics)
                self._publisher.publish(
                    snapshot.health,
                    analytics_state=(
                        "failed" if probe_failed else snapshot.analytics_state
                    ),
                    evidence_state=(
                        "failed" if probe_failed else snapshot.evidence_state
                    ),
                    extra_runtime_metrics=probed or None,
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                self._failures += 1


class TargetResourceMetricsProvider:
    """Measure target GPU/VRAM and the actual evidence-spool filesystem."""

    def __init__(
        self,
        *,
        spool_root: str | Path,
        command_runner: Callable[..., object] = subprocess.run,
        disk_usage: Callable[[Path], tuple[int, int, int]] = shutil.disk_usage,
    ) -> None:
        root = Path(spool_root)
        if not root.is_absolute():
            raise ValueError("spool root must be absolute")
        if not callable(command_runner) or not callable(disk_usage):
            raise ValueError("resource probes must be callable")
        self._spool_root = root
        self._command_runner = command_runner
        self._disk_usage = disk_usage

    def __call__(self) -> Mapping[str, object]:
        result = self._command_runner(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        output = getattr(result, "stdout", "")
        lines = output.strip().splitlines() if isinstance(output, str) else []
        if len(lines) != 1:
            raise TelemetryPublishError("target GPU resource probe failed")
        fields = [field.strip() for field in lines[0].split(",")]
        if len(fields) != 3:
            raise TelemetryPublishError("target GPU resource probe failed")
        try:
            utilization, used_mib, capacity_mib = (float(field) for field in fields)
        except ValueError as exc:
            raise TelemetryPublishError("target GPU resource probe failed") from exc
        if (
            not all(math.isfinite(value) for value in (utilization, used_mib, capacity_mib))
            or not 0 <= utilization <= 100
            or used_mib < 0
            or capacity_mib <= 0
            or used_mib > capacity_mib
        ):
            raise TelemetryPublishError("target GPU resource probe failed")
        total, used, _free = self._disk_usage(self._spool_root)
        if (
            isinstance(total, bool)
            or isinstance(used, bool)
            or not isinstance(total, int)
            or not isinstance(used, int)
            or total <= 0
            or not 0 <= used <= total
        ):
            raise TelemetryPublishError("target disk resource probe failed")
        return {
            "gpu": {
                "utilization_percent": utilization,
                "vram_used_bytes": int(used_mib * 1024 * 1024),
                "vram_capacity_bytes": int(capacity_mib * 1024 * 1024),
            },
            "disk": {"used_bytes": used, "capacity_bytes": total},
        }
