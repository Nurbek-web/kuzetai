"""Production event, evidence, and preview composition for the shared runtime."""

from __future__ import annotations

import math
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from protector.pilot.config import SiteConfig
from protector.pilot.domain import (
    CandidateEventV1,
    RuntimeWriterReceiptV1,
)
from protector.pilot.gates import site_config_sha256
from protector.pilot.rules import (
    CompiledCameraRuleV1,
    LineRuleSpecV1,
    ModuleRuleSpecV1,
    ZoneRuleSpecV1,
)
from protector.pilot.runtime.camera_epoch_fence import (
    CameraEpochFencedEventService,
)
from protector.pilot.runtime.event_engine import EvidencePolicy, SiteEventService
from protector.pilot.runtime.event_router import CameraRuleEventRouter
from protector.pilot.runtime.event_worker import EventProcessingWorker
from protector.pilot.runtime.evidence import (
    EncodedFragmentRing,
    SplitMuxEvidenceSinkFactory,
)
from protector.pilot.runtime.operational_source_authority import (
    OperationalNativeSourceAuthority,
)
from protector.pilot.runtime.provenance import (
    ProvenanceRuleBinding,
    RuntimeCandidateAuthority,
    RuntimeJournalProcessor,
)
from protector.pilot.storage.journal import SQLiteWALJournal
from protector.pilot.storage.object_store import (
    EvidenceDeliveryServices,
    build_s3_evidence_delivery,
)
from protector.pilot.storage.preview import (
    DurablePreviewEvidenceCoordinator,
    DurablePreviewPublisher,
    PreviewObjectContext,
    S3PreviewObjectStore,
)

_MAX_PREVIEW_BYTES = 16 * 1024 * 1024
_MAX_EVENT_BATCH = 64
_MAX_EVENT_CAMERAS = 20
_LIVE_METADATA_PRODUCERS = frozenset({"person"})


class ProductionEventCompositionError(RuntimeError):
    """Reviewed production event dependencies are absent or inconsistent."""


class _ProductionRepository(Protocol):
    def get_event(
        self,
        event_id: UUID,
        *,
        expected_site_id: str | None = None,
    ) -> CandidateEventV1: ...

    def mark_candidate_evidence_pending(
        self,
        event_id: UUID,
    ) -> CandidateEventV1: ...

    def mark_candidate_evidence_failed(
        self,
        event_id: UUID,
    ) -> CandidateEventV1: ...

    def activate_camera_epoch(self, **kwargs: Any) -> object: ...

    def store_provenanced_event(self, *args: Any, **kwargs: Any) -> object: ...

    def persist_journal_item(self, item: object) -> None: ...

    def prepare_preview_publication(self, **kwargs: Any) -> object: ...

    def finalize_preview_receipt(self, **kwargs: Any) -> None: ...


class _ObservationSource(Protocol):
    def drain_event_batch(self, *, max_items: int) -> Any: ...

    def drain_observations(self, *, max_items: int) -> list[Any]: ...

    def event_cursors(self) -> tuple[Any, ...]: ...


@dataclass(frozen=True, slots=True)
class ProductionEventDependencies:
    """Components injected into the target graph before it starts."""

    evidence_sink_factory: SplitMuxEvidenceSinkFactory
    native_source_authority: OperationalNativeSourceAuthority


class ProductionEventPipeline:
    """Own the off-callback event worker and all local durable event resources."""

    __slots__ = (
        "_closed",
        "_lock",
        "_worker",
        "_worker_limits",
        "authority",
        "dependencies",
        "delivery",
        "event_service",
        "journal",
        "preview_store",
        "router",
    )

    def __init__(
        self,
        *,
        dependencies: ProductionEventDependencies,
        router: CameraRuleEventRouter,
        authority: RuntimeCandidateAuthority,
        event_service: CameraEpochFencedEventService,
        journal: SQLiteWALJournal,
        delivery: EvidenceDeliveryServices,
        preview_store: S3PreviewObjectStore,
        worker_batch_size: int,
        worker_shutdown_batches: int,
    ) -> None:
        self.dependencies = dependencies
        self.router = router
        self.authority = authority
        self.event_service = event_service
        self.journal = journal
        self.delivery = delivery
        self.preview_store = preview_store
        self._worker_limits = (
            worker_batch_size,
            worker_shutdown_batches,
        )
        self._worker: EventProcessingWorker | None = None
        self._closed = False
        self._lock = threading.RLock()

    def bind_observation_source(
        self,
        source: _ObservationSource,
    ) -> EventProcessingWorker:
        """Bind exactly one shared metadata source to the off-callback worker."""

        with self._lock:
            if self._closed:
                raise ProductionEventCompositionError(
                    "production event pipeline is closed"
                )
            if self._worker is not None:
                raise ProductionEventCompositionError(
                    "production observation source was already bound"
                )
            if (
                not callable(getattr(source, "drain_event_batch", None))
                or not callable(
                    getattr(source, "drain_observations", None)
                )
                or not callable(getattr(source, "event_cursors", None))
            ):
                raise TypeError("production observation source is invalid")
            batch_size, shutdown_batches = self._worker_limits
            worker = EventProcessingWorker(
                source=source,
                service=self.event_service,
                batch_size=batch_size,
                poll_interval_seconds=0.05,
                shutdown_drain_batches=shutdown_batches,
                join_timeout_seconds=10.0,
                cursor_limit=_MAX_EVENT_CAMERAS,
            )
            self._worker = worker
            return worker

    @property
    def worker(self) -> EventProcessingWorker:
        with self._lock:
            if self._worker is None:
                raise ProductionEventCompositionError(
                    "production observation source is not bound"
                )
            return self._worker

    def close(self) -> None:
        """Close only after graph quiescence and the worker's finite drain."""

        with self._lock:
            if self._closed:
                return
            worker = self._worker
        terminal_failure: BaseException | None = None
        if worker is not None:
            try:
                worker.stop()
            except BaseException as exc:
                # The worker can still own journal/repository operations after
                # a bounded stop timeout. Retain every downstream resource so
                # the exact worker can be stopped and drained again.
                raise ProductionEventCompositionError(
                    "production event worker did not stop safely"
                ) from exc
            worker_status = worker.status
            if (
                worker_status.failed
                or worker_status.shutdown_drain_exhausted
            ):
                terminal_failure = ProductionEventCompositionError(
                    "production event worker terminated degraded"
                )
        cleanup_failures: list[BaseException] = []
        for action in (
            self.delivery.preview_workspace.close,
            self.journal.close,
        ):
            try:
                action()
            except BaseException as exc:
                cleanup_failures.append(exc)
        if cleanup_failures:
            failures = (
                cleanup_failures
                if terminal_failure is None
                else [terminal_failure, *cleanup_failures]
            )
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup(
                "production event pipeline cleanup failed",
                failures,
            )
        with self._lock:
            self._closed = True
        if terminal_failure is not None:
            raise terminal_failure


def build_production_event_pipeline(
    *,
    site_id: str,
    site: SiteConfig,
    compiled_rules: tuple[CompiledCameraRuleV1, ...],
    writer_receipt: RuntimeWriterReceiptV1,
    repository: _ProductionRepository,
    evidence_client: Any,
    preview_client: Any,
    journal_path: Path,
    preview_workspace_root: Path,
    preview_context_factory: Callable[[Any, Any], PreviewObjectContext],
    clock: Callable[[], datetime],
    max_nvenc_jobs: int = 1,
) -> ProductionEventPipeline:
    """Compose reviewed CPU/storage contracts; no hardware success is inferred."""

    (
        _active_rules,
        evidence_seconds,
        bindings,
    ) = _validate_runtime_rules(
        site_id=site_id,
        compiled_rules=compiled_rules,
        writer_receipt=writer_receipt,
    )
    if type(site) is not SiteConfig or not callable(clock):
        raise ProductionEventCompositionError(
            "production site configuration or clock is invalid"
        )
    if site_config_sha256(site) != writer_receipt.site_config_sha256:
        raise ProductionEventCompositionError(
            "production site configuration does not match writer authority"
        )
    if (
        site.storage.evidence_prefix.split("/")[-1] != site_id
        or len(site.ready_to_start.feeds) != _MAX_EVENT_CAMERAS
    ):
        raise ProductionEventCompositionError(
            "production site storage or camera scope is invalid"
        )
    if (
        type(journal_path) is not Path
        or type(preview_workspace_root) is not Path
        or not journal_path.is_absolute()
        or not preview_workspace_root.is_absolute()
        or journal_path == Path(journal_path.anchor)
        or preview_workspace_root == Path(preview_workspace_root.anchor)
        or journal_path == preview_workspace_root
    ):
        raise ProductionEventCompositionError(
            "production event paths must be separate absolute namespaces"
        )
    if not callable(preview_context_factory):
        raise ProductionEventCompositionError(
            "production preview context authority is invalid"
        )
    retention = site.storage.retention
    spool_root = retention.encoded_spool_root
    namespaces = (
        spool_root,
        preview_workspace_root,
        journal_path.parent,
    )
    if any(
        left == right
        or left.is_relative_to(right)
        or right.is_relative_to(left)
        for index, left in enumerate(namespaces)
        for right in namespaces[index + 1 :]
    ):
        raise ProductionEventCompositionError(
            "production spool, preview, and journal namespaces must not overlap"
        )
    if (
        type(max_nvenc_jobs) is not int
        or isinstance(max_nvenc_jobs, bool)
        or not 1 <= max_nvenc_jobs <= 4
    ):
        raise ProductionEventCompositionError(
            "production NVENC concurrency must be between one and four"
        )
    try:
        now = clock()
    except BaseException as exc:
        raise ProductionEventCompositionError(
            "production event clock is unavailable"
        ) from exc
    if (
        type(now) is not datetime
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ProductionEventCompositionError(
            "production event clock must be timezone aware"
        )

    ring = EncodedFragmentRing(
        spool_root,
        ring_seconds=retention.encoded_ring_buffer_seconds,
        max_camera_bytes=retention.encoded_ring_max_camera_bytes,
        max_spool_bytes=retention.encoded_ring_max_spool_bytes,
        clock=clock,
    )
    evidence_sink_factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=retention.encoded_fragment_seconds,
        max_fragment_bytes=retention.encoded_fragment_max_bytes,
    )
    journal = SQLiteWALJournal(
        journal_path,
        max_items=site.queues.events,
    )
    processor = RuntimeJournalProcessor(
        repository=repository,
        writer_receipt=writer_receipt,
    )
    delivery: EvidenceDeliveryServices | None = None
    try:
        delivery = build_s3_evidence_delivery(
            site=site,
            client=evidence_client,
            repository=repository,  # type: ignore[arg-type]
            journal=journal,
            ring=ring,
            max_nvenc_jobs=max_nvenc_jobs,
            preview_workspace_root=preview_workspace_root,
            preview_max_items=min(64, site.queues.events),
            preview_max_bytes=site.storage.max_evidence_object_bytes * 2,
            journal_processor=processor,
        )
        preview_store = S3PreviewObjectStore(
            client=preview_client,
            endpoint=str(site.storage.endpoint),
            bucket=site.storage.bucket,
            country_code=site.storage.country_code,
            preview_prefix=f"{site.storage.evidence_prefix}/previews",
            max_preview_bytes=min(
                _MAX_PREVIEW_BYTES,
                site.storage.max_evidence_object_bytes,
            ),
            server_side_encryption=site.storage.server_side_encryption,
            kms_key_id=site.storage.kms_key_id,
        )
        preview_store.attest_bounded_lifecycle(
            retention_days=retention.evidence_retention_days,
        )
        preview_publisher = DurablePreviewPublisher(
            store=preview_store,
            repository=repository,  # type: ignore[arg-type]
            clock=clock,
            storage_policy_check=(
                lambda: preview_store.attest_bounded_lifecycle(
                    retention_days=retention.evidence_retention_days,
                )
            ),
        )
        preview_coordinator = DurablePreviewEvidenceCoordinator(
            delegate=delivery.coordinator,
            publisher=preview_publisher,
            context_factory=preview_context_factory,
        )
        router = CameraRuleEventRouter.from_compiled_rules(
            rules=compiled_rules,
        )
        authority = RuntimeCandidateAuthority(
            writer_receipt=writer_receipt,
            rule_bindings=bindings,
        )
        pre_roll_seconds = min(2.0, evidence_seconds / 2.0)
        evidence_policy = EvidencePolicy(
            pre_roll_seconds=pre_roll_seconds,
            post_roll_seconds=evidence_seconds - pre_roll_seconds,
            source_references={
                feed.camera_id: f"nvr://{site_id}/{feed.camera_id}"
                for feed in site.ready_to_start.feeds
            },
        )
        service = SiteEventService(
            engine=router,  # type: ignore[arg-type]
            journal=journal,
            replay_worker=delivery.replay_worker,
            ring=ring,
            evidence_coordinator=preview_coordinator,
            load_candidate=lambda event_id: repository.get_event(
                event_id,
                expected_site_id=site_id,
            ),
            mark_evidence_pending=(
                repository.mark_candidate_evidence_pending
            ),
            mark_evidence_failed=repository.mark_candidate_evidence_failed,
            evidence_policy=evidence_policy,
            candidate_envelope_factory=authority.build_envelope,
        )
        fenced_service = CameraEpochFencedEventService(
            delegate=service,
            repository=repository,
            authority=authority,
            event_camera_ids=router.camera_ids,
            clock=clock,
        )
        batch_size = min(_MAX_EVENT_BATCH, site.queues.events)
        shutdown_batches = math.ceil(site.queues.events / batch_size) + 1
        return ProductionEventPipeline(
            dependencies=ProductionEventDependencies(
                evidence_sink_factory=evidence_sink_factory,
                native_source_authority=(
                    OperationalNativeSourceAuthority.from_site(site)
                ),
            ),
            router=router,
            authority=authority,
            event_service=fenced_service,
            journal=journal,
            delivery=delivery,
            preview_store=preview_store,
            worker_batch_size=batch_size,
            worker_shutdown_batches=shutdown_batches,
        )
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        if delivery is not None:
            try:
                delivery.preview_workspace.close()
            except BaseException as cleanup:
                failures.append(cleanup)
        try:
            journal.close()
        except BaseException as cleanup:
            failures.append(cleanup)
        if len(failures) == 1:
            raise
        raise BaseExceptionGroup(
            "production event composition and cleanup failed",
            failures,
        ) from primary


def _validate_runtime_rules(
    *,
    site_id: str,
    compiled_rules: tuple[CompiledCameraRuleV1, ...],
    writer_receipt: RuntimeWriterReceiptV1,
) -> tuple[
    tuple[CompiledCameraRuleV1, ...],
    int,
    tuple[ProvenanceRuleBinding, ...],
]:
    if (
        type(writer_receipt) is not RuntimeWriterReceiptV1
        or writer_receipt.site_id != site_id
        or type(compiled_rules) is not tuple
        or not 1 <= len(compiled_rules) <= 512
        or any(type(rule) is not CompiledCameraRuleV1 for rule in compiled_rules)
    ):
        raise ProductionEventCompositionError(
            "runtime writer and compiled rules are invalid"
        )
    active = tuple(
        rule
        for rule in compiled_rules
        if rule.enabled and rule.gate_mode in {"shadow", "operator"}
    )
    if not active:
        raise ProductionEventCompositionError(
            "production runtime has no enabled reviewed event rule"
        )
    if any(
        (
            rule.spec.source_module
            if isinstance(rule.spec, ModuleRuleSpecV1)
            else (
                "person"
                if isinstance(
                    rule.spec,
                    (ZoneRuleSpecV1, LineRuleSpecV1),
                )
                else None
            )
        )
        not in _LIVE_METADATA_PRODUCERS
        for rule in active
    ):
        raise ProductionEventCompositionError(
            "enabled production rule has no live metadata producer"
        )
    if (
        any(rule.site_id != site_id for rule in compiled_rules)
        or len({rule.rule_id for rule in compiled_rules})
        != len(compiled_rules)
        or any(
            writer_receipt.rule_revision_sha256(rule.rule_id)
            != rule.rule_revision_sha256
            for rule in compiled_rules
        )
    ):
        raise ProductionEventCompositionError(
            "compiled event rules differ from runtime writer authority"
        )
    evidence_windows = {rule.evidence_seconds for rule in active}
    if len(evidence_windows) != 1:
        raise ProductionEventCompositionError(
            "enabled production rules require one reviewed evidence window"
        )
    evidence_seconds = evidence_windows.pop()
    return (
        active,
        evidence_seconds,
        tuple(
            ProvenanceRuleBinding(
                rule_id=rule.rule_id,
                revision=rule.revision,
                rule_revision_sha256=rule.rule_revision_sha256,
                camera_id=rule.camera_id,
                module=rule.module,
                model_artifact_id=rule.model_artifact_id,
                model_gate_decision_sha256=(
                    rule.model_decision_sha256
                ),
                gate_mode=rule.gate_mode,
            )
            for rule in active
        ),
    )


__all__ = (
    "ProductionEventCompositionError",
    "ProductionEventDependencies",
    "ProductionEventPipeline",
    "build_production_event_pipeline",
)
