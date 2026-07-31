from __future__ import annotations

from collections import OrderedDict
from threading import RLock
from types import SimpleNamespace

from protector.pilot.runtime.event_engine import SiteEventService


class _FailingPendingDepthJournal:
    def pending_evidence_quarantine_depth(self) -> int:
        return 0

    def depth(self) -> int:
        return 0

    def pending_evidence_work_depth(self) -> int:
        raise RuntimeError("database secret must never escape")


def test_pending_evidence_depth_failure_is_visible_in_its_first_status_snapshot() -> None:
    service = object.__new__(SiteEventService)
    service._replay_worker = SimpleNamespace(
        status=SimpleNamespace(degraded=False, quarantine_depth=0)
    )
    service._journal = _FailingPendingDepthJournal()
    service._reasons = OrderedDict()
    service._state_lock = RLock()
    service._processing = set()
    service._pending_work = OrderedDict()
    service._pending_recovery_attempts = 0
    service._pending_retry_at = None
    service._monotonic = lambda: 0.0

    status = service.status

    assert status.degraded is True
    assert status.reasons == ("pending_evidence_depth_failed",)
    assert status.pending_evidence_work == -1
    assert "secret" not in repr(status)
