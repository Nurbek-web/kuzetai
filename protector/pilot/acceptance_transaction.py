"""One process-local lock for multi-capability acceptance C2 transactions."""

from __future__ import annotations

import threading


C2_CAPABILITY_TRANSACTION_LOCK = threading.RLock()


__all__ = ("C2_CAPABILITY_TRANSACTION_LOCK",)
