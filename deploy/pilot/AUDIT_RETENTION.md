# Audit archive primary-storage boundary

Old append-only audit rows are first written to one content-addressed,
age-encrypted archive with an asymmetrically signed canonical receipt. The
receipt-bound PostgreSQL function validates every staging row's site,
timestamp, and cutoff, deletes only those audit rows, then transactionally
compacts the per-audit staging rows. A failed transaction leaves the receipt
pending and all staging rows available for an exact retry.

The durable receipt is the minimum local verification root and idempotency
record. It is deliberately not deleted: one bounded receipt remains per
content-addressed archive. Database checks limit each receipt to 10,000
archived rows, a 16 KiB detached signature, and a 16 KiB canonical signed
receipt. The object key and signing identity are bounded columns. The
production Compose service runs one singleton batch per hour and requests the
maximum 10,000 rows, so it can create at most 24 of these bounded roots per
day while removing up to 240,000 per-audit primary rows. Evidence retention
uses its separate 1,000-row batch bound on that same hourly singleton cadence;
registered preview retirement and orphan-version reconciliation each use a
separate 1,000-row/version bound. The larger audit batch is never passed to an
evidence or preview coordinator.

This is an explicit growth policy, not a zero-growth claim. Receipt roots are
irreducible compliance evidence and must be included in database capacity and
backup planning. Changing the hourly cadence, batch size, receipt limits, or
deleting/aggregating roots requires a separately reviewed migration and an
external archive proof that preserves per-archive verification and repeat
idempotency. Ordinary API and retention roles cannot update/delete receipts,
delete staging items, or access the transaction-scoped authorization tables.
Target acceptance must measure eligible arrival rate, each independent drain
rate, backlog depth, and oldest eligible age before and after a
configured-batch-plus-one fixture and over the soak. A finite batch alone is
not proof of bounded steady state; any growing backlog, drain capacity below
the measured arrival envelope, or unbounded oldest age blocks the pilot.
