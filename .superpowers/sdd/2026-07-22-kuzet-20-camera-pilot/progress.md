# SDD ledger — plan: docs/superpowers/plans/2026-07-22-kuzet-20-camera-pilot.md

## Controller state

- Branch: `codex/kuzet-20-camera-pilot`
- Replacement worktree: `/workspace/scratch/d6f924c72a2b/kuzetai`
- Original controller starting commit: `39173bc`
- Replacement-controller checkpoint:
  `ae18d636c2df333591bc747a855b4e4730ff3267`

## Pre-flight review

- No blocking internal contradiction found between the design and implementation plan.
- NVIDIA/DeepStream/TensorRT engine build, digest validation, real 20-feed replay,
  8-hour load test, and 72-hour acceptance soak require a CUDA/NVIDIA target and
  lawful customer replay corpus. Implement contracts, graph validation, refusal gates,
  tooling, manifests, and reproducible commands locally; record hardware acceptance as
  pending, never fabricate capacity evidence.
- Plan wording that asks to run PostgreSQL or Docker services is conditional on local
  availability. Implement migrations and test portable behavior locally; preserve exact
  target commands for an integration environment if services are unavailable.
- Continuous video remains in the customer NVR; only bounded encoded evidence and
  metadata may be stored.
- All alerts remain candidates until authorised operator confirmation. Shadow/disabled
  analytics must never notify or trigger autonomous actions.
- Face recognition remains excluded from the Day-20 implementation.

## Task status

- Task 1: complete — Freeze configuration and production dependencies
- Task 2: complete — Define domain contracts and model gates
- Task 3: complete locally; live PostgreSQL gate pending — Add PostgreSQL persistence and migrations
- Task 4: complete locally; live PostgreSQL gate pending — Build authentication, authorisation, and API shell
- Task 5: complete — Implement fake/replay data plane and camera supervisor
- Task 6: complete locally; NVIDIA/L4 capacity gates pending — Build NVIDIA DeepStream data plane
- Task 7: complete locally; live storage/NVIDIA/browser gates pending — Add encoded
  evidence rings and clip assembly
- Task 8: complete locally; live integration gates pending — Implement timestamp
  event fusion, zones, loitering, and lines
- Task 9: complete locally; target model/NVIDIA/site gates pending — Build model
  registry, export tools, and conditional gates
- Task 10: complete and independently approved — Build responsive operator
  console
- Task 11: complete locally; independently approved, live PostgreSQL/Telegram
  gates pending — Add reviewed-event notification delivery
- Task 12: complete locally and independently approved; live PostgreSQL,
  Docker/Linux bind-mount, storage, and NVIDIA observability gates pending —
  Add observability, backup/restore, and deployment hardening
- Task 13: complete for the safely implementable cloud scope; exact-20,
  NVIDIA, 8-hour, and 72-hour target acceptance remains pending — Automate
  replay, failure injection, and acceptance reporting
- Task 14: complete for documentation, packaging, and regression protection;
  named training, live integration, and customer sign-off remain pending —
  Handover, operator training, and regression protection

## Historical resumption point

Baseline verification at `39173bc`:

- `uv run pytest tests/ -q` → 62 passed in 58.76s.
- `uv run ruff check protector tests cli.py` → all checks passed.
- `git diff --check` → clean.
- Current controller host reconfirmed during Task 13: Darwin 25.5 arm64;
  `nvidia-smi`, Docker, and `psql` are absent; `ffprobe` is available; project
  runtime is Python 3.12.12 under uv 0.11.16; `uv lock --check --offline`
  resolves 127 packages. CUDA/DeepStream, Compose, live PostgreSQL, and target
  twenty-feed gates therefore remain external rather than silently simulated.

## Task records

- Task 1: implementation commit `2f24978` (`feat(pilot): add validated site configuration`).
- Task 1: initial review found three Important gaps: shallow nested immutability,
  caller-selected Docker-secret root, and missing enforced customer-NVR/bounded-evidence
  storage policy.
- Task 1: fix round 1/5 (3 addressed, 0 open; commits `2f24978..d8094e7`).
- Task 1: fix commit `d8094e7` (`fix(pilot): freeze site configuration boundary`).
- Task 1: scoped re-review clean; no new Critical/Important breakage.
- Task 1: controller verification on `d8094e7`:
  `uv run pytest tests/pilot/test_config.py -q` → 19 passed;
  `uv run ruff check protector/pilot tests/pilot` → all checks passed;
  `git diff --check 2f24978..d8094e7` → clean.
- Task 1: complete (commits `39173bc..d8094e7`, review clean).

- Task 2: implementation commit `4a1f2fb`
  (`feat(pilot): define event contracts and fail-closed model gates`).
- Task 2: initial review found staged-promotion bypass, operational promotion of the
  current violence stack, conflated freshness/health, missing lifecycle provenance,
  and report-auditability/test gaps.
- Task 2: fix round 1/5 (6 addressed, 0 open; commits `4a1f2fb..fe5503b`).
- Task 2: fix commit `fe5503b`
  (`fix(pilot): enforce staged model promotion contracts`).
- Task 2: scoped re-review clean; no new Critical/Important breakage.
- Task 2: controller verification on `fe5503b`:
  `uv run pytest tests/pilot/test_domain.py tests/pilot/test_gates.py -q`
  → 34 passed; `uv run ruff check protector/pilot tests/pilot`
  → all checks passed; `git diff --check 4a1f2fb..fe5503b` → clean.
- Task 2: complete (commits `d8094e7..fe5503b`, review clean).

- Task 3: implementation commit `213570a`
  (`feat(pilot): persist cameras events gates and audit records`).
- Task 3: minor (deferred): migration parity regression test compares table/column
  names but not every type, constraint, index, and trigger; controller/final review
  must triage after Important persistence fixes.
- Task 3: minor (deferred): database SHA-256 checks enforce length but not hexadecimal
  characters; domain models do enforce hexadecimal digests.
- Task 3: initial review opened six Important findings: concurrent idempotency races,
  PostgreSQL trigger SQLSTATE/test mismatch, database lifecycle-provenance bypass,
  decorative evidence journal versions, unbounded evidence time ranges, and incomplete
  idempotency conflict comparisons.

- Task 3: fix round 1/5 (6 addressed, 0 open; commits `213570a..a3c8e34`).
- Task 3: fix commit `a3c8e34`
  (`fix(pilot): harden persistence idempotency and evidence bounds`).
- Task 3: scoped re-review clean; no new Critical/Important breakage.
- Task 3: controller verification on `a3c8e34`:
  focused persistence suite → 29 passed, 1 guarded PostgreSQL-only skip;
  full suite → 144 passed, 1 guarded PostgreSQL-only skip;
  amended-path Ruff → all checks passed; fix-range diff check → clean;
  PostgreSQL offline Alembic DDL compilation → exit 0 using `PostgresqlImpl`.
- Task 3: external gate pending — run the guarded test fixture twice against a
  disposable PostgreSQL 16+ database named `*_test` to verify real row locks,
  psycopg SQLSTATE mapping, PL/pgSQL triggers, and upgrade idempotency. Exact commands
  and fixture requirements are in `task-3-report.md`.
- Task 3: complete (commits `fe5503b..a3c8e34`, review clean; external PostgreSQL
  acceptance pending).

- Task 4: implementation commit `fa68878` (`feat(pilot): add secured operator API`).
- Task 4: minor (deferred): review timestamp was client-controlled and could backdate
  audit history; final review must verify authoritative server time.
- Task 4: minor (deferred): initial API tests omitted several adversarial cases; fix-round
  coverage and final review must triage any residual gaps.
- Task 4: initial review opened five Important findings: replayable/plaintext TOTP,
  non-atomic and IP-rotatable login throttle, incomplete URL/secret redaction,
  non-atomic confirm-plus-outbox creation, and unbounded request/string sizes.

- Task 4: fix round 1/5 (3 addressed, 2 open — legacy plaintext TOTP rows survive
  migration; ordinary `uvicorn --workers 2` bypasses env-only worker guard;
  commits `fa68878..e5b936d`).
- Task 4: fix round 2/5 (1 addressed, 1 open — worker singleton enforced;
  TOTP migration/repository/database envelope validation remains weaker than login
  authentication; commits `e5b936d..e781393`).
- Task 4: fix round 3/5 (1 addressed, 0 open; commits `e781393..614102d`).
- Task 4: fix commits:
  `e5b936d` (`fix(pilot): close operator API security gaps`);
  `e781393` (`fix(pilot): fail closed on legacy TOTP and extra workers`);
  `614102d` (`fix(pilot): authenticate TOTP envelopes before persistence`).
- Task 4: scoped re-review clean after round 3; no new Critical/Important breakage.
- Task 4: controller verification on `614102d`:
  focused API/security/storage/domain suite → 90 passed, 1 guarded PostgreSQL skip;
  full suite → 178 passed, 1 guarded PostgreSQL skip;
  Ruff across `protector`, `tests`, `cli.py`, and `migrations` → all checks passed;
  task fix-range diff check → clean.
- Task 4: external gate pending — apply `0002_api_security` to disposable live
  PostgreSQL and run guarded concurrency/migration tests. Multi-node deployment remains
  unsupported until sessions/throttles have shared state; current app enforces a
  single local worker with a lifespan-held process lock.
- Task 4: complete (commits `a3c8e34..614102d`, review clean; external PostgreSQL
  acceptance pending).

- Task 5: implementation commit `616838d`
  (`feat(pilot): add deterministic multistream supervisor`).
- Task 5: initial review opened three Important findings: duplicate sequence rejection
  permanently poisoned the camera in `degraded`, successful reconnects retained prior
  exponential backoff, and stale rejected frames did not publish their current
  source-time skew metric.
- Task 5: fix round 1/5 (3 addressed, 0 open; commits `616838d..4ea4578`).
- Task 5: fix commit `4ea4578`
  (`fix(pilot): make camera recovery observable and reusable`).
- Task 5: scoped re-review clean; no new Critical/Important/Minor breakage.
- Task 5: controller verification on `4ea4578`:
  `uv run pytest tests/pilot/test_supervisor.py tests/pilot/test_fake_runtime.py -q`
  → 10 passed; full suite → 188 passed, 1 guarded PostgreSQL skip;
  Ruff across `protector`, `tests`, `cli.py`, and `migrations` → all checks passed;
  task-range diff check → clean.
- Task 5: complete (commits `614102d..4ea4578`, review clean).

- Task 6: implementation commit `a468d53`
  (`feat(pilot): add batched DeepStream runtime`).
- Task 6: initial review opened Critical/Important findings for closed-branch
  preroll, missing mux/source liveness handling, unsafe RTSP pad selection,
  manifest/model-config identity, timestamp provenance, malformed metadata,
  source-local recovery, and fail-closed core startup/runtime errors.
- Task 6: fix round 1/5 retained seven actionable gaps after rereview: reconnect
  grace anchored to the original outage; RTSP child errors misclassified as core;
  malformed metadata aborting later batch items; non-retryable replacement
  failure; an unlaunchable target command without the signed config mount;
  missing/empty caps handling; and an unconsumed encoded tee branch
  (`a468d53..1a5b5dc`).
- Task 6: fix round 2/5 closed all remaining portable findings
  (`1a5b5dc..02cc6cd`). A rereviewer initially questioned recovery of an existing
  nvstreammux request pad via `get_static_pad`; authoritative GStreamer source
  shows that API searches all existing element pads by exact name, so the
  reviewer withdrew the finding and amended the verdict to approved.
- Task 6: fix commits:
  `1a5b5dc` (`fix(pilot): harden DeepStream target failure handling`);
  `02cc6cd` (`fix(pilot): close source recovery and target launch gaps`).
- Task 6: controller verification on `02cc6cd`:
  focused supervisor/DeepStream suite → 38 passed;
  full suite → 219 passed, 1 guarded PostgreSQL skip;
  Ruff across `protector`, `tests`, `cli.py`, and `migrations` → all checks passed;
  `uv lock --check --offline` → clean; task-range diff check → clean.
- Task 6: external gates pending — build/inspect the pinned Linux/amd64 DeepStream
  9.1 image on an NVIDIA L4 host; mount signed commercial-rights/model/engine/config
  artifacts whose hashes and SM/TensorRT versions match the runtime manifest; run
  the frozen lawful 20-feed eight-hour replay and archive the specified graph,
  throughput, queue-age, drop, GPU/VRAM, recovery, and digest artifacts. No NVIDIA
  execution or 20-camera capacity result is claimed on this Apple host.
- Task 6: complete locally (commits `4ea4578..02cc6cd`, review clean; external
  NVIDIA/L4 acceptance pending).

Dispatch the fresh Task 7 implementer for bounded encoded evidence rings, clip
assembly, and atomic object storage. Preserve the Task 6 discard-sink safety until
the Task 7 writer owns and drains the encoded branch.

- Task 7 implementation commit `67708bf`
  (`feat(pilot): create bounded event evidence pipeline`).
- Task 7 initial review verdict: changes required — 1 Critical, 7 Important,
  1 Minor. The target entrypoint did not install or drive the evidence writer;
  incoming splitmux files bypassed the configured ring budgets; overlapping or
  regressive source intervals could defeat the source-time/clip-duration bound;
  the early preview and terminal failure workflow were incomplete; S3 integrity
  and conflicting-publisher ownership were unsafe; credential-bearing endpoints
  were accepted; object/database state transitions were not concurrency-safe or
  durably journaled; local path/volume attestation was susceptible to check/use
  races; and retention deletion did not fsync touched parent directories.
- Controller review added required fixes for startup fragment identity validation,
  exact incomplete-file cleanup scope, evidence-prefix-only retention, single-FD
  pre-assembly re-attestation, finite object reads/uploads, required S3 SSE,
  probed browser compatibility, and the documented splitmux conflict between
  keyframe requests and non-zero `max-size-bytes`.
- Task 7 fix round 1/5 is in progress with the same implementer. External L4,
  real GStreamer/NVENC/browser-fixture, Kazakhstan storage, live PostgreSQL, and
  lawful 20-feed replay gates remain pending and must not be fabricated.
- Task 7 fix round 1 implementation commit `c0a901a`
  (`fix(pilot): make evidence capture bounded and durable`). The configured
  target path now installs the writer fail-closed, adopts standard splitmux
  close messages with writer-bound source-time epochs, enforces owned/scoped
  spool and object-store policy, provides playable preview/final coordination,
  and serializes/journals evidence finalization.
- Task 7 controller verification on `c0a901a`:
  full suite → 284 passed, 1 guarded PostgreSQL skip;
  Ruff across `protector`, `tests`, `cli.py`, and `migrations` → all checks passed;
  `uv lock --check --offline` → clean; fix-range diff check → clean.
- Task 7 fix round 1 independent re-review is in progress on the exact committed
  range `67708bf..c0a901a`.
- Task 7 fix round 1 re-review verdict: changes required — 1 Critical and
  3 Important. Moving RTCP anchors did not define a stable epoch transform and
  accepted `Gst.CLOCK_TIME_NONE`; supervisor epochs repeated across process
  restarts; broad `SQLAlchemyError` journaling could return false-ready and
  poison FIFO without a production replay drain; coordinator cleanup and
  abandoned preview/consumed-ID state were not exception-safe or bounded.
- Task 7 fix round 2/5 is in progress with the same implementer. It must add a
  stable validated source-time transform, boot-scoped evidence epochs,
  transient-only WAL fallback plus a bounded observable replay/quarantine
  service, and durable bounded preview lifecycle cleanup.
- Task 7 fix round 2 implementation commit `0757ad9`
  (`fix(pilot): stabilize evidence lifecycle recovery`). It adds an immutable
  per-epoch RTCP/running-time transform with invalid-clock refusal, fresh
  runtime-session epochs, transient-only database fallback, a finite
  observable replay/quarantine worker, and a marker-owned bounded preview
  workspace whose persisted metadata supports abandoned-candidate failure
  reconciliation before pin/file cleanup.
- Task 7 fix round 2 implementer verification:
  focused evidence/runtime/storage suite → 158 passed, 1 guarded PostgreSQL
  skip; full suite → 310 passed, 1 guarded PostgreSQL skip; final lifecycle
  subset → 5 passed; Ruff, offline lock, staged diff, and repository diff
  checks → clean. A portable FFmpeg 7.1.1 smoke produced a 4.000-second H.264
  High/yuv420p remux; this is not an NVIDIA/NVENC/browser acceptance result.
- Task 7 fix round 2 independent re-review is in progress on exact committed
  range `c0a901a..0757ad9`.
- Task 7 fix round 2 re-review verdict: changes required — 0 Critical,
  4 Important, 0 Minor. Retained rings could reserve a stale pre-restart epoch;
  PostgreSQL `40001`/`40P01`/`55P03` transient work was quarantined instead of
  retried; the preview workspace used redirectable pathnames after one-time
  marker validation; and failed terminal reconciliation could erase its retry
  metadata, ignore persisted expiry evidence, or mask the primary upload error.
- Task 7 fix round 3/5 is in progress with the same implementer. It must bind
  reservation to the current stream epoch, narrow-classify PostgreSQL
  concurrency SQLSTATEs as retryable, pin/re-attest the owned preview namespace,
  and preserve retry identity plus primary/cleanup error ordering.
- The original round-3 implementer was lost during a controller turn
  interruption after leaving one RED epoch-selection test. A replacement
  implementer resumed that exact shared-worktree state without resetting it.
- Task 7 fix round 3 implementation commit `4ebf9bd`
  (`fix(pilot): preserve evidence recovery identity`). Reservations now require
  the current stream epoch; exact PostgreSQL concurrency SQLSTATEs remain live
  with backoff; preview operations retain and attest a directory descriptor;
  and terminal tombstones survive failed marking/release/cleanup while
  publisher failures preserve primary-first ordering.
- Task 7 fix round 3 RED/GREEN evidence: 11 focused failures were reproduced;
  focused Task 7 suite → 168 passed, 2 guarded PostgreSQL skips; full suite →
  320 passed, 2 guarded PostgreSQL skips; Ruff, offline lock, and diff checks
  → clean.
- Task 7 fix round 3 independent re-review is in progress on exact committed
  range `0757ad9..4ebf9bd`.
- Task 7 fix round 3 re-review verdict: changes required — 0 Critical,
  2 Important, 1 Minor. The external assembler could still write through a
  replaceable workspace pathname before post-write attestation, and successful
  object upload followed by an undurable ready transition deleted its only
  reconciliation identity. Replay status also lacked cumulative failed-attempt
  telemetry.
- Task 7 fix round 4/5 is in progress with the replacement implementer. It must
  use descriptor-backed bounded assembler output, persist and reconcile an
  explicitly verified ready intent across restarts, and expose retry-attempt
  telemetry.
- Task 7 fix round 4 implementation commit `5f52103`
  (`fix(pilot): pin evidence assembly and ready recovery`). The coordinator
  now gives assemblers pre-opened inode-bound outputs, real FFmpeg uses the
  seekable `fd:` protocol with explicit MP4/FD inheritance and strict probing,
  and ready intent persists exact key/hash/size before publication for
  verified restart reconciliation. Replay status exposes cumulative failed
  attempts.
- Task 7 fix round 4 verification: focused Task 7 suite → 178 passed,
  2 guarded PostgreSQL skips; full suite → 330 passed, 2 guarded PostgreSQL
  skips; real portable FFmpeg 7.1.1 descriptor assembly/probe → pass; Ruff,
  offline lock, and diff checks → clean.
- Task 7 fix round 4 independent re-review is in progress on exact committed
  range `4ebf9bd..5f52103`.
- Task 7 fix round 4 re-review verdict: changes required — 0 Critical,
  3 Important, 0 Minor. The first selected video packet was not required to
  be keyframed, production FFmpeg could exceed its output ceiling before
  rejection, and one ready-recovery branch lost primary-first error ordering.
- Task 7 fix round 5 implementation commit `89df497`
  (`fix(pilot): enforce finite evidence boundaries`). It requires first-packet
  keyframe truth for missing/positive splitmux claims, launches FFmpeg behind
  a fail-closed POSIX `RLIMIT_FSIZE` boundary, and preserves integrity failure
  ordering through failed ready reconciliation.
- Task 7 fix round 5 verification: focused Task 7 suite → 186 passed,
  2 guarded PostgreSQL skips; full suite → 338 passed, 2 guarded PostgreSQL
  skips; real portable FFmpeg descriptor/512-byte limiter smokes → pass; Ruff,
  offline lock, and diff checks → clean.
- Task 7 fix round 5 independent re-review verdict: changes required —
  0 Critical, 1 Important, 0 Minor. Keyframe probing and later ring adoption
  reopened the staging basename separately, allowing replacement bytes to be
  stored with the original probe's positive keyframe result.
- Task 7 controller closeout implementation is verified and awaiting the
  controller's scoped commit because this agent's sandbox cannot write the
  external worktree Git index. Splitmux now opens once descriptor-relative
  with `O_NOFOLLOW`, unlinks and fsyncs under the ring lock, and probes/reads
  the same finite descriptor. A basename swap leaves replacement bytes
  unadopted. Held-source bytes remain additive to writer/visible staging until
  descriptor close, while direct/adoption copies reserve capacity before
  `_atomic_write` and atomically transition pending bytes to an adopted record.
- Task 7 controller closeout RED/GREEN evidence: basename replacement first
  stored unprobed bytes; a blocked probe then reported 80 bytes instead of the
  required 160 while its unlinked source inode was held. Exact evidence suite
  → 47 passed; focused Task 7 suite → 190 passed, 2 guarded PostgreSQL skips;
  full suite → 342 passed, 2 guarded PostgreSQL skips; full Ruff, offline lock,
  and diff checks → clean.
- Task 7 controller closeout commits: `bc011bb`
  (`fix(pilot): bind fragment probe to adopted bytes`) and `a471a27`
  (`fix(pilot): account in-flight fragment adoption`).
- Task 7 final independent accounting review: clean — 0 Critical,
  0 Important, 0 Minor. The exact scoped regressions passed 6/6; focused
  Task 7 suite → 190 passed, 2 guarded PostgreSQL skips; full suite →
  342 passed, 2 guarded PostgreSQL skips; full Ruff, offline lock, and diff
  checks → clean.
- Task 7: complete locally. External NVIDIA/L4 splitmux/NVENC/browser,
  filesystem-quota/GOP, live PostgreSQL, Kazakhstan object-store, and lawful
  20-feed acceptance gates remain pending and unclaimed.

Dispatch a fresh Task 8 implementer for timestamp-based idempotent event
fusion, normalised zones/loitering/directional lines, candidate-only
human-review workflow, bounded WAL persistence/replay, and Task 7 evidence
reservation integration.

- Task 8 RED tests were created by the fresh implementer and frozen after
  proving the engine module was absent. That implementer and one replacement
  stalled before producing an implementation; the controller resumed the
  shared RED state without discarding or weakening tests.
- Task 8 implementation now provides source-time N-of-M fusion, duplicate and
  stale-sample refusal, per-camera/epoch/module/track state, bounded merge and
  cooldown state, normalised intrusion/loitering/directional-line geometry,
  deterministic immutable candidates, WAL-first replay, visible degradation,
  and Task 7 evidence reservation/association.
- Task 8 safety: disabled emits nothing; shadow/operator remain
  `review_status=candidate`; there is no notification or autonomous response
  path. Pending evidence placeholders are not persisted; Task 7 publishes
  only measured ready/failed identities.
- Task 8 controller verification before commit: focused suites → 29 passed;
  full suite → 371 passed, 2 guarded PostgreSQL skips; full Ruff, offline
  lock, and diff checks → clean.
- Task 8 resumption point: commit only
  `protector/pilot/runtime/event_engine.py`,
  `tests/pilot/test_event_engine.py`, and
  `tests/pilot/test_zone_analytics.py` with
  `feat(pilot): add idempotent site event engine`, then dispatch a fresh
  independent read-only task reviewer.
- Task 8 implementation commit: `7579e89`
  (`feat(pilot): add idempotent site event engine`).
- Task 8 first independent review verdict: changes required — 1 Critical,
  4 Important, 2 Minor. Simultaneous candidates shared a persistence key;
  evidence was reserved before WAL durability and used a fabricated pending
  digest; geometry ignored confidence/finite-segment and complete polygon
  validity; ordering-stream state was unbounded; engine/service transitions
  were unsynchronised; journal-depth failure could report healthy; and source
  references accepted token-bearing query/fragment data.
- Task 8 fix round 1 used a fresh implementer. After it stopped progressing
  with a shared RED/GREEN draft, the controller preserved the worktree,
  corrected one misplaced PostgreSQL-only test block, and completed the
  bounded fix without weakening tests.
- Task 8 fix round 1 RED/GREEN evidence: the fresh implementer ran the focused
  event/geometry suite and first got an `EvidenceIntent` import failure; after
  implementation it observed 43 focused tests pass. The controller's first
  expanded run isolated the misplaced PostgreSQL block at
  1 failed / 152 passed / 2 guarded skips, then reached the final clean
  verification below.
- Task 8 fix round 1 now uses event-UUID persistence identity, exact
  candidate-before-reservation receipts, hash-free versioned evidence intents,
  constrained repository transitions, restart-safe terminal reconciliation,
  complete geometry gates, bounded ordering streams, engine transition
  locking, bounded same-event service claims, visible journal observability
  failures, and opaque credential-free NVR source references.
- Task 8 fix round 1 controller verification: focused integration →
  162 passed, 2 guarded PostgreSQL skips; full suite → 397 passed,
  2 guarded PostgreSQL skips; full Ruff, offline lock, and diff checks clean.
- Task 8 fix round 1 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-1-report.md`.
- Task 8 resumption point: commit the scoped fix, then dispatch the original
  independent Task 8 reviewer for exact-range re-review.
- Task 8 fix round 1 commit: `6828525`
  (`fix(pilot): harden event persistence and recovery`).
- Task 8 fix round 1 independent re-review verdict: changes required —
  1 Critical, 3 Important, 0 Minor. Normal pending post-roll work had no
  periodic re-reservation/finalisation path; old-format candidate WAL keys
  were copied rather than normalised; unique in-flight service claims had no
  finite bound; and pending/failed transition callbacks were not validated.
  Fresh reviewer verification was 49 focused Task 8 passes, 113 related
  integration passes with 2 guarded PostgreSQL skips, full 397 passes with
  2 guarded skips, and clean Ruff/diff checks.
- Task 8 fix round 2 must add a bounded, restart-aware periodic pending
  evidence workflow using real ring semantics; normalise actual legacy WAL
  keys with exact replay convergence; cap and expose in-flight claims; and
  require exact transition receipts with immediate Task 7 reconciliation on
  failure.
- Task 8 fix round 2 fresh-implementer RED:
  11 failed / 51 passed / 1 guarded skip across event and journal tests.
  The failures covered pending post-roll completion, periodic/claim bounds,
  transition receipts, and actual legacy WAL identities.
- Task 8 fix round 2 now periodically reacquires exact pending reservations,
  completes ready evidence once, reconciles epoch/expiry failure, bounds and
  exposes pending/processing work, requires exact pending/failed receipts,
  journals unique capacity-refused candidates, and transactionally normalizes
  old WAL keys/payloads with exact duplicate convergence and conflict rollback.
- Controller review added one RED regression for a completed duplicate that
  re-enqueued stale candidate work. Claim classification now suppresses
  active/completed duplicates while still journalling unique capacity-refused
  candidates; the regression is green.
- Task 8 fix round 2 controller verification: focused event/journal →
  70 passed, 1 guarded skip; related evidence/storage → 158 passed,
  1 guarded skip; full suite → 417 passed, 2 guarded PostgreSQL skips;
  full Ruff, offline lock, and diff checks clean.
- Task 8 fix round 2 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-2-report.md`.
- Task 8 resumption point: commit only the four scoped tracked files, then
  dispatch the independent Task 8 reviewer on the exact fix-round-2 range.
- Task 8 fix round 2 commit: `da92f0a`
  (`fix(pilot): complete bounded post-roll evidence`).
- Task 8 fix round 2 independent re-review verdict: changes required —
  0 Critical, 4 Important, 0 Minor. Normal no-crash post-roll completion,
  legacy WAL normalization, bounded processing claims, and exact transition
  receipts are closed. Remaining portable gaps are durable restart recovery
  for pending work; initial-preview versus periodic lifecycle serialization;
  rejection of delayed old-epoch periodic completion; and material validation
  of ready evidence digests, codec, timestamps, duration, and interval.
- Task 8 fix round 3 must persist finite pending-work identity and reconcile it
  transactionally at startup across every crash boundary; publish work to the
  periodic drain only after preview plus the exact pending transition; bind
  draining to the engine's current active epoch; and fail closed on malformed
  ready evidence. Add adversarial restart, concurrency, epoch, and receipt
  tests using the real Task 7 workspace lifecycle where applicable.
- Task 8 fix round 3 fresh-implementer RED: 15 failed / 49 passed in the
  focused event suite, reproducing durable restart loss, initial/periodic
  lifecycle overlap, delayed old-epoch completion, and malformed ready
  receipts on immediate and periodic paths.
- Task 8 fix round 3 now stores finite reserved/active evidence lifecycle
  records in SQLite before preview work, reconstructs active work or
  terminally reconciles reserved/terminal/corrupt/over-capacity work at
  startup, quarantines poison records without retaining active capacity, and
  exposes recovery degradation.
- Periodic work is not drainable until preview creation plus an exact pending
  transition and durable activation complete. Unit barriers and the real
  Task 7 PreviewWorkspace/EvidenceCoordinator cover preview-versus-periodic,
  failure-versus-periodic, and cleanup-versus-completion races.
- Pending completion checks the EventEngine's active camera epoch before
  reacquisition, before completion, and after completion. Ready receipts now
  require exact identity/source, lowercase SHA-256, browser H.264, ordered UTC
  timestamps, 4-10 second duration, and bounded coverage of the immutable
  intent.
- Task 8 fix round 3 controller verification: focused event/journal →
  101 passed, 1 guarded PostgreSQL skip; full suite → 447 passed, 2 guarded
  PostgreSQL skips; full Ruff, offline lock, and diff checks clean.
- Task 8 fix round 3 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-3-report.md`.
- Task 8 resumption point: commit the three scoped tracked files, then dispatch
  the original independent reviewer on the exact round-3 fix range.
- Task 8 fix round 3 commit: `4f21d81`
  (`fix(pilot): recover evidence lifecycle durably`).
- Task 8 fix round 3 independent re-review verdict: changes required —
  0 Critical, 4 Important, 1 Minor. The initial/periodic race,
  pre-publication epoch refusal, receipt validation, prior WAL migration and
  bounds are closed. Remaining gaps are a true crash window before the
  lifecycle row; the real coordinator terminalizing an active workspace before
  service recovery; retryable repository outages being quarantined as poison;
  terminal ACK failure retaining non-drainable memory; published-ready versus
  epoch-change convergence; and silent quarantine eviction.
- Task 8 fix round 4 must durably seed the full trigger/recovery identity before
  candidate replay ACK and ring reservation; promote that seed through
  reserved/active phases; resume real-coordinator active work even when its
  startup reconciliation marked the candidate failed; distinguish retryable
  recovery failures from deterministic poison; make lifecycle ACK idempotent
  and live-retryable; define ready-publication-wins fencing for exact durable
  ready state; and refuse or explicitly account for quarantine overflow.
- Task 8 fix round 4 fresh-implementer RED: 8 failed / 101 passed /
  1 guarded PostgreSQL skip. Failures reproduced missing seed order,
  seed-write durability, silent quarantine eviction, real Task 7 failed-state
  recovery, transient-load quarantine, ACK capacity leakage, and durable-ready
  epoch fencing.
- Task 8 fix round 4 now persists a versioned full recovery seed before normal
  candidate enqueue/replay and ring reservation, atomically promotes
  seed→reserved→active, idempotently restores seed-only candidates, and
  converges real coordinator/repository/object-store/workspace restarts at
  actual SystemExit boundaries. Missing-seed candidate metadata is moved to
  the bounded visible main quarantine without head-of-line blocking valid
  seeded candidates.
- Retryable repository, cleanup, transition, quarantine, and ACK failures
  retain finite durable identity and schedule periodic backoff. Status exposes
  durable depth, memory depth, retry attempts, and next retry. ACK is
  transactional/idempotent, including commit-before-return recovery.
- Exact durable ready publication wins a concurrent epoch fence and ACKs the
  lifecycle; an epoch switch before publication terminalizes. Both orders use
  the real publisher/repository/object store/workspace/coordinator in tests.
  Pending quarantine now refuses overflow instead of silently evicting.
- Task 8 fix round 4 controller verification: focused journal/event →
  124 passed, 1 guarded PostgreSQL skip; full suite → 470 passed, 2 guarded
  PostgreSQL skips; full Ruff, offline lock, and diff checks clean.
- Task 8 fix round 4 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-4-report.md`.
- Task 8 resumption point: commit the four scoped tracked files and dispatch
  the original independent reviewer on the exact round-4 range. This is the
  fourth bounded fix round; one final round remains before escalation.
- Task 8 fix round 4 commit: `210e798`
  (`fix(pilot): fence crash-safe evidence recovery`).
- Task 8 fix round 4 independent re-review verdict: changes required —
  0 Critical, 3 Important, 0 Minor. Real Task 7 recovery, ordinary transient
  retry, ready/epoch fencing, seed ordering, pending-quarantine refusal,
  migration/transactions, and prior safety bounds are closed. Remaining gaps:
  terminal failed ACK commit-before-return leaves orphan memory; a full main
  quarantine HOL-blocks later seeded candidates; and pre-intent deterministic
  failure ACKs the seed despite incomplete failed transition or release.
- Task 8 fix round 5 is the final bounded round. It must reconcile exact failed
  terminal memory when the durable row is absent; replay only rows with a
  matching lifecycle while leaving unquarantinable orphans durable and
  visible, preserving eligible FIFO; and retain/schedule the seed until both
  exact terminal receipt and reservation cleanup succeed on pre-intent
  failure.
- Task 8 fix round 5 fresh-implementer RED: 6 focused failures reproduced
  failed-terminal ACK orphan capacity, full-quarantine head-of-line blocking,
  and one-shot/repeated pre-intent transition/release loss across live and
  restart paths. A controller follow-up RED also reproduced unreleased
  over-capacity seed reservations.
- Task 8 fix round 5 now reconciles exact failed terminal memory after an ACK
  commit crash; exposes a bounded eligible-row replay API that preserves FIFO
  while leaving unquarantinable missing-seed rows durable and visible; and
  retains the seed until both exact terminal transition and reservation
  cleanup are durable. Failed and over-capacity recovered seeds release before
  ACK.
- Task 8 fix round 5 controller verification: focused event/journal →
  132 passed, 1 guarded PostgreSQL skip; related integration → 290 passed,
  2 guarded PostgreSQL skips; full suite → 478 passed, 2 guarded PostgreSQL
  skips; full Ruff, offline lock, and diff checks clean.
- Task 8 fix round 5 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-5-report.md`.
- Task 8 fix round 5 commit: `334f75c`
  (`fix(pilot): close event recovery failure compositions`).
- Task 8 resumption point: dispatch a fresh independent reviewer for exact
  range `210e798..334f75c`; close Task 8 only on a clean verdict.
- Task 8 fix round 5 independent review verdict: changes required —
  0 Critical, 2 Important, 0 Minor. The intended failed-ACK,
  quarantine-eligibility, and pre-intent cleanup regressions are closed.
  Remaining compositions: the initial ring-reserve exception path can ACK a
  seed after the real ring partially pinned fragments; and recovery capacity
  uses a static row index, so terminal rows reconciled earlier in the same
  pass can falsely consume capacity and fail later recoverable seeds.
- Task 8 fix round 5 review:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-8-fix-round-5-review.md`.
- Task 8 round 5 remains open for one batched in-round correction. Resumption
  point: TDD the real partial-reserve cleanup boundary and dynamic live-slot
  recovery accounting, then amend `334f75c` with a new scoped commit and send
  the exact delta back to the same independent reviewer.
- Task 8 round 5 independent-review correction RED: 3 primary failures
  reproduced partial real-ring reservation cleanup and terminal rows falsely
  consuming the sole recovery slot. A follow-up RED reproduced that release
  metadata failure removed the in-memory pin before durable metadata cleanup.
- The correction now requires an exact failed receipt plus durable idempotent
  release before reserve-exception seed ACK; restores in-memory pins when
  release metadata persistence fails; releases ready/failed seed reservations;
  and uses actual live pending occupancy instead of a static record index.
- Task 8 correction verification: event/journal/evidence → 188 passed,
  1 guarded PostgreSQL skip; related integration → 299 passed, 2 guarded
  PostgreSQL skips; full suite → 487 passed, 2 guarded PostgreSQL skips; Ruff
  including migrations, offline lock, and diff checks clean.
- Task 8 independent-review correction commit: `4a3ef82`
  (`fix(pilot): make event recovery cleanup atomic`).
- Task 8 resumption point: return exact delta `334f75c..4a3ef82` to the same
  independent reviewer; close Task 8 only on a clean final verdict.
- Task 8 final corrected round-5 re-review verdict: approved locally —
  0 Critical, 0 Important, 0 Minor across correction
  `334f75c..4a3ef82` and cumulative Task 8 range `210e798..4a3ef82`.
  Independent real-ring restart probing confirmed a durable stale pin and
  seed converge to zero pins/rows/memory; dynamic live-slot recovery keeps
  terminal/quarantined rows free, active rows counted, and true excess
  terminalized/released/ACKed.
- Task 8 final independent verification: targeted 18 passed; focused
  event/journal/evidence → 188 passed, 1 guarded PostgreSQL skip; related →
  299 passed, 2 guarded PostgreSQL skips; full → 487 passed, 2 guarded
  PostgreSQL skips; Ruff, offline lock, correction/full-range/worktree diff
  checks clean.
- Task 8 is complete. External live PostgreSQL, Kazakhstan storage,
  NVIDIA/L4, real 20-camera replay, and target-site acceptance gates remain
  explicitly pending and unclaimed.
- Resumption point: begin Task 9 with a fresh TDD implementer using
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-9-brief.md`.
- Task 9 fresh-implementer RED began with both required suites failing
  collection on the absent model registry, then added focused RED cases for
  byte-verifying export/deployment audit, target runtime identity, safe
  subprocess/output publication, INT8 binding, report binding, explicit
  runtime gates, finite ROI fanout, and compact NVIDIA version banners.
- Task 9 now provides one central conditional promotion authority; canonical
  registry/artifact/engine/runtime bindings; rights/hash-first export and
  deployment audit; L4/SM 8.9/TensorRT target probing; atomic no-clobber,
  timeout/output/engine-bounded candidate builds; INT8 calibration and exact
  engine no-regression gates; signed site/shadow/capacity contracts; and
  disabled-by-default finite shared fire/weapon/verifier/shadow scheduling.
- Task 9 portable verification: focused → 46 passed; related gates/graph/config
  → 137 passed; full → 533 passed, 2 guarded PostgreSQL skips; production-path
  Ruff, offline lock, and diff checks clean.
- Task 9 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-9-report.md`.
- Task 9 implementation commit: `88d9321`
  (`feat(pilot): gate conditional models by rights quality and capacity`).
- Task 9 external gates remain pending and unclaimed: actual rights-cleared
  model bytes, pinned NVIDIA L4/DeepStream target build, signed site/shadow
  matrices, exact 20-feed frozen replay, and measured 25%+ capacity headroom.
- Task 9 resumption point: dispatch a fresh independent reviewer for exact
  range `4a3ef82..88d9321`; commit only reviewed fixes.
- Task 9 independent review is in progress. Reproduced findings so far:
  runtime scheduling trusts caller-constructed gate results without full
  site/registry/engine/runtime binding; central promotion accepts non-L4 and
  non-pinned TensorRT engine identities when internally self-consistent; INT8
  export can disagree with the registry precision and does not supply the
  bound calibration input to TensorRT; and an artifact pathname can be swapped
  after the approved-byte audit but before TensorRT opens it (rights/hash
  TOCTOU). Task 10 is held until the reviewer finishes the whole audit and a
  fresh TDD fix implementer closes the complete Task 9 boundary.
- Task 9 independent review verdict: changes required — 2 Critical,
  6 Important, 0 Minor. Criticals are artifact-byte TOCTOU between audit and
  export, and post-hash mutation of a hard-linked engine by surviving exporter
  descendants. Importants cover runtime authority/binding bypass, incomplete
  INT8 calibration/config binding, non-L4 promotion, capacity workload
  under-binding, secret-bearing receipt references, and failed-publication
  cleanup. Report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-9-review.md`.
- Task 9 resumption point: dispatch a fresh TDD implementer for one bounded
  correction round covering all eight findings; require RED reproductions,
  focused/related/full verification, and an implementation report before
  independent re-review.
- Task 9 fix round 1 RED: 19 intentional failures / 46 passes across artifact
  pathname replacement and symlink input, surviving-descendant engine
  mutation, caller-forged runtime gates and discarded work bindings,
  registry/INT8 precision mismatch and absent local calibration bytes, three
  non-pilot target identities, understated workload denominator, seven
  secret-bearing reference forms, and publication-durability cleanup/retry.
  No fixture-only failures. Fresh implementer is proceeding to GREEN.
- Task 9 fix round 1 GREEN closes the two byte-identity races and all six
  Important findings. Additional RED cases forced frozen weapon ROI fanout
  into the independently expected capacity denominator, bound both workload
  identities into verifier work, disabled mixed-site compositions, and
  required the bounded shadow-verifier boundary.
- Task 9 fix round 1 implementation verification: focused → 68 passed;
  related gates/DeepStream/config/domain/Task 9 → 159 passed; full suite →
  555 passed, 2 guarded PostgreSQL skips; production/test/CLI/migrations/pilot
  Ruff, offline lock, and diff checks clean. Controller independently
  reproduced focused 68 passes and full 555 passes / 2 skips with all required
  static/lock/diff checks clean.
- Task 9 fix round 1 report:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-9-fix-round-1-report.md`.
- Task 9 resumption point: commit the reviewed correction delta, then return
  exact range `88d9321..<fix-commit>` to a fresh independent reviewer. Task 9
  remains open until that re-review is clean.
- Task 9 fix round 1 committed as `ff22522`
  (`fix(pilot): bind model promotion to exact runtime evidence`).
- Task 9 fix round 1 fresh re-review confirms the two Critical byte-provenance
  races, exact target checks, and core INT8 binding are closed, but has
  reproduced remaining Important compositions: expected workload is not yet
  derived/validated against the actual immutable `SiteConfig`; verifier
  candidates do not carry and revalidate their upstream detector/site/config/
  decision identity or approved camera membership; engine and durable build
  receipt publication remain separate failure/crash domains; and reference
  canonicalization still accepts backslash/path-parameter token forms. The
  reviewer is completing the whole audit before the next bounded fix round.
- Task 9 fix round 1 independent re-review verdict: changes required —
  0 Critical, 4 Important, 1 Minor. The four Importants are the expected
  workload authority, verifier origin/camera admission, strict reference
  canonicalization, and recoverable engine+receipt+commit publication. The
  Minor is contradictory deployment-audit approval for a non-pilot target.
  Review:
  `.superpowers/sdd/2026-07-22-kuzet-20-camera-pilot/task-9-fix-round-1-review.md`.
- Task 9 remains open. Resumption point: one fresh TDD fix round must close all
  five findings, with the publication commit marker required by deployment
  audit/runtime and site workload derived centrally from actual `SiteConfig`
  plus an attested frozen replay/fanout manifest.
- Task 9 fix round 2 RED: 45 intentional failures / 70 passes with production
  unchanged. Coverage maps to 18 accepted noncanonical references, 3 non-pilot
  deployment audits, 4 missing engine+receipt+commit/restart behaviors,
  9 missing central `SiteConfig` + attested-manifest authority cases, and
  11 unknown-camera/verifier-origin binding cases. Fresh implementer is
  proceeding to GREEN.
- Task 9 fix round 2 focused GREEN: 120 passed / 0 failed. This includes
  signed corpus/fanout derivation from immutable `SiteConfig`, strict reference
  cases, exact-target deployment audit, origin-bound verifier admission, and
  both pre-commit and post-commit restart recovery. Related/full/static
  verification remains in progress.
- Task 9 fix round 2 implementation verification completed: focused →
  125 passed; related → 215 passed; full repository → 612 passed with the two
  guarded PostgreSQL skips; Ruff, offline lock, and diff checks clean. Report:
  `task-9-fix-round-2-report.md`.
- Controller independently reproduced focused 125 passes, full 612 passes /
  2 guarded skips, Ruff, offline lock, and diff checks.
- Task 9 fix round 2 independent review verdict: changes required —
  1 Critical, 0 Important, 1 Minor. A deterministic identical-build
  interleaving proved that record equality is not live-owner exclusion: retry B
  can reclaim build A's active intent, delete A's engine, crash, and let A
  return success with receipt+commit but no engine. A self-referential intent
  symlink also raises instead of producing a machine-readable fail-closed
  audit refusal. Review: `task-9-fix-round-2-review.md`.
- Task 9 remains open. Resumption point: a fresh TDD implementer must add a
  crash-released nonblocking per-publication OS lock held across recovery,
  export, publication, and cleanup; include the lock path in alias checks; use
  no-follow intent presence checks; add deterministic concurrency and
  dangling/looping intent-symlink regressions; run focused/full/static checks;
  then return the delta for a fresh independent re-review.
- Task 9 fix round 3 RED: 8 intentional failures / 3 passes / 67 deselected
  with production unchanged. The deterministic live-build interleaving reached
  retry B's exporter instead of refusing it; dangling intent returned a path
  mismatch; looping intent raised `RuntimeError`; the lock alias was accepted;
  three lock symlink forms were ignored; and no bounded owner-only lock file
  existed.
- Task 9 fix round 3 now derives a fifth exact publication path for a persistent
  lock file; opens it read/write/create with close-on-exec and no-follow,
  validates a bounded regular inode, restricts it to mode `0600`, and acquires
  a nonblocking POSIX exclusive lock. The descriptor stays owned continuously
  across intent recovery, exporter execution, engine/receipt/commit
  publication, cleanup, success, ordinary errors, and simulated process-stop
  unwinding. Kernel ownership releases on unlock/close/crash while the safe
  pathname may remain for reuse.
- Intent audit and recovery use no-follow `lexists` presence. Publication
  binding resolves only parent directories, never attacker-controlled final
  directory entries. Engine, receipt, commit, intent, and lock destinations
  must be distinct; a custom receipt cannot alias the lock.
- Task 9 fix round 3 verification: new regressions → 11 passed; complete model
  audit → 78 passed; focused Task 9 → 133 passed; related
  config/gates/DeepStream/Task 9 → 211 passed; full repository → 620 passed,
  2 guarded PostgreSQL skips. Full Ruff, offline lock, and diff checks are
  clean. Report: `task-9-fix-round-3-report.md`.
- Task 9 remains open pending independent re-review. Resumption point: commit
  only the scoped round-2/round-3 Task 9 correction after controller
  verification, then dispatch a fresh independent reviewer across the exact
  correction delta and cumulative Task 9 behavior. External NVIDIA L4, live
  exact-20-feed, rights, signed site-quality, and measured capacity gates
  remain pending and unclaimed.
- Controller independently reproduced Task 9 focused → 133 passed, full
  repository → 620 passed / 2 guarded PostgreSQL skips, Ruff, offline lock,
  and diff checks clean. Source inspection confirms the crash-released lock is
  held across intent recovery/export/publication/cleanup and every unwind;
  unsafe lock/intent final entries are not followed. Resumption point: commit
  the exact seven tracked Task 9 correction files, then require a fresh
  independent clean re-review before marking Task 9 complete.
- Task 9 bounded corrections committed as `f83af03`
  (`fix(pilot): make model publication and workload gates authoritative`).
  Resumption point: fresh independent reviewer must audit exact
  `ff22522..f83af03` and cumulative `4a3ef82..f83af03`; Task 10 remains held
  until a clean verdict.
- Task 9 final independent review approved: 0 Critical, 0 Important, 0 Minor.
  Fresh reviewer verification: focused Task 9 → 133 passed; related suite →
  224 passed; Ruff, offline lock, and both exact/cumulative diff checks clean.
  Review: `task-9-final-review.md`.
- Task 9 is complete at `f83af03`. External NVIDIA L4 engine build, signed
  customer rights/site/frozen-replay evidence, measured 20-stream capacity,
  live RTSP, and soak gates remain pending and unclaimed. Resumption point:
  Task 10 TDD implementer should build the secure server-rendered operator
  console from `task-10-brief.md`, preserving all existing API/demo behavior.
- Task 10 initial RED:
  `uv run pytest tests/pilot/test_web_views.py -q` stopped at collection with
  the expected `ModuleNotFoundError: No module named 'protector.pilot.api.web'`.
  A later logout-specific RED failed exactly because the authenticated console
  had no sign-out control.
- Task 10 now adds a server-rendered Jinja console at `/pilot` with public login,
  an exact 20-card latest-health dashboard, bounded event filters/search, safe
  event detail/review history, role/gate-dependent review controls, local
  responsive CSS/JavaScript, CSRF-protected logout, and explicit empty/loading/
  error/evidence states. The existing JSON login/review APIs remain the
  authoritative mutation boundary.
- Evidence preview is fail-closed behind an optional provider that receives only
  the opaque event UUID. The same-origin route requires an authenticated
  session, a persisted ready event/evidence row, a strict media type, and a
  16 MiB response ceiling. Object keys, source references, RTSP sources, and
  unrestricted storage URLs never enter HTML/client state.
- Task 10 security coverage proves unauthenticated view redirects do not reflect
  attacker-controlled return targets; viewer/operator/admin control visibility;
  script/attribute escaping; latest health selection; safe evidence states;
  same-origin CSP with no inline/external assets; frame denial, nosniff,
  no-referrer and no-store; bounded search; fresh review idempotency; keyboard
  semantics, visible focus, 44 px actions, mobile layout, and reduced motion.
- Task 10 verification:
  focused web → 20 passed; existing auth/event/security compatibility → 52
  passed; pilot suite before the logout-only delta → 576 passed / 2 guarded
  PostgreSQL skips; final full repository → 640 passed / 2 guarded PostgreSQL
  skips. Full Ruff, offline lock, and diff checks are clean.
- Task 10 controller browser review found and reproduced one real mobile defect:
  at 390 px the document widened to 833 px despite correct internal table
  scrolling. The first shell/scroller CSS correction was insufficient; DOM
  geometry identified an absolutely positioned visually-hidden table-header
  descendant at x≈833. A strengthened rendered-markup RED now prevents that
  composition. The header uses an accessible `aria-label`, and the unused
  absolute-hide CSS was removed.
- Task 10 controller browser recheck is clean: desktop 1280 px and mobile
  390 × 844 have no document overflow; the filtered dashboard is exactly
  390 px while its table remains internally scrollable (372 / 896 px);
  20 cards, detail preview/roles/escaping, 340 × 46.8 px mobile review actions,
  persisted mobile rejection/history, and authenticated logout all passed.
  Synthetic keyboard Tab dispatch was unreliable in browser control, so only
  DOM/source semantics, focus CSS, native controls/labels, and non-pointer-only
  interaction are claimed.
- Task 10 report: `task-10-report.md`. Resumption point: commit only the scoped
  Task 10 production/test files, then dispatch a fresh independent reviewer for
  the exact Task 10 range. Do not mark complete until review is clean.
- Task 10 controller automated re-verification after the responsive fix:
  web/auth/event/security focus → 54 passed; full repository → 640 passed /
  2 guarded PostgreSQL skips; Ruff, offline lock, and `git diff --check` are
  clean. Source review found no additional release-blocking defect. Resumption
  point: create the scoped Task 10 commit and dispatch the independent reviewer.
- Task 10 implementation committed as `b1d6e36` (`feat(pilot): add secure
  operator console`). Resumption point: independent review of exact range
  `f83af03..b1d6e36`; no Task 11 work until the Task 10 verdict is clean.
- Task 10 independent review of `f83af03..b1d6e36` rejected with 0 Critical,
  1 Important, and 2 Minor findings. The Important issue is an unqualified
  first-20 camera query that could mix disabled/foreign-site rows while still
  claiming 20/20. Minors are an accepted-but-unrenderable JPEG preview and an
  error-state test that did not execute the 503 path. Bounded fix loop 1 is in
  progress; Task 11 remains held.
- Task 10 bounded fix round 1 RED added explicit-site, enabled/foreign identity,
  19/21 count, ambiguous omitted-site, real SQL query failure, and JPEG
  rejection regressions. The initial five selected tests failed at the expected
  missing additive `pilot_site_id` app contract.
- Task 10 bounded fix round 1 now scopes health to the explicit enabled pilot
  site, requires exactly 20 cameras without truncation, and fails ambiguous
  omitted-site rendering visibly with HTTP 503. Evidence preview accepts only
  the MP4 media type rendered by the console; a forced SQLAlchemy camera-health
  query failure proves the visible 503 path.
- Task 10 fix verification: web/auth/event/security focus → 60 passed; full
  repository → 646 passed / 2 guarded PostgreSQL skips; scoped Ruff, offline
  lock, and diff check are clean. No commit was created by the fix implementer.
  Resumption point: controller source review and exact scoped commit, then fresh
  independent re-review before Task 10 can close.
- Task 10 controller composition review extended the site binding to the event
  list, direct event detail, and evidence preview, preventing a foreign-site
  event/evidence disclosure once `pilot_site_id` becomes authoritative. The
  supplied site identity is stripped and bounded to 1–128 characters.
  Additional TDD coverage proves foreign ready evidence is absent/inaccessible.
- Task 10 final bounded-fix controller verification: web/auth/event/security
  focus → 64 passed; full repository → 650 passed / 2 guarded PostgreSQL skips;
  full Ruff, offline lock, and diff checks are clean. Resumption point: commit
  the five scoped fix files and re-dispatch the independent reviewer.
- Task 10 bounded fix committed as `adc7311` (`fix(pilot): bind console to
  authoritative site`). Resumption point: independent re-review of
  `b1d6e36..adc7311` plus cumulative Task 10 range; Task 11 remains held.
- Task 10 re-review closed the original 1 Important / 2 Minor findings but
  rejected with 0 Critical / 1 Important / 0 Minor: authenticated JSON camera
  and event authorities ignored `pilot_site_id`, so a foreign-site candidate
  hidden by the console could still be fetched, confirmed, and placed in the
  notification outbox. Bounded fix round 2 is extending the site predicate
  through list/get/audit and the atomic review/outbox transaction. Task 11
  remains held.
- Task 10 bounded fix round 2 centralises site resolution, scopes authenticated
  camera/event/audit APIs, prevents caller-selected site switching, and passes
  the expected site into the locked review/audit/outbox transaction. TDD proves
  foreign reads/review/audit/outbox fail closed while disabled same-site
  historical events remain reviewable.
- Task 10 round-2 controller verification: focused API/web/security → 66 passed;
  full repository → 652 passed / 2 guarded PostgreSQL skips; full Ruff, offline
  lock, and diff checks are clean. Resumption point: commit the six scoped
  files and request another independent cumulative verdict.
- Task 10 bounded fix round 2 committed as `84d1903` (`fix(pilot): enforce site
  authority in operator APIs`). Resumption point: reviewer verifies
  `adc7311..84d1903` and the cumulative Task 10 range; Task 11 remains held.
- Task 10 round-2 re-review confirms the foreign-site JSON list/get/review/
  outbox exploit is closed, but rejected with 0 Critical / 1 Important /
  0 Minor because the event-only audit join hid legitimate same-site camera
  audit records. Bounded fix round 3 is replacing that overcorrection with
  relational site attribution per auditable entity type; unknown/unattributable
  records remain hidden. Task 11 remains held.
- Task 10 bounded fix round 3 uses correlated persisted-relation attribution for
  site, camera, candidate event, evidence, review, notification outbox, and
  delivery-attempt audits. Same-site records remain visible; foreign, unknown,
  and payload-only claimed identities remain hidden without duplicate rows.
- Task 10 round-3 controller verification: focused API/web/security → 67 passed;
  full repository → 653 passed / 2 guarded PostgreSQL skips; full Ruff, offline
  lock, and diff checks are clean. Resumption point: commit the two scoped files
  and request the cumulative independent verdict.
- Task 10 bounded fix round 3 committed as `5e12e0f` (`fix(pilot): preserve
  site-scoped audit history`). Resumption point: reviewer verifies
  `84d1903..5e12e0f` and cumulative `f83af03..5e12e0f`; Task 11 remains held.
- Task 10 final cumulative independent review approved with 0 Critical /
  0 Important / 0 Minor. Reviewer compiled the correlated audit predicates for
  SQLite and PostgreSQL and ran 94 focused tests with one guarded live-
  PostgreSQL skip; Ruff, offline lock, and diff checks are clean. Task 10 is
  closed at `5e12e0f`.
- Task 11 resumption point: dispatch a fresh TDD implementer from
  `task-11-brief.md`; no target-network Telegram delivery will be claimed
  without customer/network approval, and no external notification will be sent
  during local tests.
- Task 10 controller composition review found that the newly authoritative site
  identity did not yet constrain the event table or direct detail/evidence
  routes. A second RED proved a ready foreign-site event appeared in the list
  and that empty/overlong supplied site identities were accepted.
- Task 10 bounded fix round 1 now centralizes pilot-site resolution and applies
  it to health, event-list, detail, and evidence joins. Foreign-site events are
  absent and return generic 404s on direct detail/evidence requests; historical
  same-site events are not hidden solely because a camera is disabled. Supplied
  site identities must contain 1–128 characters.
- Final Task 10 fix verification: web → 30 passed; web/auth/event/security focus
  → 64 passed; full repository → 650 passed / 2 guarded PostgreSQL skips; full
  Ruff, offline lock, and diff check are clean. Resumption point: controller
  exact scoped commit, then a fresh independent re-review before Task 10 closes.
- Task 10 fix round 2 RED reproduced the remaining site-authority gap: the JSON
  camera API returned a foreign camera, while missing/ambiguous API site
  configurations returned 200 rather than a generic 503.
- Task 10 fix round 2 centralizes pilot-site resolution in API dependencies and
  applies it to camera list, event list/get/review, post-review fetch, and
  candidate-event audit list. The repository review transaction now accepts an
  additive optional `expected_site_id` and camera/site-qualifies the same locked
  candidate select that precedes review/audit/outbox writes. Foreign get/review
  returns generic 404 with no mutation; disabled same-site historical events
  remain readable/reviewable.
- Task 10 fix round 2 verification: web/auth/event/security focus → 66 passed;
  full repository → 652 passed / 2 guarded PostgreSQL skips; full Ruff, offline
  lock, and diff check are clean. No commit was created by the fix implementer.
  Resumption point: controller source review and scoped commit, then fresh
  independent re-review before Task 10 closes.
- Task 10 fix round 3 RED proved the candidate-event-only audit join hid valid
  same-site camera and lifecycle audit rows. The correction uses correlated
  persisted-relationship attribution for site, camera, candidate event,
  evidence, review, notification outbox, and delivery attempt entity types.
  Foreign and unknown/payload-claimed rows remain excluded without duplicate
  audit rows.
- Task 10 fix round 3 verification: web/auth/event/security focus → 67 passed;
  full repository → 653 passed / 2 guarded PostgreSQL skips; full Ruff, offline
  lock, and diff check are clean. No commit was created by the fix implementer.
  Resumption point: controller source review and scoped commit, then fresh
  independent re-review before Task 10 closes.
- Task 11 initial RED failed collection with the expected
  `ModuleNotFoundError: No module named 'protector.pilot.notifications'`.
  The authenticated dead-letter view RED separately failed on the absent
  `data-notification-state="dead_letter"` marker.
- Task 11 now implements an immutable safe event view, event-bound expiring
  HMAC application links, an explicit-approval fixed-origin Telegram connector,
  and a finite site-bound at-least-once outbox worker with transactional leases,
  durable attempts, expired-lease recovery, capped exponential retry,
  sanitised failures, delivery audit, and authenticated dead-letter visibility.
- Worker claim and finalisation rebuild authority from persisted event, camera,
  site, confirming review, and active confirmer rows. Outbox payload, event
  reason, review notes, RTSP/source values, evidence object keys, model sources,
  signed links, provider bodies, and arbitrary exception text are excluded from
  connector persistence/audit. Review notes remain on review rows but are no
  longer duplicated into audit payloads.
- Task 11 adversarial TDD closed signed-link `repr`, bot-token path/control,
  token-bearing exception-chain, authoritative worker-site, future scheduling,
  invalid safe-view, and bounded concurrency-wait gaps. The direct corrupt-
  outbox matrix proves disabled, shadow, observation, candidate, rejected, and
  expired state cannot reach a connector; escalated state is also revalidated.
- Task 11 adds additive Alembic revision `0003_notification_delivery` with
  nullable lease identity/expiry and a `(status, available_at,
  lease_expires_at)` claim index. PostgreSQL offline SQL compilation reaches
  the new head; SQLite upgrade coverage verifies the columns/index/revision.
- Task 11 final verification: notifications → 34 passed; related integration
  before the final six-case matrix → 123 passed / 1 guarded PostgreSQL skip;
  full repository → 688 passed / 2 guarded PostgreSQL skips. Full Ruff,
  offline lock, PostgreSQL static migration SQL, and `git diff --check` are
  clean.
- Task 11 report: `task-11-report.md`. No commit, push, deployment, real
  Telegram request, target-network request, or external notification was made.
  Resumption point: controller source review of the uncommitted scoped Task 11
  files, then create `feat(pilot): notify only after authorised confirmation`
  only if review is clean.
- Task 11 controller pre-review found that signed event-detail URLs were issued
  but not consumed by the web route, and that connector-returned authority loss
  dead-lettered without the normal generic failed-attempt audit. Focused REDs
  reproduced exact-expiry acceptance, the missing audit, absent app signer/
  clock injection, and absent safe review-note integrity metadata.
- The bounded correction adds an optional repr-hidden signer and deterministic
  UTC clock to the app context. Authentication remains mandatory; unsigned
  authenticated detail remains valid. Any queried event-detail URL now
  requires the exact event/origin/expiry/signature contract before database
  lookup, with generic data-free 404s for missing signer/fields, extra/tampered
  query, changed event, or `now >= expires`. TTL is one second to 24 hours.
- The authority-loss finalisation path now appends the sanitised
  `notification.delivery_failed` attempt audit before dead-lettering. Both
  review methods retain only `notes_present` plus a SHA-256 note digest in the
  immutable audit; raw notes remain confined to the authoritative review row.
- Task 11 bounded-follow-up verification: exact regressions → 6 passed;
  notification/web/repository → 94 passed / 1 guarded PostgreSQL skip; related
  API/security suite → 131 passed / 1 guarded skip; full repository → 690
  passed / 2 guarded skips. Ruff, offline lock, PostgreSQL static migration SQL,
  and `git diff --check` are clean. No commit or external notification was made.
  Resumption point remains controller source review.
- Task 11 independent review requested 0 Critical / 2 Important / 1 Minor
  corrections: lease expiry was not itself a finalisation fence, the final
  outbound boundary did not bind the persisted model analytic to the event
  module, and signed-link origin parsing accepted malformed/noncanonical
  authorities.
- Task 11 fix round 1 TDD now requires the same token/status plus a non-null
  `lease_expires_at > finalisation_now` for both success and failure. Late
  callbacks leave their row/attempt for normal expired-lease recovery; tests
  cover late success and failure, then a separate recovered attempt owning the
  final delivered state. The late-success case preserves the honest
  at-least-once duplicate-delivery boundary.
- A public fail-closed gate policy now binds authoritative artifact analytics
  to exact pilot event categories. The worker joins `model_artifacts` and
  applies the policy during both claim and finalisation revalidation. Worker
  tests block confirmed/operator fight, fall, violence, X-CLIP, ViT, unknown,
  and the exact persisted `person` artifact plus `fight` event mismatch before
  connector I/O. Restricted-zone/person, intrusion, loitering, line crossing,
  weapon, and fire/smoke approved bindings remain allowed.
- Signed-link origins now require canonical lowercase HTTPS host authorities,
  a valid optional non-default numeric port, no encoded/backslash/whitespace/
  control ambiguity, and no noncanonical host/port spelling. Raw URL parser
  errors are replaced by a generic configuration `ValueError`.
- Task 11 fix-round-1 verification: notification/gates/repository/web focus →
  162 passed / 1 guarded PostgreSQL skip; full repository → 737 passed /
  2 guarded skips. Full Ruff, offline lock, PostgreSQL static migration SQL,
  and `git diff --check` are clean. Report updated:
  `task-11-report.md`. No commit or external notification was made. Resumption
  point: controller source review, then scoped commit and fresh independent
  re-review of the Task 11 fix.
- Task 11 implementation commit: `93b3a8f`
  (`feat(pilot): notify only after authorised confirmation`).
- Task 11 fix round 1 commit: `2c1ab7f`
  (`fix(pilot): fence reviewed notification delivery`).
- Task 11 fix-round independent review (`task-11-review-fix-1.md`) approved
  progression with 0 Critical / 0 Important / 1 parked Minor. It confirmed
  strict expiry fencing, authoritative persisted analytic/event binding at
  claim and finalisation, and canonical origin/port/parser-error hardening.
  Focused review verification: 48 passed; Ruff and exact-range diff checks
  clean.
- Parked Task 11 Minor for whole-branch triage: an application origin ending
  in an empty literal `?` or `#` is accepted and canonicalised away. It creates
  no SSRF, signature, authentication, or authority bypass, but is stricter to
  reject explicitly.
- Task 11 complete locally at `2c1ab7f`. Live PostgreSQL `SKIP LOCKED`
  concurrency and real Telegram delivery require target services plus explicit
  customer/network approval and remain pending. No real notification was sent.
  Resumption point: Task 12 implementation from `task-12-brief.md`.
- Task 12 initial RED failed collection on the missing `protector.pilot.metrics`
  and `protector.pilot.retention` modules. Subsequent behavioral RED cycles
  covered metric validation/snapshot races, health status and exact-site/source
  freshness, retention starvation/multi-evidence state, production metric
  refresh, substituted/reserved evidence inventory, restore extras/member
  bombs, deployment PID limits, and explicit S3 pagination.
- Task 12 now implements isolated low-cardinality Prometheus metrics,
  authenticated generic component health/readiness, a fixed-secret
  production API factory, finite site-scoped mark-before-delete evidence
  retention, signed-KZ-target encrypted backup/fresh restore tooling, a
  hash-locked API-only image, and a hardened internal Compose control plane
  behind TLS. Continuous raw video remains in the customer NVR; no per-camera
  model stack was added.
- Append-only audit history remains untouched. Portable audit pruning is
  explicitly pending because encrypted archive, durable receipt, and safe
  partition/drop machinery do not yet exist. Prometheus retention is bounded
  to 30 days/5 GB; evidence cleanup is finite and site scoped.
- Task 12 verification: metrics/retention focus → 23 passed; full repository →
  760 passed / 2 guarded PostgreSQL skips; full Ruff and offline lock clean;
  PostgreSQL static SQL compiled through `0003_notification_delivery`; shell
  syntax, executable modes, Compose structural assertions, and
  `git diff --check` clean.
- Docker, `age`, `pg_dump`, `pg_restore`, ShellCheck, live PostgreSQL/KZ object
  storage/TLS/Prometheus, and NVIDIA hardware are unavailable locally. Exact
  external commands, fixtures, expected metrics, and pending verdicts are in
  `task-12-report.md`; no service, restore, or capacity acceptance is claimed.
- Task 12 report: `task-12-report.md`. No commit, push, deployment, merge, live
  backup/restore, or production-readiness claim was made. Resumption point:
  controller source review of the scoped uncommitted Task 12 files, then fresh
  independent review; only a clean result may be committed as
  `feat(pilot): harden and observe pilot deployment`.
- Task 12 implementation commit: `3d9c350`
  (`feat(pilot): harden and observe pilot deployment`).
- Task 12 controller verification on `3d9c350`: full repository → 760 passed /
  2 guarded PostgreSQL skips; full Ruff and offline lock clean; PostgreSQL
  static SQL compiled through `0003_notification_delivery`; backup/restore
  shell syntax and executable modes clean; staged diff check clean.
- Task 12 fresh independent review is in progress on exact committed range
  `2c1ab7f..3d9c350`. External Docker/PostgreSQL/KZ storage/TLS/Prometheus/
  NVIDIA/20-camera gates remain pending and no capacity claim is made.
- Task 12 independent review (`task-12-review.md`) requested changes:
  0 Critical / 9 Important / 0 Minor. Findings cover authoritative camera
  health, disconnected runtime/worker telemetry, reconnect counter epochs,
  unscheduled/incomplete evidence+audit retention, replayable storage
  attestations, unsigned restore receipts, non-atomic DB/evidence backup
  consistency, incomplete fresh-database checks, and non-reproducible external
  commands. Reviewer verification: 137 focused tests; Ruff, offline lock,
  shell syntax, Compose parse, and exact-range diff clean.
- Task 12 fix round 1/5 is in progress with the same implementer on
  `3d9c350`; no external gate has been reclassified as passed.
- Task 12 controller source review found that age recipient encryption did not
  authenticate the backup producer and that config/model hashes were stored
  without the reviewed manifests. Focused REDs failed on the absent detached
  checksum signature and absent encrypted manifest artifacts.
- The bounded correction signs the exact fixed-name checksum manifest with the
  external `/run/secrets/backup_signing_private_key`; restore requires exactly
  six encrypted payloads plus checksum/signature and verifies with
  `/run/secrets/backup_signing_public_key` before checksum, decryption, or
  database work. A wholesale artifact replacement with attacker-recomputed
  checksums now fails before age/PostgreSQL tools.
- Encrypted fixed-name config/model manifest copies are checksum/signature
  bound. Restore hashes their decrypted bytes against both the signed backup
  declaration and operator-provided expected hashes before PostgreSQL
  inspection. Fake-tool coverage also preserves downstream extra-file/member-
  bomb checks using explicitly re-authenticated test fixtures.
- The Task 12 external NVIDIA command now uses the real DeepStream entrypoint
  flags `--site-config` and `--runtime-manifest` with explicit read-only
  fixture/secret mounts and a bounded 120-second smoke. Task 13 retains
  ownership of 8-hour replay and 72-hour soak commands/evidence.
- Task 12 remains uncommitted. Resumption point: fresh focused/full/static
  verification of the authenticity correction, controller review, and fresh
  independent Task 12 review before any commit.
- Task 12 controller bounded-disk follow-up added configurable database and
  reviewed-manifest caps (10 GiB/16 MiB defaults; 100 GiB/64 MiB absolute
  ceilings). Backup checks `pg_database_size` before `pg_dump`, then checks
  dump, copied manifests, evidence archive, metadata, and encrypted artifact
  sizes. Restore bounds authenticated ciphertext and every decrypted artifact
  before `pg_restore`.
- Oversize fake-tool coverage uses tiny configured bounds/sparse files to prove
  refusal for database preflight, post-dump expansion, authenticated ciphertext,
  and decrypted dump expansion without creating large fixtures.
- The apparent duplicate schema check was an intermediate-read artifact. The
  current checks are intentionally distinct: signed/decrypted declared revision
  versus operator expectation before mutation, then actual restored
  `alembic_version` integrity after `pg_restore`.
- Final Task 12 post-review verification: focused metrics/retention → 23
  passed; full repository → 760 passed / 2 guarded PostgreSQL skips; full Ruff,
  offline lock, PostgreSQL static SQL through `0003_notification_delivery`,
  shell syntax/executable modes, Compose structural assertions, and
  `git diff --check` all clean. Docker, age, PostgreSQL CLI, ShellCheck, live
  services, KZ storage, NVIDIA, and 20-camera gates remain pending.
- Task 12 resumption point: controller source review of the final uncommitted
  scope and fresh independent Task 12 review; commit only on a clean verdict.
- Task 12 fix round 1 closes independent-review findings I1-I9 and controller
  follow-ups. Authoritative exact-20 health is atomically ingested; telemetry
  is session-aware and wired from runtime/notification workers; evidence and
  append-only audit retention are scheduled; age/OpenSSL archive receipts bind
  exact remote/SSE/KMS identity; storage markers and restore receipts are
  authenticated; DB/object backup consistency and full fresh-database checks
  are enforced; provisioning and shared-runtime measured-capacity gates fail
  closed; Compose has ordered least-privilege roles/services and separate
  fenced egress; backup acquisition, Docker context, secret reads, and
  DeepStream teardown are bounded.
- Task 12 final audit-prune RED proved a repeat call validated source rows after
  they had been intentionally removed. Revision `0004_operational_retention`
  now returns from the locked `pruned_at` receipt before item/scope validation;
  the migration-order regression and full retention module pass.
- Task 12 fix-round verification: pilot suite → 716 passed / 2 guarded skips;
  full repository → 778 passed / 2 guarded skips; full Ruff, offline lock,
  PostgreSQL static SQL through `0004_operational_retention`, backup/restore
  shell syntax, Compose YAML structure, executable modes, and `git diff
  --check` are clean.
- Task 12 external gates remain pending: live PostgreSQL roles/prune and fresh
  restore, Docker build/Compose/TLS/Prometheus, KZ storage and host-firewall
  allowlists, customer-approved notification egress, NVIDIA/L4 DeepStream, and
  a lawful frozen 20-feed corpus. Exact commands and expected metrics are in
  `task-12-report.md`, `deploy/pilot/TARGET_ACCEPTANCE.md`, and
  `deploy/pilot/NETWORK_POLICY.md`. No production or GPU-capacity claim is
  made.
- Task 12 fix round 1 remains uncommitted. Resumption point: controller source
  review, then fresh independent re-review; commit only after a clean verdict.
- Task 12 fix round 1 was committed as `51e022a`
  (`fix(pilot): connect and bound pilot operations`). Its independent review
  (`task-12-review-fix-1.md`) requested 0 Critical / 4 Important / 0 Minor:
  durable retired telemetry authority, authoritative inner capacity bindings,
  an exact immutable target mount contract, and compaction of per-audit
  primary staging rows.
- Task 12 fix round 2 F1 uses one durable monotonic active generation per
  site/publisher. Runtime and notification `A(g1) -> B(g2) -> A(g1)` is
  rejected in-process and after API restart before metrics, components,
  `CameraModel.state`, or health history can mutate. Epoch advancement and
  exact-20 health persistence share one transaction, failed persistence is
  retryable, exact duplicates are no-ops, and the generation-less legacy
  health write fails closed when authoritative telemetry is configured.
- Task 12 fix round 2 F2 binds measured capacity to separately reviewed
  runtime-manifest registry-entry, frozen-workload, and expected-workload
  SHA-256 identities. Recomputing the capacity file's outer SHA after
  tampering any inner identity still fails provisioning and target startup for
  the exact-binding reason before machine-token/GPU access.
- Task 12 fix round 2 F3 adds `runtime-mount-contract.v1` and a bounded
  validator for the immutable captured image ID, three reviewed inputs,
  machine token, one writable evidence spool, 20 unique direct RTSP secret
  files, and hash-matching read-only model/engine/`nvinfer` sources. The
  recorded target command emits 56 deterministic mount argv items without
  reading/printing RTSP values and invokes the inspected image ID, not its
  mutable tag.
- Task 12 fix round 2 F4 adds transaction-scoped PostgreSQL authorization for
  exact receipt-item compaction after verified audit deletion and before the
  final `pruned_at` update. Failed cycles retain retry material; successful
  cycles remove all per-audit primary staging rows while preserving one
  individually bounded signed receipt root per content-addressed archive.
  Compose enforces one 10,000-row batch/hour (at most 24 roots and up to
  240,000 removed audit rows/day). `AUDIT_RETENTION.md` explicitly records
  that the irreducible receipt history is not a zero-growth claim.
- Task 12 fix round 2 final verification: pilot suite → 731 passed /
  2 guarded live-PostgreSQL skips; full repository → 793 passed / 2 guarded
  skips; full Ruff, offline lock, PostgreSQL static SQL through revision 0004
  (654 lines), backup/restore shell syntax, Compose service/network/cadence
  structure, and `git diff --check` are clean.
- Task 12 fix round 2 remains uncommitted. External Docker/PostgreSQL/KZ
  storage/TLS/firewall/NVIDIA/20-camera gates remain pending and no
  production-readiness or GPU-capacity claim is made. Full detail is in
  `task-12-report.md`. Resumption point: controller source review, fresh
  independent task review, then controller-owned commit only on a clean
  verdict.
- Task 12 fix round 2 commit: `6c89a00`
  (`fix(pilot): bind operational acceptance inputs`).
- Task 12 fix-round-2 independent review
  (`task-12-review-fix-2.md`) approved progression with 0 Critical /
  0 Important / 0 Minor. It verified durable bounded telemetry authority,
  independently bound capacity inputs, the immutable exact target mount
  contract, transaction-scoped audit staging compaction, and distinct
  production evidence/audit batch bounds. Reviewer verification: 98 focused
  tests; full repository 798 passed / 2 guarded live-service skips; Ruff,
  offline lock, PostgreSQL static migration SQL, shell syntax, Compose
  structure, and range diff checks clean.
- Task 12 is complete locally at `6c89a00`. Docker/live PostgreSQL/KZ
  storage/TLS/firewall/NVIDIA/real-20-camera gates remain explicitly pending
  and unclaimed. Resumption point: Task 13 implementation from
  `task-13-brief.md`.
- Task 12 fix round 2 controller source review found that Compose's shared
  audit-sized batch value (10,000) reached the evidence coordinator's
  hard-maximum-1,000 constructor after external setup, so the production
  retention process could not start. A second F3 probe found that 20 unique
  camera targets could still alias one host secret source path.
- Focused REDs exercised the actual Compose command through the service parser
  and real coordinator constructors, four invalid CLI boundaries before
  reviewed/external inputs, duplicate camera host sources, and a camera/token
  source collision. All six focused cases failed for the expected absent
  split/isolation behavior before implementation.
- The correction now uses separately bounded
  `--evidence-batch-size=1000` and `--audit-batch-size=10000` on the hourly
  singleton cadence. Argument parsing rejects evidence outside 1..1,000,
  audit outside 1..10,000, and interval outside 5..3,600 before config,
  secret, PostgreSQL, or S3 access. The retention policy documents both
  independent bounds.
- The target mount contract now compares path identities and requires 20
  unique camera host sources disjoint from token, reviewed-input, spool, and
  artifact/config sources. It never opens, compares, or prints RTSP secret
  values.
- Fresh correction verification: new exact cases → 6 passed; retention module
  → 26 passed; DeepStream/mount module → 44 passed; pilot suite → 736 passed /
  2 guarded skips; full repository → 798 passed / 2 guarded skips. Full Ruff,
  offline lock, PostgreSQL static SQL through revision 0004 (654 lines),
  backup/restore shell syntax, exact Compose split controls/network structure,
  and `git diff --check` are clean.
- The full Task 12 fix round 2 remains uncommitted and ready for fresh
  independent review. External gates and all no-production/no-GPU-capacity
  boundaries are unchanged. Resumption point: controller handoff to the
  independent reviewer; controller owns any commit.
- Task 13 initial RED failed at collection because
  `protector.pilot.acceptance` did not exist. The accepted boundary is one
  typed fail-closed manifest/run/report/signature module with narrow replay
  and report CLIs.
- Task 13 now validates the exact 20 lawful sources, canonical hashes,
  independent module dispositions, impossible/secret-like input, observed
  counters, platform thresholds, and complete recovery. Heavy analytics and
  ungated fire/weapon cannot become operator through this tooling.
- The portable runner uses exactly one shared `FakeDataPlane`, drains its real
  observations and health through injected consumers, and refuses to fabricate
  unsupported fault recovery. Its record is permanently `test_only` and
  `contract`, incapable of passing the 8-hour or 72-hour gates.
- Reports use nearest-rank percentiles (`ceil(q*n)`, explicit zero for empty),
  escaped self-contained HTML, canonical JSON bound to the HTML digest, and an
  external OpenSSL Ed25519 detached signature. No key or custom cryptography is
  stored in the repository.
- Task 13 final verification: focused acceptance tests 20 passed; full
  repository 818 passed / 2 guarded live-service skips; full Ruff, offline
  lock, PostgreSQL static SQL through revision 0004, backup/restore shell
  syntax, Compose static structure, script executable modes, and `git diff
  --check` are clean.
- Task 13 external NVIDIA/DeepStream/TensorRT, real exact-20 RTSP/corpus,
  live-service, KZ storage, 8-hour, 72-hour, and signed fire/weapon matrix gates
  remain explicitly pending and unclaimed. Task 13 is uncommitted. Resumption:
  controller source review and fresh independent task review; controller owns
  any commit.
- Task 13 controller correction round 1 removes manufactured portable success:
  the injected consumer now exercises the real EventEngine and PilotMetrics,
  records observation-repository consumption, and emits typed timestamped
  boundary/lifecycle/resource traces. Unexercised evidence/review/notification
  boundaries remain explicitly incomplete.
- Actual camera health publication times and availability are retained;
  extending the contract window for finite fault observations makes health
  stale rather than backdating a success. Portable faults are observed through
  a deterministic non-destructive in-process state machine.
- Target mode now invokes exactly one existing shared DeepStream entrypoint
  with explicit reviewed inputs, no shell, finite timeout, bounded output, and
  requires a bounded non-symlink observed target record bound to the exact
  manifest. No target command was executed locally.
- Correction verification: focused 20 passed; full repository 818 passed /
  2 guarded skips; full Ruff, offline lock, and diff check clean. Task 13
  remains uncommitted for controller re-review.
- Task 13 controller correction round 2 replaces serialized portable fault
  expectations with a finite stateful harness. Source faults exercise the real
  fake runtime/supervisor; runtime and API restarts replace their single shared
  authorities with unique boot IDs; evidence/model/verifier faults mutate
  typed boundaries and queue state. Omitted transitions remain incomplete.
- Target replay now owns exactly one `shell=False` process plus one
  machine-authenticated bounded collector, accepts only exact 8h/72h durations,
  refuses pre-existing output, early exit, missing/badly bound observations,
  unbounded responses/logs, and forced-kill completion, and validates the final
  target/site/manifest/gate record. Exact commands in
  `docs/pilot/ready_to_start.md` match the implemented flags.
- Acceptance success is derived from typed lifecycle, boundary, queue,
  resource, fault, and exact-bound capacity traces. Contradictory summary
  claims, absent latency samples, incomplete queues/recovery, unsupported
  outage exclusions, and unbound capacity evidence fail closed.
- Task 13 correction-round-2 verification: focused acceptance → 32 passed;
  pilot suite → 768 passed / 2 guarded skips; full repository → 830 passed /
  2 guarded skips; full Ruff, offline lock, PostgreSQL static SQL through
  revision 0004, backup/restore shell syntax, Compose 10-service/4-network
  structure, and `git diff --check` clean.
- Task 13 remains uncommitted and review-ready. Target NVIDIA/DeepStream,
  lawful exact-20 sources, the machine-only target collector service, live
  PostgreSQL/KZ storage/TLS/firewall/notification services, signed fire/weapon
  matrices, and actual 8h/72h results remain pending and unclaimed. Resumption:
  controller source review, then a fresh independent Task 13 review.
- Task 13 correction round 3 moves the exact eight-fault schedule and
  state/target policy into acceptance authority. It binds offsets, durations,
  source-index/fixed targets, typed trace identity and order, source-return
  recovery, and distinct runtime/API restart boots; non-UTC timestamps now
  fail instead of being normalized.
- Endurance resource evidence must span exact start/end with <=65-second gaps.
  Record validation enforces append order, unique lifecycle/fault-phase/
  exception identities, current camera/queue boot bindings, normalized secret
  key rejection, and bounded detached signatures before OpenSSL.
- Operator module output now requires a passing target core/capacity run.
  Fire/weapon additionally require an existing authoritative
  `ConditionalModelGateResultV1` whose decision hash, artifact ID, and registry
  entry hash match the manifest. The misleading naked signature boolean was
  removed. The report CLI loads repeatable bounded non-symlink decision JSON
  inputs and rejects duplicate modules; default remains shadow.
- Target final records bind the random collector nonce as `run_id`, blocking
  stale same-binding reuse. Child stdout/stderr are discarded; the global
  4 MiB file limit was removed so bounded evidence/spool files are unaffected.
  Forced kill and early exit remain failures. The site matrix now has pending
  positive and hard-negative rows for both fire and weapon.
- Task 13 correction-round-3 verification: focused acceptance → 44 passed;
  pilot suite → 780 passed / 2 guarded skips; full repository → 842 passed /
  2 guarded skips; full Ruff, offline lock, PostgreSQL static SQL through 0004
  (654 lines), backup/restore shell syntax, Compose 10-service/4-network
  structure, and whitespace/diff checks clean.
- Task 13 remains uncommitted for controller source review and fresh
  independent review. NVIDIA/live exact-20/collector-service/signed
  conditional/8h/72h gates remain external pending and unclaimed.
- Task 13 final append-only signing correction requires all four report targets
  to be absent, refuses regular files and symlinks, publishes via exclusive
  creation, signs through a private bounded temporary, and cleans only
  invocation-created partial artifacts on failure. New and pre-created empty
  directories remain supported.
- Final focused acceptance verification is 46 passed; Ruff and
  tracked/untracked whitespace/diff checks are clean. The prior fresh full-suite
  checkpoint remains 842 passed / 2 guarded skips because this correction was
  isolated to signed-report publication. Task 13 remains uncommitted; resumption
  is controller source review and fresh independent review.
- Task 13 correction round 4 closes independent review C1/C2 and I1-I5. A real
  machine-authenticated FastAPI acceptance authority now journals exact
  start/sample/fault/finalize evidence in an append-only SQLite WAL, survives
  API restart on the same host boot, rejects host-reboot monotonic joins, and
  commands all 16 canonical fault phases. Production wiring requires a
  hash-pinned, non-writable site executable and persistent state mount; partial
  configuration fails closed.
- Start freezes launch, exact 20 camera IDs, per-camera analytic schedules
  (including zero-rate disabled work), and the canonical schedule. Periodic
  samples carry exact 20-camera deltas, health/queue/shared-boot state and
  resources. The authority validates fractional schedules with cumulative
  floors, derives final camera/work/health/queue/resource/boot/fault evidence
  from its journal, and overrides adapter self-assertions.
- Lifecycle camera identity, launch inputs, continuous coverage/accounting,
  analytic allowlists, canonical credential-free references, and signed
  complete conditional gate attestations are now fail-closed. Target
  documentation records the executable contract, persistent UID-10001 state,
  same-boot restart rule, and exact pending hardware gates.
- Round-4 verification: real authority/deployment tests 6 passed; focused
  Task 13/auth 65 passed; pilot 800 passed / 2 guarded skips; full repository
  862 passed / 2 guarded skips; Ruff, offline lock, static Alembic through 0004,
  backup/restore shell syntax, Compose structural parse/wiring, and diff check
  clean. Docker runtime config could not run because Docker is absent.
- External NVIDIA/DeepStream/TensorRT, lawful exact-20 source corpus/feeds,
  live service/storage/network controls, signed site conditional evidence, and
  actual 8-hour/72-hour results remain pending and unclaimed. Resumption point:
  controller source review and fresh independent Task 13 re-review; do not
  commit unless that review is clean.
- Task 13 correction round 5 closes the real-clock, graceful-shutdown,
  finite-journal, URI-scan, analytic-disposition, and adapter-filesystem gaps
  from the whole-range controller audit. Process creation and authority start
  precede the local gate origin; samples use exact scheduled offsets with
  pre/post adapter five-second bounds and authority-owned canonical times.
  Fault state evidence is timestamped after the adapter acknowledgement while
  preserving the separate canonical command offset.
- DeepStream now converts SIGTERM/SIGINT into GLib main-loop quit plus
  guaranteed runtime drain/stop. The target runner finalizes only after a clean
  zero exit. Journal start reserves the entire gate and enforces 10,000
  entries/session, 40,000 globally, four sessions, 2 MiB/entry, and 256 MiB
  database bounds. Operator docs define checkpoint/archive/rotation only
  between verified finalized campaigns.
- Adapter responses reject FIFOs without blocking; work roots must be private
  non-symlink directories with actual API-UID write/search access. URI schemes
  are found anywhere in manifest strings, and all positive scheduled analytics
  require dispositions while known unscheduled shadow modules remain allowed.
- Round-5 verification: focused acceptance/authority/DeepStream 118 passed;
  pilot suite 811 passed / 2 guarded live-service skips; full repository 873
  passed / 2 guarded live-service skips; full Ruff, offline lock, pilot shell
  syntax, Compose 10-service/4-network structure and authority wiring, and
  `git diff --check` are clean.
- Task 13 remains uncommitted for independent source review. CUDA/NVIDIA,
  genuine DeepStream/TensorRT capacity, lawful exact-20 sources, live services,
  signed site conditional evidence, and actual 8h/72h gates remain external
  pending and unclaimed. Resumption point: controller review of round 5; commit
  only on a clean verdict.
- Task 13 independent review rejected commit `400fe18` with 2 Critical and 5
  Important findings. Correction round 6 remains uncommitted. Focused
  authority verification at the latest stable checkpoint is 12 passed in
  150.43 seconds; the prior target/route checkpoint was 20 passed / 60
  deselected. These are partial checkpoints, not approval.
- The correction now binds signed-capacity bytes and trust-key/signature
  hashes, runtime-manifest/image/config/code/mount identities, expected versus
  observed Docker network IDs/config hashes, a random runtime launch nonce,
  and a dedicated acceptance-controller bearer scope. It stages reviewed
  inputs, launches one hardened non-root shared DeepStream container, and has
  removed the impossible image-ID/mount-contract-hash build cycle.
- Adversarial review found additional release blockers that remain in the
  active bounded fix loop: the acceptance controller must be a separate
  loopback service that survives the API-under-test restart; the host runner
  must execute idempotent effects between durable claim and observed commit;
  target manifest and authority-derived run bytes require separate detached
  Ed25519 trust roots; RSA/ECDSA must be rejected; exact GPU
  count/UUID/product/PCI/VRAM/driver/CUDA/MIG identity must replace
  `--gpus all`; source profile/identity must match the frozen workload; queue
  percentiles must gate each camera; GPU/VRAM/disk evidence must be contiguous
  interval high-water data; and cleanup must force-remove every partially
  created container.
- The current code has atomic start plus 16 PREPARED intents, run-scoped
  deterministic command IDs, CLAIMED/COMMITTED journal rows, and retry
  equivalence checks in progress. Do not accept a protocol where the main API
  restarts itself or where ACK initiates the effect. Do not evaluate a raw
  caller-authored target run.
- External gates remain unchanged and unclaimed: CUDA/NVIDIA/DeepStream/
  TensorRT, exact lawful 20-source corpus/RTSP feeds, live PostgreSQL/Kazakhstan
  storage and firewall policy, signed conditional site matrices, actual 8-hour
  replay, actual 72-hour soak, and measured GPU capacity with at least 25%
  headroom. Resumption point: finish correction round 6, run focused/full
  verification, then obtain a fresh xhigh independent Task 13 review with zero
  Critical/Important findings before any controller commit.
- Task 13 correction-round-6 adversarial audit remains open. A read-only
  fault-protocol review rejected the transitional design because the
  API-under-test still owned effects, CLAIMED work was not crash-safe, API
  restart was not recoverable, receipts were self-asserted, and sampling plus
  start/sample/finalize retries were not independently durable. The active
  correction has since moved effect invocation out of ACK and introduced a
  typed external-runner receipt, but separate-controller lifecycle,
  reconciliation across every crash cut, response-loss idempotency, and
  independent sampling still require focused RED/GREEN proof.
- A second read-only audit reproduced two concrete acceptance bypasses against
  the current evaluator: substituting all 20 declared source references and
  stream profiles still passed after rebinding hashes, and arbitrary capacity
  signature/trust-key hashes still passed in a self-consistent caller-authored
  chain. Task 13 must bind ordered source/profile observations and verify
  role-separated detached Ed25519 manifest, capacity, authority-run, and final
  report attestations before review.
- Container audit confirmed and the implementer corrected two cleanup gaps:
  deterministic by-name removal after Docker create timeout/malformed output,
  and cleanup after final run-ID mismatch. The audit still must recheck cleanup
  error preservation, exact target identity, actual restart windows, and the
  completed source/GPU/runtime binding after the edit set stabilizes.
- Task 14 preflight is complete but implementation remains intentionally
  blocked on Task 13 approval. Its TDD scope is five handover/runbook documents,
  an investor-MVP versus controlled-pilot README boundary, a pending-only
  handover manifest/training template, focused documentation regression tests,
  and no fabricated attendance, 72-hour result, capacity, or external-service
  result.
- Task 13 round-6 checkpoint: the main production API no longer exposes
  acceptance routes or accepts acceptance environment configuration. A
  separate loopback-only authenticated controller service owns the acceptance
  surface and persistent journal; focused controller smoke tests pass locally.
- Container reconciliation now observes the complete uncertain-create horizon,
  validates the exact launch label before removal, proves a full consecutive
  absence window after a late create, and surfaces cleanup failure. The direct
  container-runner reconciliation suite is 17 passing at the implementer
  checkpoint; full launch-contract coverage remains pending.
- GPU target identity now selects one exact UUID and observes product, PCI bus,
  integer VRAM, compute capability, disabled MIG, NVIDIA driver, CUDA
  driver/runtime, and host NVIDIA-container-toolkit versions rather than
  filling observed evidence with expected values. It remains fake-tested only
  on this Apple host; no NVIDIA identity or capacity result is claimed.
- Signed manifest/run/capacity inputs, SPKI-based role separation, strict
  Ed25519 rejection, interval high-water resources, per-camera queue
  percentiles, 60-second target cadence, and a bounded 72-hour journal/final
  preflight are in the active edit set. The target-run path is still
  transitional until the dedicated authority derives and signs a deterministic
  final journal root, the full signature chain is reverified, and caller-
  authored raw run signatures are removed.
- Remaining Critical work at this checkpoint: durable runner/controller
  request replay and concurrent effect ownership; response-loss tests for
  start/sample/claim/ack/finalize; authority-derived lifecycle/boundary/
  capacity/exception evidence; exact 20-source negotiated profile evidence;
  signed trust-policy roots; and complete parser-tested target documentation.
- Round-6 SQLite/idempotency audit rejected the transitional journal contract:
  request/results and session reservations are not atomically persisted,
  concurrent fault claims have no durable owner, runner identity/progress is
  memory-only, response loss cannot replay exact committed results, and the
  current pre-commit size check does not reserve aggregate main/WAL/SHM
  headroom. The required correction is additive durable journal/session/request
  state plus a host executor receipt journal that reconciles desired state
  before repeating any effect; focused concurrency, crash-cut, rollback, and
  physical byte-bound tests are specified for the active implementer.
- Boundary regression audit added two Important blockers: every successful
  `ensure_fault` must be followed by an independently captured contradictory-
  sensitive observation, and the controller's SQLite root plus DB/WAL/SHM
  files must reject symlink ancestors, wrong ownership, and group/world-
  writable modes. These findings are in the active Task-13 fix loop; no Task-13
  approval or new commit exists.
- Task-13 target documentation/CLI audit rejected the WIP commands: both
  endurance examples omit the new controller attestation inputs/outputs, use
  container paths from the host, invert controller versus runner privileges,
  omit controller signer provisioning, and present a bare Docker launch that
  bypasses the canonical acceptance runner. It also found a placebo machine-
  token argument, missing reproducible identity-hash preflight, incomplete
  whole-chain verification, missing site FPS/source-index binding, temporary
  runner state, and symlink-ancestor gaps. Exact parser/Compose/mount-contract
  regression tests are required before Task-13 review.
- Current round-6 partial verification only: the evolving signed-report suite
  is 69 passed in 27.94 seconds, the dedicated controller smoke suite is 2
  passed, and changed acceptance modules compile with `git diff --check`
  clean. This is not Task-13 approval; durability/source/docs RED tests and
  focused authority verification remain pending.
- Trust/source red-team rejected the stable WIP on two Critical and three
  Important findings. The final report trust root is not yet independently
  pinned as part of a full manifest/capacity/run/report policy; actual resolved
  source identity and native negotiated FPS/bitrate/profile drift are not yet
  authority-bound; target attestation verification omits schedule/root/count
  proof; signed YAML/attestation canonical-byte rules are incomplete; and the
  injected process-factory seam bypasses target source validation. The audit
  confirmed ordered source indices, portable target-secret refusal, no-follow
  input paths, post-final sealing/root recheck, and the acyclic final
  attestation flow in the latest edits.
- Source-index/FPS migration initially regressed the existing config fixtures;
  after updating the canonical fixtures and 20-camera example, focused config
  plus DeepStream graph verification is 65 passed in 0.97 seconds. Native
  resolved-source HMAC and epoch-bound CAPS/bitrate evidence remain open.
- Scale audit found a valid 72-hour run can create 259,201 variable queue-age
  runs per camera, exceeding the current 100,000-run/final-record bounds, and
  that the per-sample authority path repeatedly scans/verifies the full growing
  journal (quadratic over 4,321 samples). Fixed bounded conservative queue
  aggregation, exact-60-second authority enforcement, indexed session cursors,
  physical main/WAL/SHM headroom, and a full-size no-sleep benchmark are
  required.
- The queue-size blocker is corrected in principle with conservative upward
  1 ms aggregation and a >2 s failure bucket (at most 2,002 bins/camera).
  Scale review still rejects approval because normal sampling repeatedly
  decodes/verifies the entire growing chain, controller cadence is not yet
  literal 60 seconds, final-body limits disagree at 32/64 MiB, queue cadence
  permits aggregate-counter overflow, and post-write physical enforcement
  omits SHM. Direct 72-hour-equivalent size/count and O(1)-sample-read tests
  remain required.
- Crash-cut re-review confirms request-size routing, post-final sealing,
  exact-duration sample ceilings, observer/executor identity separation, and
  SHM accounting are corrected, with seven focused tests passing. It still
  rejects Task 13: PREPARED effects lack cross-process CAS ownership and can
  repeat after crash; the CLI always launches a new nonce/container before it
  can replay/retrieve durable work; session reservations are not persisted
  atomically; retry equivalence permits omitted/changed evidence; physical
  byte caps are pre-commit rather than guaranteed post-commit; and runner
  journal ancestors are not securely revalidated/opened on every connection.
- Round-6 performance checkpoint: after exact-60/gate ceilings, incremental
  hash verification, O(1) sample cursor reads, and bounded queue aggregation,
  the stable end-to-end simulated 8-hour authority test passes 1/1 in 14.71
  seconds (previous failed after about 194 seconds). Config plus DeepStream
  remains 65 passed. These are partial results; the crash-cut, trust, native
  source, reservation, byte-cap, and documentation blockers above remain.
- Round-6 recovery checkpoint: focused runner/journal recovery verification is
  11 passed / 79 deselected. The host runner now holds a process-wide campaign
  lock for the complete invocation, refuses an incomplete durable campaign
  before process launch, and recovers a committed final envelope before
  generating a new launch nonce. This remains a partial checkpoint: the
  existing crash-resume test proves observe/ensure/observe ordering but does
  not yet prove exactly one physical mutation across the post-effect,
  pre-receipt crash cut.
- The live authority atomicity audit confirms the new transactional reservation
  table blocks a second 72-hour reservation under a 500 MiB aggregate budget.
  It also found a warm-cache tamper bypass: mutating a previously verified
  row's payload while leaving the cached head row unchanged is returned without
  rehashing. Cached verification must remain amortized O(1) in normal operation
  while detecting historical database mutation, and concurrent exact retries
  must replay deterministic committed responses.
- Native-source preflight confirms target identity/profile acceptance is still
  nominal-only: the manifest binds a Docker-secret path and declared values,
  the observer can echo those values, and the injected process-factory seam
  skips the target-source check. Required work remains an opaque site-keyed
  resolved-source identity, native DeepStream/GStreamer CAPS plus measured
  frame/byte windows, epoch/drift/gap latching, bounded deltas, and validation
  before every process-launch seam.
- The native-source design review specifies the portable implementation:
  domain-separated HMAC-SHA256 commitments over the resolved RTSP secret plus
  site/camera/index; a pure-Python per-epoch profile tracker fed only by native
  rtspsrc/parser/decoder CAPS and buffer probes; a minimum 60-second measured
  frame/byte window; exact codec/resolution and signed FPS/bitrate ranges;
  bounded sequential profile cursors/deltas; reconnect, source-time regression,
  CAPS drift, gap, replay, or overflow failure; and runtime-only key mounting.
  The prewarm latch happens before the gate clock so the 60-second quality
  window does not falsify the 30-second RTSP recovery metric. Hardware behavior
  remains pending NVIDIA validation.
- Crash/atomicity implementer handoff is frozen without commit. Controller
  reproduction is 18 passed in 24.35 seconds; the complete current
  acceptance-report/runner suite is 76 passed in 20.02 seconds; focused Ruff
  and `git diff --check` are clean. Completed-final recovery now precedes
  process launch, incomplete campaigns fail before launch, a full-campaign
  cross-process lock is held, and the stateful reconciliation test proves one
  mutation across the covered crash-resume path.
- Independent atomicity review still rejects the block on three Important
  durability defects: a committed append can grow SQLite main+WAL+SHM beyond
  the configured cap because enforcement occurs inside the pre-commit
  transaction; the raw verified-entry cache can consume roughly 270 MiB for a
  72-hour run under the 512 MiB controller limit; and a finalize request for an
  invalid/nonexistent session is persisted before session validation. A fresh
  bounded TDD implementer owns only these corrections before trust work.
- Independent canonical-artifact review rejects Task 13 on two Criticals: no
  external immutable root-signed policy pins all role keys, and the signed
  journal root/count lacks an exported replayable proof consumed by report
  verification. Important follow-ups are strict duplicate-key/canonical-byte
  parsing, private signer-key permissions, exact executable-role separation,
  full review-bundle verification, and parser-executable 8h/72h documentation
  commands. No hardware result is claimed.
- Fresh authority-durability TDD reproduced the pre-fix failures: an
  exact-cap append committed 12,392 bytes past the physical SQLite ceiling,
  the verified raw-payload cache retained unbounded history, and premature
  finalize persisted a request before validating a session. The correction is
  now frozen for independent review: it reserves retained WAL plus a
  conservative full-page next-commit projection before mutation with cache
  spilling disabled; treats checkpointing as cleanup only; caps trusted raw
  cache at 2 MiB and per-session sample JSON at 64 MiB; streams verified
  samples into compact evidence aggregates; validates finalize before binding;
  and replays exact sealed operations plus committed final evidence read-only
  across restart/reboot.
- Root reproduction for that frozen correction is 30 authority/controller
  tests passed in 33.18 seconds, with focused Ruff and `git diff --check`
  clean. This is not Task-13 approval until the independent reviewer finishes
  the retained-reader/consecutive-commit, reservation, tamper, peak-memory,
  invalid-finalize, sealed-retry, and reboot-retrieval attack probes.
- Atomicity review resolved the physical cap, reservations, tamper handling,
  streaming finalization, sealed retries, and reboot retrieval, but found a
  valid 72-hour profile needed 70,865,674 sample bytes. The aggregate ceiling
  is corrected from 64 MiB to 128 MiB and the durable reservation now uses the
  enforced aggregate cap; authority/controller/report verification is 107
  passed in 47.70 seconds with Ruff and diff checks clean.
- One Important atomicity blocker remains: pathname check, `sqlite3.connect`,
  pathname recheck can be raced by swapping in an attacker database and
  restoring the legitimate path before the second check. The active fix must
  pre-open no-follow, pin main/WAL/SHM identities, attest the actual descriptors
  opened by SQLite under a connect lock, and fail closed where descriptor-path
  inspection is unavailable. A pathname-only recheck is not sufficient.
- The first descriptor-level inode correction rejects deterministic
  main/WAL/SHM swap attacks and unsupported descriptor-inspection platforms,
  but independent review found a new Important ordinary-concurrency defect:
  8 threads performing 25 `entry_count` reads produced 4 false
  `connected inode does not match its path` failures. The before/after
  process-wide descriptor delta is racy because other SQLite connections close
  outside `_SQLITE_CONNECT_LOCK` and descriptor numbers can disappear or be
  reused. The atomicity block remains rejected pending a RED regression test
  and an attestation design that is independent of fragile process-global
  descriptor deltas while preserving exact swap rejection and concurrent
  reads.
- A follow-up patch made eight-way journal-only concurrency pass by treating
  the no-follow pre-open descriptor as a trusted before-inventory entry, but
  root adversarial testing still rejects it: four unrelated threads repeatedly
  opening/closing a separate regular file caused all four journal reader
  threads to fail with `connected inode does not match its path`. Therefore
  rejecting every process-global descriptor delta remains an unsafe primitive.
  The next correction must bind attestation to the journal connection (or an
  equivalently isolated ownership mechanism), and its regression suite must
  combine journal concurrency with unrelated regular-descriptor churn.
- Independent platform analysis confirms stock Python `sqlite3` exposes no
  connection-specific main/WAL/SHM descriptor identity. Exact per-connection
  attribution would require a native VFS; undocumented CPython-layout `ctypes`
  is rejected. The bounded portable alternative under review is an explicit
  target privilege/mount boundary: provision main/WAL/SHM ahead of time as
  individually writable files inside a parent namespace the runtime UID cannot
  rename, with the host orchestrator/root outside the runtime threat boundary.
  Target startup must fail if that immutability contract is absent. Portable
  tests may simulate the boundary with a non-writable directory, and unrelated
  process descriptors must have no effect.
- The root-trust advisory froze the next Task-13 TDD contract. Target artifacts
  move to canonical duplicate-free JSON and an offline-root-signed
  `AcceptanceTrustPolicyV1` that pins six pairwise-distinct SPKIs (root plus
  manifest, capacity, run, report, and conditional roles), exact site/campaign,
  gates, validity, and manifest bytes. The policy pins the manifest; the
  manifest must not pin the policy, avoiding a hash cycle. A streaming
  canonical JSONL journal proof binds all 531 (8h) or 4,371 (72h) entries and is
  signed indirectly by the run attestation. A self-contained bounded review
  bundle must reverify root→policy→roles→artifacts→proof→attestation, rerun
  `evaluate_acceptance`, and exact-compare JSON/HTML using only the external
  root SPKI fingerprint as trust input.
- The atomicity implementer replaced the rejected descriptor scan with the
  explicit protected-namespace contract. Portable journals may create their
  own files but cannot be paired with a signer. Signed target journals require
  a precreated main/WAL/SHM triplet, a root/provisioner-owned parent not
  writable by runtime UID 10001, runtime-owned one-link mode-0600 files, and
  pinned identities revalidated before and after every connection. The image
  supplies the root-owned namespace and Compose mounts the three writable files
  individually; a signed attestation records
  `journal_namespace_mode=protected`. Focused swap, incomplete namespace,
  lifecycle, cap, and descriptor-churn tests pass repeatedly. Combined
  authority/controller/report evidence is 117 passed in 62.50 seconds; Ruff
  and diff checks are clean. This block is frozen pending fresh independent
  review.
- Independent namespace review rejects that first protected implementation on
  one Critical: its remaining raw main-file witness descriptor is closed while
  other SQLite connections may hold process-scoped POSIX locks, which can
  release those locks and risk corruption. Protected mode must use only pinned
  pathname identities because the immutable namespace already prevents
  replacement. Important hardening also requires three same-device files,
  Compose long bind syntax with `create_host_path: false`, protected-mode FD
  churn plus held-writer/integrity/hash-chain tests, and an explicit pending
  Linux three-file-bind kill/restart smoke because Docker is unavailable on
  this M2 host.
- The lock-safety correction is frozen for final re-review. All journal
  connections now avoid raw same-inode witness descriptors and use pinned
  `lstat` identities before/after connection; protected namespace immutability
  supplies the target replacement boundary, while portable mode is explicitly
  non-signing. The triplet must share one device. Compose uses long bind syntax
  with `create_host_path: false`. A protected `BEGIN IMMEDIATE`/subprocess
  exclusion test runs alongside four readers and four unrelated FD churners,
  then verifies `PRAGMA integrity_check` and the journal hash chain. Five
  focused repetitions passed 12 tests each; combined
  authority/controller/report is 119 passed in 83.52 seconds, with Ruff and
  diff checks clean. The extracted Linux smoke passes `bash -n`; actual
  retained-WAL file-bind kill/restart remains explicitly pending because this
  host has no Docker CLI.
- Independent final atomicity/namespace review is approved with zero Critical,
  Important, or Minor findings. Fresh reviewer evidence: the focused matrix
  passed 15 tests three consecutive times; authority/controller/report passed
  119 tests in 88.62 seconds; Ruff, `git diff --check`, and the exact external
  smoke `bash -n` check are clean. The external Linux/Docker retained-WAL
  bind-mount run remains a truthful pending target gate. Resume at the
  root-signed trust-policy and replayable-proof slice.
- Trust-policy preflight requires two distinct results: immutable
  `VerifiedAcceptanceTrustV1` snapshots the externally anchored chain without
  authorizing a new run, while `ExecutionTrustGrantV1` additionally enforces
  expected site/campaign/gate and that both start and gate end fall inside the
  root-signed validity window. Historical verification after expiry must never
  be accepted as a controller execution grant. Target manifest bytes are
  canonical JSON and are pinned as `manifest_payload_sha256`; the manifest must
  not contain the policy hash.
- Journal-proof preflight selects a target-only V2 attestation/final envelope
  while leaving the run-record model intact. Canonical JSONL has one header,
  exactly 531/4,371 typed chain entries for 8h/72h, and one trailer; it binds
  the protected namespace, policy/campaign/manifest/launch/execution/schedule,
  exact kind/identity counts, journal root, and final-record hash without
  embedding its own digest or attestation. Export and verification must be
  streaming and crash-recoverable, V1 must be rejected in the target/report
  lane, and the dedicated controller must stream only an authenticated sealed
  proof whose exact digest/size are in V2.
- The first trust-policy GREEN checkpoint reached 108 adversarial tests, but
  the independent exact-byte capture review rejects the slice on two Critical
  defects: path validation was detached from the descriptor walk and the
  capture did not revalidate every retained directory edge or the leaf's
  parent-relative identity. It also requires generic label-only OS failures
  without chained secret paths and stronger mutation tests. The implementer is
  closing this bounded review before the trust slice can be frozen.
- Controller/runner trust-integration preflight is complete. Both processes
  must independently verify the offline-root chain; only the external root
  SPKI fingerprint is a trust input. A locally constructed immutable trust
  binding (root/policy/campaign/manifest) and manifest-derived launch/workloads
  must be exact-compared at start. Production signing derives its expected run
  key only from the policy and requires a runtime-owned single-link mode-0600
  private key. Injected launchers may not bypass source, mount, or observed-GPU
  checks. Target recovery and reporting must reject the V1 no-proof downgrade.
- The corrected trust-policy/captured-byte slice is frozen without a commit for
  fresh independent review. Implementer evidence: 130 focused tests passed
  with one root-only foreign-owner skip; 139 existing acceptance, report,
  controller, and config tests passed; full requested Ruff scope and
  `git diff --check` are clean. The frozen contract now includes typed exact
  canonical manifests, root-authenticated distinct role keys, separate
  timeless/execution/historical results, full-gate validity, strict JSON/YAML,
  and component-pinned mutation-safe byte capture.
- A read-only acceptance-math audit found six Critical and one Important
  false-pass classes that survive stronger signatures: lifecycle evidence is
  not bound to module mode/operator/audit and queued-attempted delivery stages;
  evidence-ready lacks object/hash/bytes/duration/playability identity and
  sufficient run coverage; cross-camera checks omit tracker/analytic state and
  cannot serialize an honest leakage failure; queue capacities/coverage are
  mutable and final-only; disk limits are observer-declared with no plateau
  gate; extra boot identities outside canonical restart faults pass; and
  conditional module dispositions may be omitted. These are parked as a
  mandatory Task-13 metrics-schema correction after the root-trust integration
  boundary is approved.
- Offline review-bundle preflight is complete. Target reports are currently
  self-rooted and cannot be approved until a fixed-inventory bounded bundle is
  verified using only the external offline-root SPKI fingerprint, replays the
  V2 journal proof, historically verifies the full execution interval, reruns
  a version-frozen evaluator, exact-compares the signed report, and
  deterministically rerenders HTML. The bundle must include public artifacts
  only, use the policy-pinned report role, publish atomically without
  replacement after self-verification, cap total size at 384 MiB and proof at
  272 MiB, and distinguish valid failed gates from corrupt/untrusted evidence.
- Fresh trust review rejects the first freeze on five Important findings and
  opened bounded fix round 1/5: restricted YAML accepts uppercase/null and
  legacy numeric spellings as strings that downstream validation can coerce;
  the verified typed manifest is shallow-frozen because each source's
  `analytics_hz` dictionary remains mutable after signature verification; and
  JSON/YAML parse or validation failures preserve attacker-controlled keys,
  values, credentials, and newlines in exception text/causes. Historical
  verification also permits a run that has not ended, and Ed25519 helpers
  accept a valid first PEM followed by an unauthenticated second key/garbage
  while retaining the whole blob as verified key material. The original
  implementer is adding exhaustive RED cases, deep immutable schedules,
  content-independent suppressed errors, completed-interval checks, and an
  exact single-public-key encoding boundary.
- The original round-1 follow-up produced no filesystem delta or test evidence
  after repeated checkpoints and was interrupted without changes. A fresh
  bounded TDD implementer now owns the same five-item review correction; no
  scope or verdict was lost.
- Native source/profile audit reports C5/I5/M1. Target identity currently
  hashes only secret filenames and claimed scalars; the observer can self-claim
  negotiated properties; there is no 60-second native prewarm, sticky
  timestamp/profile failure, bounded epoch/delta chain, or thread-safe probe
  ownership; and injected launchers bypass source/GPU checks. The accepted
  correction is a portable locked `NativeSourceProfileTracker`, site-keyed
  domain-separated HMAC commitments over resolved sources, native RTP/parser/
  decoder CAPS plus integer frame/byte/timestamp deltas, exact signed
  codec/resolution and FPS/bitrate ranges, sticky continuity faults, fresh
  60-second readiness per epoch before the gate clock, and mandatory observed
  identity even for fakes. Raw URLs/HMAC bytes must never persist or serialize;
  actual 20-source GStreamer/NVDEC behavior remains a pending NVIDIA gate.
- Trust fix round 1/5 is frozen without a commit for fresh re-review. RED
  evidence covered 31 initial failures, nine expanded YAML/Pydantic scalar
  failures, two canonical-encoder surrogate leaks, and one detached-artifact
  key-retention failure. GREEN evidence: 181 trust tests passed with one
  root-only skip; 139 authority/controller/report/config tests and 82
  provisioning/report-helper tests passed; relevant Ruff and diff checks are
  clean. The correction deep-freezes manifest schedules, suppresses all
  attacker-derived parser context, orders historical verification after gate
  completion, and canonicalizes only a fully consumed single Ed25519 public
  key.
- Trust re-review rejects round 1 at C0/I2/M0 and opened fix round 2/5. The
  YAML guard misses leading-dot exponent/underscore spellings such as `.5e2`
  and `.5e_2`; a generated family test is required while quoted controls remain
  strings. Separately, `canonical_json_bytes` is non-injective because
  `json.dumps` silently coerces integer, null, and boolean mapping keys to the
  same bytes as string keys; every nested non-string object key must be
  rejected before signing. The other four prior findings and sole-root/path
  capture boundaries cleared three independent rereviews.
- Trust fix round 2/5 is frozen without a commit for a fresh reviewer. Eight
  focused REDs covered the generated leading-dot exponent/underscore family
  and recursive non-string keys through mappings, sequences, and BaseModels.
  GREEN evidence: 189 trust tests passed with one root-only skip; 139
  authority/controller/report/config tests passed; relevant Ruff and diff
  checks are clean. Quoted YAML controls and canonical `1e2` remain valid;
  signing JSON now rejects nested key coercion with constant suppressed errors.
- Controller-only trust TDD map is complete. Target authorities get one frozen
  boot context and an exact `AcceptanceTrustBindingV1`; every request and
  stored session must match it. New starts exact-compare the locally projected
  signed manifest and authorize once, before mutation, at one server timestamp;
  exact stored retries reconstruct the original grant and remain read-only
  after policy expiry. Production exposes no signer/clock/trust overrides or
  free run-key fingerprint. The runtime-owned mode-0600 one-link PKCS#8
  Ed25519 key must be descriptor-captured, fully consumed, and match the policy
  run role. Authenticated readiness probes trust/signer/journal consistency
  without reauthorizing at current time; Compose uses fixed long read-only
  mounts with `create_host_path: false`.
- Independent trust round-2 review is approved at C0/I0/M0. Reviewer generated
  1,089 forbidden YAML variants (all rejected with 1,089 quoted controls
  preserved), nine nested non-string-key collision graphs, and reran prior
  exploit/root/path probes. Evidence: 189 trust tests passed with one root-only
  skip; 139 authority/controller/report/config tests passed; Ruff and diff
  checks are clean. Resume at controller-only offline-root integration; trust
  primitives remain uncommitted as part of Task 13.
- Metrics-schema correction design preserves `AcceptanceRunRecordV1` and proof
  line counts but adds target-only, manifest-bound limits and exhaustive typed
  operational evidence. The authority—not an arbitrary final candidate—must
  derive queue coverage, per-camera tracker/analytic namespace isolation,
  frozen per-store budgets and retention plateau/drills, exact canonical
  runtime/API restart transitions, and complete event/evidence/review/audit/
  outbox/attempt rows from a bounded repeatable-read observer snapshot. Twenty
  explicitly tagged workflow drills (one per camera) prove evidence/review
  plumbing without fabricating model accuracy; all real candidates remain
  exhaustively covered. Both `fire_smoke` and `weapon` require explicit
  operator/shadow/disabled dispositions even when unscheduled. Portable
  contract fixtures may omit this block but can never pass a target gate.
- Task 13 resumed with maximum safe parallelism for non-overlapping files.
  The controller/offline-root implementer continues the authority, production
  builder, signer-key, readiness, and Compose slice. A fresh xhigh TDD
  implementer owns only the portable native source-profile tracker and focused
  tests; another fresh xhigh TDD implementer owns only a new operational
  evidence/evaluator module and focused tests. Neither new slice may touch the
  controller/trust integration files, and neither may commit before an
  independent review. The superseded stalled trust implementer terminated
  without filesystem changes.
- The controller/offline-root integration slice is frozen without a commit for
  independent review. The focused trust-controller suite passes 23 tests; the
  broader trust, authority, controller, report, and config bundle passes 351
  tests with one root-only skip; authority/controller alone passes 43 tests.
  Scoped Ruff and `git diff --check` are clean. During the bounded fix loop,
  two obsolete tests that relied on the deliberately removed production
  injection API were replaced with sealed-builder assertions, while a genuine
  portable finalized-retry regression was corrected. A fresh xhigh reviewer
  now owns the frozen boundary and must return C0/I0 before integration.
- The isolated native source-profile primitive is frozen without a commit for
  fresh independent review. RED first failed collection because the module did
  not exist, then a strict non-integer/non-positive counter case failed before
  validation was added. GREEN evidence is 18 focused tests, scoped Ruff,
  compileall, tracked and untracked whitespace checks; root also reproduced a
  combined 48/48 source-profile and operational-evidence pass. The frozen
  primitive covers exact ordered 20-source identity, secret-free
  domain-separated commitments, native callback provenance, immutable bounded
  epoch deltas, sticky continuity/profile failures, and the all-source
  60-second prewarm boundary. DeepStream/runner wiring remains intentionally
  outside this isolated slice.
- The isolated operational-evidence schema/evaluator is frozen without a
  commit for fresh independent review. RED first failed on the missing module
  and then exposed orphan notification/object namespace and boot-timeline
  holes. GREEN evidence is 30 focused tests plus scoped Ruff, compile, and
  whitespace checks. Its public seam is
  `evaluate_operational_acceptance(limits, evidence, environment=...)`; target
  omission fails closed while portable `test_only` omission is explicitly
  `not_evaluated`. Exact endpoint coverage, canonical five-queue capacities,
  20-camera tracker/analytic isolation, per-store plateau/retention drills,
  exhaustive lifecycle rows, exact 20 plumbing drills, restart transitions,
  and explicit fire/weapon dispositions are all encoded. A fresh xhigh
  reviewer is attacking coercion, coverage, aliasing, and false-pass edges.
- Controller/offline-root review rejects the first freeze at C1/I1/M0 and
  opens bounded fix round 1/5. The target replay client never propagated the
  exact trust binding to start/sample/fault/finalize requests, so the reviewed
  production authority would reject every real collector request. Separately,
  the controller joined the shared control network despite its documented
  loopback-only boundary. The implementer is adding an offline-root-derived
  binding seam with end-to-end request coverage and moving the controller to a
  dedicated internal network with no peer services. Reviewer evidence before
  the fix was 255 focused passes with one skip, Ruff/diff clean; the broad
  suite had 1,154 passes and 43 unrelated model-promotion fixture failures.
- Native source-profile review rejects the first freeze at C3/I4/M0 and opens
  bounded fix round 1/5. Signed expectation containers were caller-mutable;
  callback capabilities were forgeable/mutable across cameras; readiness
  ignored stale peers; two endpoints could masquerade as continuous prewarm;
  invalid Unicode could retain a raw credential URL in an exception;
  monotonic-time enforcement missed repeated CAPS and epoch restart; and a
  dropped callback stranded the source. The implementer is adding owned
  immutable expectations, opaque immutable per-bind capabilities, all-source
  freshness and continuous cadence, content-independent URL failures, a
  tracker-wide time high-water, and finalizer-safe callback lifecycle.
- Operational-evidence review rejects the first freeze at C3/I4/M0 and opens
  bounded fix round 1/5. Repository coverage was self-claimed rather than
  anchored to an authority snapshot; staircase/sawtooth disk growth and
  artifact-budget mismatches passed; namespace rows were unordered and not
  manifest-owned; Pydantic coercion remained enabled; lifecycle rows could
  occur after the run or out of order; several artifact/audit/drill identities
  could be reused; and reordered arrays changed the digest while still
  passing. The implementer is adding distinct repository boundaries/query
  binding, robust weighted retention-window plateau math, exact namespace
  limits, strict validation, ordered in-run lifecycle, complete uniqueness,
  and canonical sequence validation.
- The 43 failures seen by the broad controller reviewer were reproduced and
  root-caused under the systematic-debugging workflow: the shared
  model-promotion `SiteConfig` fixture had not been updated when exact
  `source_index` and `fps` became mandatory feed fields. Adding the canonical
  zero-based index and a 25 Hz fixture value restored the complete
  `test_model_promotion.py` file to 55/55 passes. This was fixture drift, not a
  relaxation of the production schema.
- Controller trust fix round 1/5 is frozen without a commit for a fresh
  re-review. `AuthenticatedTargetCollector.start` now requires the typed
  verified authority context, exact-compares it with signed start inputs,
  derives the nested binding only from that context, and preserves it through
  every durable HTTP request and retry. Compose now gives the controller a
  dedicated internal `acceptance-loopback` network with no peer service while
  preserving explicit host-loopback publication and authenticated readiness.
  Evidence: 25 focused tests, 408 broad passes with one skip, scoped Ruff and
  diff checks clean. A fresh xhigh reviewer is reproducing both prior exploits
  and rechecking the original sealed production boundary.
- Native source-profile fix round 1/5 is frozen without a commit for a fresh
  re-review. RED evidence reproduced seven original exploit groups, then added
  readiness revocation on non-decoder callbacks, legitimate cross-camera
  timestamp interleaving versus future poisoning, far-future bind rejection,
  and 20-thread callback exercise. The fix owns its immutable signed
  expectations, uses opaque immutable weakref-finalized leases, derives
  continuous cadence from signed FPS/profile with a one-second ceiling,
  checks all-peer freshness on every native callback, suppresses Unicode URL
  failures, and separates per-source ordering from the epoch restart
  high-water. Evidence: 29 focused and 59 combined passes, scoped Ruff,
  compile, and whitespace checks clean. A fresh xhigh reviewer now attacks the
  corrected boundary.
- Operational-evidence fix round 1/5 is frozen without a commit for a fresh
  re-review. Twenty-five of the first 57 adversarial cases failed against the
  old implementation, plus a follow-up canonical coverage-array exploit, and
  all now pass. Limits own exact ordered namespace expectations and repository
  source/query/start watermark; target evaluation separately requires an
  authoritative final boundary with row/order/snapshot digests. Weighted RLE
  retention-window envelopes reject staircase, rounding, and growing sawtooth
  traces while allowing a bounded cycle; evidence artifacts reconcile to
  signed object/store budgets. Models are strict, lifecycle rows are ordered
  within the run, identifiers are unique, arbitrary manifest camera order is
  preserved exactly, and unknown environments reject. Evidence: 68 focused
  and 97 combined passes, scoped Ruff, compile, and whitespace checks clean.
  A fresh xhigh reviewer now reproduces every prior false pass.
- Controller trust re-review rejects fix round 1 at C1/I0/M0 and opens bounded
  fix round 2/5. Although binding propagation and network isolation cleared,
  the collector relied on `isinstance` for verification provenance. Both the
  verified-trust and context dataclasses were publicly constructible, so a
  fake root, signatures, and self-consistent context reached the HTTP start
  boundary. The correction must make verified trust mintable only through the
  real offline-root verifier (with field-bound provenance), require it in
  context construction/authorization/collector use, reject copied provenance
  on altered fields, and replace direct-forgery test fixtures with genuine
  verified chains. Reviewer evidence was 28 focused and 409 broad passes with
  one skip; the prior Compose finding remained fixed.
- The first fresh source-profile re-review produced no verdict because its
  turn was stopped by an unrelated safety-classifier false positive before
  review output. It made no filesystem changes. A replacement fresh xhigh
  reviewer is checking the same frozen source/profile boundary under a narrow
  runtime correctness brief; approval is still required and no finding was
  waived.
- Replacement source-profile re-review rejects fix round 1 at C0/I3/M0 and
  opens bounded fix round 2/5. Rejected same-source payloads advanced callback
  and epoch high-water before their later validation; subnormal positive FPS
  overflowed continuity arithmetic; and unbounded Python integers in counters
  and timestamps could enter the first snapshot and make serialization fail.
  The correction separates non-mutating timestamp checks from commit-after-
  acceptance, gives FPS total bounded arithmetic, and constrains all native
  counters/times/generations to conservative signed-integer ranges. Reviewer
  evidence was 29 focused passes with Ruff, compile, and diff checks clean.
- Operational-evidence re-review rejects fix round 1 at C2/I4/M0 and opens
  bounded fix round 2/5. Min/max envelopes ignored RLE overlap weights, so a
  rising high-value duty cycle passed; evidence byte reconciliation omitted
  fixed store overhead. Actual 30/365-day retention could not coexist with the
  two-window proof; identity uniqueness missed cross-kind aliases and duplicate
  content hashes; a wrong repository-boundary type raised `AttributeError`;
  and worst-case plateau evaluation admitted billions of span scans. The
  correction adds exact weighted window sums, fixed-overhead accounting, a
  separate manifest-bound plateau observation window while retaining real
  retention drills, one global identity namespace, deterministic runtime type
  failure, and a bounded linear two-pointer aggregation. Reviewer evidence was
  68 focused and 97 combined passes with static checks clean before the fix.
- Native source-profile fix round 2/5 is frozen without a commit for a fresh
  re-review. Eight targeted RED cases showed FPS/integer bounds and six
  rejected-payload time reservations. Callback time validation is now
  non-mutating until the complete native payload succeeds; rejected decoder
  data no longer consumes its pending parser. Signed/observed FPS has a 1 Hz
  floor, and every external/internal counter, timestamp, generation, bind,
  epoch, stale, and delta input is bounded to signed-int64 with checked
  increments. Evidence: 38 focused and 106 combined passes, scoped Ruff,
  compile, and whitespace checks clean. A fresh xhigh reviewer is checking
  pre-mutation failure and maximum-bound serialization.
- Native source-profile re-review rejects fix round 2 at C0/I3/M0 and opens
  bounded fix round 3/5. A rejected source identity in `bind_source` reserves
  restart time before its commitment is verified; generation overflow can
  partially mutate accepted CAPS or epoch/restart state before event creation
  fails; and exported failure/delta/snapshot record constructors do not bound
  their integer fields, so oversized values can escape validation and even
  break JSON serialization. The correction must validate commitment before
  timestamp commit, reserve generation capacity before any state mutation,
  and enforce signed-int64 bounds across every exported record. Reviewer
  evidence was 38 focused and 106 combined passes with static checks clean.
- Operational-evidence fix round 2/5 is frozen without a commit for fresh
  independent re-review. Nineteen original exploit cases and one scanner-bound
  case were RED. The correction separates manifest-bound plateau observation
  windows from actual 30/365-day retention, requires 2–10,000 complete
  post-warmup windows, computes exact RLE overlap-weighted integer sums and
  cross-multiplied trends in linear time, reconciles fixed overhead plus
  artifacts and object counts, enforces global workflow/artifact identity and
  content-hash uniqueness, and fails closed on a wrong authoritative boundary
  type. Evidence: 111 focused and 149 combined passes; Ruff, format, compile,
  and whitespace checks clean.
- The next journal-proof slice is preflighted but must not start until a slot
  clears. It keeps `AcceptanceRunRecordV1`, introduces target-only
  `TargetRunAttestationV2` plus `acceptance-final-envelope.v2`, and rejects the
  V1 no-proof form in target collection/reporting. The canonical JSONL proof
  is exactly header + every verified raw journal row + trailer: 533 lines for
  8h (531 entries) and 4,373 for 72h (4,371 entries), with exact kind counts
  `start=1,sample=481/4321,fault_intent=16,fault_claim=16,fault_ack=16,
  finalize=1`. Entry hashes must factor the journal's existing injective
  chain-hash function; export and verification use SQL/file cursors without
  `fetchall`, whole-proof buffering, or per-sample expansion. The trailer binds
  final-record hash/root/count but excludes proof/attestation digests to avoid
  a cycle; V2 binds proof SHA-256, bytes, line count, and kind counts. A
  private descriptor-relative proof store must use exclusive temporary
  creation, file and directory `fsync`, no-replace publication, deterministic
  crash recovery, a 272 MiB cap, and authenticated sealed-only streaming.
- Native source-profile fix round 3/5 is frozen without a commit for fresh
  independent re-review. Four adversarial REDs reproduced identity-rejection
  time reservation, CAPS and epoch generation-overflow partial mutation, and
  bool/oversized integers in exported records. The fix verifies identity
  before committing restart high-water, preflights event generation and
  checked increments before every mutation (including stale fan-out), and
  applies signed-int64/non-bool validation to failure, delta, source-snapshot,
  and tracker-snapshot records. Evidence: 43 focused and 154 combined passes;
  scoped Ruff, compile, and tracked/untracked whitespace checks clean.
- Controller trust fix round 2/5 is frozen without a commit for a fresh
  independent re-review. Verified trust and authority context are sealed and
  carry process-local domain-separated HMAC provenance over injectively
  named/length-framed exact fields; every authorization, historical verifier,
  context builder, authority consumer, and collector start revalidates the
  receipt. The collector accepts verified trust plus configured identifiers
  and rebuilds context before token, journal, or network activity. Forged test
  fixtures now use real OpenSSL-generated chains through the production
  verifier. Evidence: 27 controller-trust, 310 trust/authority/controller/
  report (one skip), and 412 required broad tests (one skip); Ruff and diff
  checks clean. Proof/bundle integration remains deliberately outside this
  frozen boundary.
- Operational-evidence re-review rejects fix round 2 at C0/I4/M1 and opens
  bounded fix round 3/5. A non-divisible plateau window can leave almost one
  whole growing tail unscanned; independent byte/object maxima can fabricate
  an inventory combination never observed simultaneously; retention drills
  are not bounded by signed per-object/store limits; and the claimed global
  identifier namespace omits camera/state, retention namespace, and restart
  fault identities. Canonical RLE also permits adjacent identical spans
  (Minor). Prior weighted duty-cycle, fixed-overhead, duplicate-hash, boundary
  type, linear scan, and actual-retention fixes remain cleared. Reviewer
  evidence was 154 combined passes with static checks clean.
- Native source-profile round-3 reviewer produced a substantive rejection
  checkpoint before an unrelated safety-classifier failure terminated its
  final response. It reproduced two Important classes: a wrong-identity bind
  still returns a callback that can later submit valid CAPS and reserve time,
  and exported records validate integer fields but not nested/type/enum/string
  structure, allowing accepted objects whose `to_dict`/JSON conversion raises.
  It also reproduced caller-retained-object risks: a post-construction
  `object.__setattr__` can retarget an expectation retained by the tracker, and
  a shared observation reachable from a snapshot can be changed before the
  next callback. Generation-boundary paths were atomic in its checkpoint. The
  review is being resumed under a narrow correctness-only brief; no finding is
  waived and round 4 waits for the complete verdict.
- Cross-slice integration preflight identifies a required authority boundary:
  the runner must never submit a freely chosen `AcceptanceLimitsV1`. Static
  queue/store/retention/repository-query/namespace/disposition policy belongs
  in (or is deterministically projected from) the offline-root-pinned
  manifest; dynamic start/end, boot transitions, repository high-water, and
  lifecycle rows are authority-derived from the verified session and a
  bounded reviewed observer snapshot. The existing dynamic
  `AcceptanceLimitsV1` cannot itself be called “manifest-owned” until that
  projection exists. Likewise, native prewarm/profile output must be obtained
  from the pinned runtime/observer before authority start and exact-compared to
  the signed source projection; injected process factories must provide the
  same typed evidence and cannot trigger the current expected-value fallback.
- Operational-evidence fix round 3/5 is frozen without a commit for fresh
  independent re-review. RED comprised 45 failures: 38 identity-alias
  permutations plus tail coverage/reset, joint inventory, signed retention
  budget, and non-maximal RLE cases. The final plateau window now absorbs the
  trailing remainder while every analyzed window retains at least the
  configured size and total post-warmup weight is exact; the linear bound is
  retained. Artifact bytes/objects must coexist in one observed span,
  retention claims are bounded by signed object/store limits, manifest
  camera/state/fault plus evidence retention/lifecycle identifiers share one
  exact registry, and adjacent identical spans are rejected. Evidence: 155
  focused and 198 combined passes; Ruff, format, compile, diff, and whitespace
  checks clean.
- Controller trust re-review rejects fix round 2 at C2/I1/M0 and opens bounded
  fix round 3/5. The default target runner constructs its collector without
  verified trust, so production start deterministically fails. Completed-run
  recovery occurs before offline-root verification and accepts a detached
  caller-key chain, while the optional-trust collector reads its token and
  creates its journal before eventually rejecting at start. The HMAC sealing,
  mutation/copy/subclass/process-replay cases, crypto parsing, and Compose
  network isolation cleared. Reviewer evidence: 337 focused passes with one
  skip, the pilot suite 1,291 passes with three skips, and static checks clean;
  Docker Compose runtime validation remains unavailable on this host.
- The resumed native source-profile round-3 review remained stalled after its
  concrete rejection checkpoint and was interrupted so the fix loop could
  proceed; no edits were made and no finding was waived. Fix round 4/5 owns
  four reproduced correctness classes: a wrong-identity callback remains
  usable; exported records accept invalid structural/nested values whose
  serialization raises; the tracker retains caller-owned expectation/CAPS
  objects that can be altered after validation; and snapshots/delta reads
  expose nested objects shared with live internal state. Generation max/max-1
  mutation paths were independently checked as atomic at the checkpoint.
- Operational-evidence re-review rejects fix round 3 at C0/I3/M0 and opens
  bounded fix round 4/5. Artifact reconciliation accepts any historical joint
  inventory rather than the final/post-ready inventory; adjacent window means
  are phase-sensitive and falsely reject a stationary 30-low/30-high cycle
  when the signed window is 70 samples; and the identity owner registry still
  omits site, repository/storage, boot, and principal identities. All prior
  tail, scanner, retention, RLE, boundary, and original alias fixes cleared,
  including a 3,000-case naïve scanner equivalence check. Evidence: 155
  focused and 462 combined passes with one skip; static checks clean.
- Native source-profile fix round 4/5 is frozen without a commit for fresh
  independent re-review. Eight RED cases reproduced the four retained
  correctness classes: usable wrong-identity callbacks, caller-owned
  expectation/CAPS objects, shared snapshot/delta graphs, and structurally
  invalid exported records. Wrong-identity capabilities are now inert except
  for safe lease close/finalization; expectations and accepted CAPS are
  reconstructed and owned; exported records require exact bounded nested
  types, event vocabulary, ordering, ownership, and cross-field invariants;
  and every observation/state/failure/delta read is detached from live state.
  Evidence: 52 focused and 207 source-plus-operational passes; scoped Ruff,
  compile, and whitespace checks clean. Frozen SHA-256:
  `source_profile.py=0dddcc624aab0c8a90c335b0d3d1e8f68ac8aa466e01bc28778a372515110193`,
  `test_source_profile.py=e60a92c57512eb605b4c7e6e480bc0cb765274fb37a1e847b25563cbe29a7fea`.
- Controller trust fix round 3/5 is frozen without a commit for fresh
  independent re-review. The target runner independently verifies the
  external offline root, policy, five distinct role keys, and manifest before
  campaign lock, collector state, token, completed-run recovery, process, or
  network activity; exact site/campaign/gate and duration are enforced.
  Default collector construction requires verified trust and derives the run
  key from it; detached target manifest/run/capacity roots are removed.
  Temporary V1 recovery now exact-compares the durable start trust binding and
  verifies the final run signature with the policy-pinned run role. Target CLI
  documentation and exact Compose healthcheck structure were updated.
  Evidence: 34 target, 28 controller-trust, 85 report, 422 integrated (one
  skip), and 1,389 pilot tests (three skips); Ruff, compile, Compose YAML,
  and diff checks clean. Journal proof/bundle V2 remains deliberately pending.
- Native source-profile re-review rejects fix round 4 at C0/I8/M1 and opens
  the final bounded fix round 5/5. Reproduced Important classes are:
  `object.__setattr__` capability transplantation from a valid callback into a
  wrong-identity callback; mutable shared `StrEnum` internals corrupting live
  failure serialization; accepted impossible state/profile/delta
  cross-fields (zero-generation verified identity, inconsistent one-sample
  baselines, unbounded ready max-gap, epoch after generation, ready
  bind/close events); hostile `str` subclasses and traceback locals retaining
  raw URL/key material; and close/finalizer generation exhaustion consuming
  the finalizer while leaving the source bound. The Minor is scoped Ruff
  formatting. Focused evidence remained 52 passing; combined failures were
  confined to concurrently changing operational-jitter RED tests. No source
  files were edited by the reviewer.
- Operational-evidence fix round 4/5 is frozen without a commit for fresh
  independent re-review. Final artifact inventory must be jointly present in
  the final evidence-store observation. Phase-sensitive adjacent means were
  replaced by a single-pass exact-integer OLS invariant over every
  post-warmup sample: a positive fitted end-to-end rise is material only when
  it exceeds `5 * observed_range / sqrt(sample_count)`. Periodic and bounded
  aperiodic jitter controls across phase/window offsets pass, while rising
  duty cycle, growing sawtooth/staircase, one-byte-per-window and linear
  growth, and tail-reset growth still fail. The semantic-owner registry now
  treats site, repository source, both stores, all boot IDs, principals, and
  prior domains distinctly while allowing explicit lifecycle foreign keys;
  153 cross-domain alias permutations are covered. Evidence: 257 focused and
  573 combined passes with one skip; Ruff, format, compile, and whitespace
  checks clean. Frozen SHA-256:
  `acceptance_operational.py=eda5d9de4ec66d611e2dc6f45172ab6f1f92cfe79da5414dd3616961950de1e7`,
  `test_acceptance_operational.py=4339a1d9fba95e315eb584a8a3a2f9866e367980f1c8f0e3e4c85174a7f69085`.
  Fresh review must specifically attack weak sustained drift and outlier
  widening of the `5R/sqrt(N)` tolerance.
- Controller-trust re-review rejects fix round 3 at C0/I1/M1 and opens bounded
  fix round 4/5. The offline-root, role separation, pre-I/O ordering,
  mandatory collector trust, root-authenticated V1 recovery, and Compose
  isolation survived every adversarial probe. However, both documented 8h and
  72h replay blocks omit required adapter work-root, observer, durable
  collector-state, attestation-output, and signature-output arguments, so
  `target_command` rejects them; both following report blocks omit the
  parser-required run attestation. The scoped Python files also fail the Ruff
  format check (Minor). Reviewer evidence was 347 focused passes with one
  skip, Ruff lint/compile/YAML/diff clean. The broad pilot run was contaminated
  only by concurrent source-profile edits and is not used as a verdict.
- Operational-evidence re-review rejects fix round 4 at C0/I3/M0 and opens the
  final bounded fix round 5/5. The exact OLS rule admits sustained growth when
  an early, interior, or late outlier widens its range; it also admits drift
  superimposed on bounded byte and object cycles, while falsely rejecting a
  stationary 82-sample square cycle at some phases. Final aggregate evidence
  inventory is not strictly later than artifact readiness and is not
  identity-bound, allowing a retention drill to delete an acceptance artifact
  whose bytes/count are only represented by an aggregate. Round 5 must add
  acceptance-level REDs for every reproduced phase/outlier/metric case,
  preserve exact canonical-RLE bounded traversal and stationary jitter, require
  a demonstrably post-ready final snapshot, and separate retention-object and
  acceptance-artifact identities. Reviewer evidence: 257 focused and 636
  combined passes with one skip, 30,000 OLS and 3,000 scanner reference
  comparisons, and clean Ruff/format/compile/diff checks. Frozen hashes were
  unchanged and the reviewer made no edits.
- Native source-profile final bounded fix round 5/5 is frozen without a
  commit for independent review. Callback authority is bound to the live
  handle object through state-held weak references while a distinct close
  lease preserves safe finalization; exported failure codes are immutable
  exact string objects; reachable snapshot/delta and continuity projection
  invariants are enforced; secret-bearing public entry points encapsulate and
  overwrite URL/key arguments before fallible work and clear their holders on
  every exit; and generation reservations cover explicit close, GC close,
  twenty handles, and restart boundaries. Evidence: 83 focused, 340 combined,
  and 30 adversarial mutation/traceback/thread/GC tests passed; scoped
  Ruff/format/compile/diff and untracked whitespace checks passed. Frozen
  SHA-256:
  `source_profile.py=cd9845f1499cc23601f936bfd1331f5bd0aa9b6b86185099afc89666444114ab`,
  `test_source_profile.py=f0cd9f83c2e66965229c697473e9cdaa02facbf399af6abb7973f2a20056831c`.
- Controller-trust documentation fix round 4/5 is frozen without a commit for
  independent review. Both 8h and 72h host commands now carry the complete
  offline-root chain and five roles, launch/network/execution/schedule
  artifacts, adapter and observer inputs/work roots, distinct durable
  collector state, token, and record/attestation/signature outputs; each
  following report command consumes its exact gate outputs. Container-only
  verify paths were replaced with documented host paths, and external
  NVIDIA/twenty-source results remain explicitly pending. RED was five missing
  argument failures plus two container-path failures. Evidence: 7 focused,
  91 report, and 353 trust/controller/report tests passed with one skip;
  scoped Ruff lint/format, compile, YAML, and diff checks passed. Frozen
  SHA-256: `ready_to_start.md=8f400ae59f35a1beb348babac3ed93508ac486b32cd1ad0b9b9444849e467d0a`,
  `test_acceptance_report.py=a93a4972e54e42f6bf1bfdfc424630b648525a3b9ec08d01b1fe1aad26669fdf`.
- Native source-profile round-5 re-review rejects the frozen fix at C0/I3/M1.
  Exported failure-code class constants remain mutable through ordinary and
  `type.__setattr__`; changing/deleting one can make a wrong-identity bind fail
  after setting `bound=True` but before reserving its close, leaving a wedged
  source. Public records accept impossible arithmetic (`baseline >
  max_gap*(observations-1)`, cumulative counters below observation count, and
  terminal clocks below baseline), and readiness is not biconditional or
  bounded to the 60-second epoch timeline. Tracker construction also clones an
  arbitrarily large tuple/iterable before checking exact-20 cardinality.
  Callback provenance, secret traceback clearing, hostile URLs, INT64
  close/GC/restart behavior, and randomized state transitions otherwise
  cleared. Evidence: 83 focused and 446 combined passes; static checks clean;
  hashes unchanged; reviewer made no edits. The mandatory post-round
  correctness repair must isolate the internal failure vocabulary and be
  rollback-safe, enforce exact reachable arithmetic/readiness, and reject
  non-exact/oversized expectation containers before cloning.
- Operational-evidence final bounded fix round 5/5 is frozen without a commit
  for independent re-review. Trend detection now uses an exact-integer
  canonical-RLE bounded-lag delta-mass traversal (at most 128 lags and 10,000
  input runs, no sample expansion) with one positive/negative extreme trimmed
  per lag. It rejects all reproduced outlier-hidden and cycle-plus-drift byte
  and object cases while accepting every phase of the stationary 82-sample
  cycle and prior jitter controls. The signed evidence contract now carries a
  strictly later final evidence-store observation with aggregate and live
  object identity binding; retention/live-artifact aliases and non-strict
  lifecycle order are refused. Evidence: 363 focused and 716 combined tests
  passed with one skip; Ruff format/check, compile, and diff checks passed.
  Frozen SHA-256:
  `acceptance_operational.py=d62882ecb8fbb72a3333c2c7b97d32f49ddf4e714edc818a4dd6f5606e44f82d`,
  `test_acceptance_operational.py=9ea0b895c2b38d76cb8819f44c73682fb4db722ffbe8c9cb4f96537477a81da6`.
- Operational-evidence round-5 re-review rejects the frozen fix at C2/I2/M0.
  Full-evaluator probes show that two outliers can hide linear byte/object
  growth, and a period-200 growing sawtooth is invisible beyond the fixed
  128-lag horizon. The final live inventory binds only aggregate counts and
  keys, so it cannot prove each ready artifact's digest and size, need not
  follow the complete terminal lifecycle, and retention object paths remain
  outside the global semantic-owner registry. The mandatory post-round
  correctness repair must use a robust full-horizon bounded-RLE trend test,
  bind exact `(object_key, sha256, byte_size, storage_identity)` inventory
  rows strictly after all lifecycle rows, and register every object identity.
  Evidence: 363 focused and 446 combined passes, 3,000 randomized scanner
  equivalence checks, bounded 10,000-run timing, and clean static checks.
  Frozen hashes were unchanged and the reviewer made no edits.
- The read-only native/runtime integration audit found that the frozen tracker
  is not yet connected to GStreamer/DeepStream or target authority: declared
  profile hashes and observer-echoed negotiated values can stand in for native
  evidence, process-factory launch evidence is untyped, expected GPU identity
  is used as a missing-observation fallback, and gate collection starts without
  the required native 60-second prewarm. The final operational limits/evidence
  remain partly caller-selected and are not evaluated by the target authority.
  The queued integration slice must add a bounded secret-free native probe
  adapter, source-bin CAPS/parser/decoder/NTP wiring and rebuild leases, a
  provenance-bearing manifest-derived static policy, typed real/fake process
  evidence with no GPU fallback, authority-owned dynamic run facts, and
  operational evaluation before signing. Portable contracts are implementable
  here; actual RTSP/NTP/NVDEC/twenty-stream behavior remains an explicit
  NVIDIA-only gate. The audit made no edits or claims about hardware results.
- Controller-trust documentation fix round 4 is approved at C0/I0/M0. All 12
  frozen hashes matched before and after review; both documented gate
  workflows parse and bind exact gate-specific artifacts; 32 trust adversaries,
  313 focused tests (one root-only skip), and 40 authority tests passed.
  Explicit V1 recovery mutations to trust, launch, execution, and schedule
  fail closed before relaunch/output. Ruff/format/compile, eight YAML files,
  and whitespace checks are clean. Both external NVIDIA/twenty-source verdicts
  remain PENDING. The reviewer made no edits; V1 is accepted only as the
  interim base for the queued journal-proof V2 slice.
- Operational-evidence post-round correctness repair is frozen without a
  commit for fresh independent review. Seventeen evaluator-level REDs covered
  two/clustered outliers hiding linear byte/object growth, period-200 recurring
  drift, all terminal lifecycle classes at the exact END timestamp,
  retention/ready-path aliases, and missing/aliased typed live-inventory rows;
  209 existing controls remained green before implementation. The fixed
  detector combines an exact weighted full-horizon rank statistic with a
  strict-majority paired-quantile translation check over canonical RLE, with no
  sample expansion or fixed lag/outlier count. Final inventory now binds exact
  ordered key/hash/size/store rows at the final scheduled sample strictly after
  all lifecycle rows, and object paths join the global owner registry.
  Evidence: 634 focused and 746 combined source/operational tests passed;
  Ruff format/check, compile, and whitespace checks are clean. Frozen SHA-256:
  `acceptance_operational.py=2c33c937b0260ad67251474925d6a8f9375713d53499a0a2997a04ade57a75eb`,
  `test_acceptance_operational.py=548ea4f8322ab59007d0655cecc3508ad328e39c092f3b855c9b72dbd8e89745`.
- Native source-profile post-round correctness repair is frozen without a
  commit for fresh independent review. Twenty-three REDs reproduced mutable
  public failure constants (including type-level bypass), wrong-identity
  half-binds and injected constructor failures, non-exact/oversized
  expectation containers, unreachable state arithmetic, forged false
  readiness/timelines, and two-sample 60-second readiness. Public codes are now
  synthesized canonically while internal branches use private literals;
  binding preconstructs its callback/ref/candidate/failures/reservation/delta
  before atomic publication; state arithmetic uses checked int64 operations;
  readiness is biconditional and uses the maximum current observation for
  staggered callbacks; exact built-in container length is checked before
  access. Evidence: 112 focused and 746 combined source/operational tests
  passed; Ruff format/check, compile, whitespace, and diff checks are clean.
  Controller independently reconfirmed the 112 focused passes and hashes.
  Frozen SHA-256:
  `source_profile.py=12f0a50270c192deb6d80005064d586923f2955ab753cf2b692a7a6696f2e66c`,
  `test_source_profile.py=cc6beec7f969a18814332c9c46f61486709a200d23f165565ac996dd16018351`.
- Operational-evidence post-round re-review rejects the frozen repair at
  C2/I2/M0. The full evaluator still accepts material period-129 byte/object
  growth and monotonic growth confined to the final 51 samples, while it
  falsely rejects a bounded one-time step followed by a stable plateau.
  Separately, fight/fall/violence/X-CLIP/ViT dispositions can be set to
  operator and drive a confirmed delivered notification, violating the
  shadow-only boundary. Prevalidated final live-artifact rows are also retained
  by identity, so caller mutation can alter the supposedly frozen signed
  graph. All prior exact-inventory, lifecycle, and owner-registry fixes remain
  covered. Evidence: 634 focused and 746 combined passes, 3,000 randomized
  reference comparisons, bounded 10,000-run checks, and clean static checks;
  frozen hashes were unchanged and the reviewer made no edits. The next
  correctness repair must replace the distribution-only trend inference with
  lifecycle/sequence-aware bounded-growth evidence, hard-ban heavy operator
  modes, and explicitly own nested final rows.
- Native source-profile post-round re-review rejects the frozen repair at
  C0/I4/M1. Exported snapshots can claim a generation below the minimum
  epoch/bind/CAPS/observation/failure history, omit `profile_mismatch` after an
  unverified callback generation, and consume INT64 while bound callbacks still
  require reserved closes. Per-source NTP/timestamp counters and baselines can
  be below the minimum implied by strictly advancing observations. Ready
  snapshots can separate sources beyond even the globally permitted 300-second
  stale bound because the signed per-source stale limit is not projected.
  Standalone failures can occur at the epoch-start generation, and failure
  tuples are cloned before vocabulary-derived cardinality checks. Mutation
  proof, transactional bind/GC/retry, exact expectation containers, secret
  scrubbing, detachment, and randomized transitions cleared. Evidence: 112
  focused and 746 combined passes with clean static checks; frozen hashes were
  unchanged and the reviewer made no edits. The next correctness repair must
  make chronology/reservation/staleness projections and failure bounds exact.
- Task 13 journal-proof V2 correction is frozen without a commit for fresh
  independent review. The protected authority now streams an exact bounded
  canonical JSONL hash-chain proof; the typed header binds launch, execution,
  the ordered 20-camera set, and the canonical fault schedule; the signed V2
  attestation binds proof/root/count/trust/run evidence. Controller download,
  exact no-replace publication, durable completed-final recovery, complete
  offline-root report inputs, and evaluator reexecution all fail closed.
  Additional RED/GREEN coverage closes mutation-during-hash and raced
  replacement cleanup windows. Evidence: 380 clean scoped passes with one
  guarded skip, 12 proof-unit passes, clean Ruff/format/compile/diff checks,
  and static Compose YAML at 11 services/5 networks/15 acceptance-controller
  volumes. Docker, CUDA/NVIDIA, lawful exact-20 sources, and real 8h/72h runs
  remain external PENDING gates; no capacity or production-readiness claim is
  made. Core frozen hashes are recorded in `task-13-report.md`.
- Native source-profile chronology/reservation/staleness correctness repair is
  frozen without a commit for fresh independent review. Eighteen focused REDs
  exercised provable minimum generations, required mismatch history, callback
  generation headroom, per-source counter/baseline chronology, signed
  staleness projection, standalone failure chronology, and bounded failure
  cloning. Evidence: 18/18 focused GREEN, 130 full source-profile passes, and
  983 combined source-profile/operational passes; Ruff format/check,
  compileall, and tracked/untracked whitespace checks are clean. Frozen
  SHA-256:
  `source_profile.py=7c2b3c39aa1c726aeb39aa5bcb80e221e0bae72a36d6e9443e661208a07948c5`,
  `test_source_profile.py=cdf3148316656a5c7a93e8c154bed0a2119ad2575fbada5948c55a99244a2442`.
  Fresh independent adversarial review is active; no hardware claim is made.
- Operational-evidence sequence/ownership correctness repair is frozen without
  a commit for fresh independent review. It uses bounded canonical-RLE
  sequence evidence for translated recurrence, exact stable one-transition
  plateaus, and late growth; hard-bans fight/fall/violence/X-CLIP/ViT operator
  paths at disposition, event, evaluator, and notification boundaries; and
  deeply owns final artifact inventory rows. Evidence: 988 combined
  source-profile/operational passes, 1,500 seeded randomized probes, and a
  10,000-run/10-million-sample guard at 0.358 seconds and 2.415 MiB peak;
  Ruff and whitespace checks are clean. Frozen SHA-256:
  `acceptance_operational.py=8d282c844639f0e1f24d6334d67f27d25fd9792f38e9ae9e83c3461ff0ccbd31`,
  `test_acceptance_operational.py=18e058e530d4e962da3afbde2d72a2ebaf1863c3c48463d78fdf892796c55e98`.
  Fresh independent adversarial review is active.
- Native source-profile chronology re-review rejects the frozen repair at
  C0/I3/M0. A closed wrong-identity callback can omit its sticky
  `profile_mismatch`; failure codes can claim unreachable state/generation
  provenance (including callback failures on never-bound sources); and a
  staggered exact-20 snapshot can backdate readiness before the last source
  could first complete its prewarm. Focused 130 and combined 988 tests passed;
  Ruff/format/compile/diff checks were clean; the frozen hashes matched and the
  reviewer made no edits. The mandatory correctness repair must bind sticky
  identity/failure provenance and the earliest reachable all-source readiness
  time without rejecting legitimate post-ready observations.
- Operational-evidence re-review rejects the frozen repair at C2/I3/M1.
  Full-evaluator probes still accept long period-200 translated byte/object
  growth and rising-duty growth; post-validation noncanonical heavy-module
  aliases can enter operator notification; stationary irregular cycles are
  phase-dependent false failures; late downward and multi-step traces evade
  exact-one-transition plateau semantics; and a prevalidated outer final-store
  observation remains caller-mutable by identity. Focused 858 and combined
  988 tests passed; the 10,000-run/10-million-sample guard stayed bounded at
  0.3493 seconds/2.415 MiB; lint/compile/diff passed, while scoped Ruff format
  failed. Frozen hashes matched and the reviewer made no edits. Mandatory
  correctness repair is active for sequence proof, evaluator revalidation,
  and deep outer ownership.
- Task 13 journal-proof V2 re-review rejects the frozen correction at
  C0/I2/M1. The target collector consumed a wrong-origin HTTP response body
  before validating its final URL, and the record/attestation/signature
  publishers (unlike the proof publisher) used path-based parent checks and
  link/unlink cleanup vulnerable to symlinked ancestors and parent-swap races.
  A scoped Ruff format check also contradicted the recorded clean claim for
  `test_auth_api.py`; the apparent duplicate durable-journal lookup was only
  overlapping display output and is not a finding. Evidence: 380 scoped
  passes with one root-only skip; lint/compile/YAML/diff and Compose static
  checks otherwise clean; frozen hashes matched and the reviewer made no
  edits. Mandatory correction is active for pre-body origin validation and
  descriptor-relative preflight/publication of all four artifacts.
- Task 13 journal-proof publication correctness repair is frozen without a
  commit for fresh independent re-review. RED evidence was 12 failures/one
  already-green control across hostile response status/origin/path/query/
  fragment/credentials, symlink ancestry, four-target preflight, parent swap,
  temp replacement, and race-winner preservation. The collector now validates
  the exact response URL/status before reading; all four outputs share
  descriptor-relative pinned-parent batch preflight, exact append-only
  publication, and identity-safe cleanup. Evidence: 393 scoped passes with one
  root-only skip, 12 proof-unit passes, 13 adversarial passes, clean Ruff
  lint/format, compileall, whitespace, and Compose static checks. Frozen core
  SHA-256:
  `replay_20.py=ec484811fad02955851565f7876952052feb14a544be52ec3653551681eb3679`;
  complete round-7 hashes are in `task-13-report.md`. Docker/NVIDIA execution
  remains external and unclaimed.
- Native source-profile provenance/readiness correction is frozen without a
  commit for fresh independent re-review. The tracker now records the actual
  generation that begins each epoch, assigns code-specific earliest reachable
  failure generations, makes the first per-camera prewarm-completion timestamp
  sticky, and derives all-source readiness from the exact latest completion.
  Exact-threshold, bounded-jitter, restart, wrong-identity close, later-NTP,
  and forged-provenance cases are covered. Evidence: 145 focused passes and an
  exact-hash combined run of 1,042 source/operational passes in 242.16 seconds;
  Ruff lint/format, compileall, and whitespace checks are clean. Frozen
  SHA-256:
  `source_profile.py=588841f9100ed16dadc3d96b161c5c9229e200387a794139877589a581ebaf12`,
  `test_source_profile.py=3ebe7e9409ebf1609756218d12eacb66bcffb24c40687287b28ea789399f820d`.
  A fresh reviewer who did not implement this slice is active.
- Operational-evidence recurrence/ownership correction is frozen without a
  commit for fresh independent re-review. The evaluator now classifies
  complete stationary/translated recurrence across the full canonical-RLE
  suffix (including periods beyond 128), admits only a completed stable
  one-transition nonrecurring plateau, revalidates exact types and heavy-module
  vocabulary at evaluation boundaries, and deeply clones the retained outer
  final-store observation. Evidence: 897 focused passes and the same
  exact-hash combined run of 1,042 passes; 2,000 seeded randomized probes; and
  a 10,000-run/10-million-sample guard at 0.3967 seconds and 2.568 MiB peak
  with exactly 10,000 traversals. Ruff lint/format, compileall, and whitespace
  checks are clean. Frozen SHA-256:
  `acceptance_operational.py=30b805105edc8333539ab069c79f71ef03d00768c2d18984a01b87b813034c83`,
  `test_acceptance_operational.py=a2797d6096b853dd5c02fa30f13cec608a322d7a7b490215c54d87d2d9325758`.
  A fresh reviewer who did not implement this slice is active.
- The final read-only target-integration audit rejects any
  acceptance-readiness claim until four sequential TDD slices are complete:
  (A) a GStreamer-free primitive-only source-probe bridge with generation-owned
  leases and an exact-20 native prewarm receipt; (B) DeepStream RTP/parser/
  decoder/NvDs-NTP wiring plus transactional camera-local lease rebuild; (C)
  versioned static manifest policy, a typed target-process/factory contract,
  mandatory observed GPU identity, and prewarm-before-collector ordering; and
  (D) authority-owned repository/restart/run evidence with both standard and
  operational evaluators executed before finalize, proof export, or signature.
  V1 canonical bytes must remain unchanged; new target runs require V2,
  incomplete V1 campaigns cannot resume under V2 semantics, evaluator versions
  are frozen, and a fresh gate-specific authority database is required. The
  audit made no edits. Native RTCP/NTP, NVDEC, exact GPU identity, twenty lawful
  sources, eight-hour replay, and 72-hour soak remain external PENDING gates.
- Native source-profile provenance re-review rejects the frozen repair at
  C2/I0/M0. A real source limited by a 0.985x NTP clock first completed at
  60.08 seconds, yet a consistently reconstructed aggregate source/profile
  snapshot was accepted with a 60.00-second completion. A real
  `counter_regression` first emitted at generation 4 could likewise be shifted
  to generation 5 after an unrelated later event. Terminal aggregate
  invariants prove only reachability, not exact history. The active correction
  must add bounded, dedicated-key-authenticated, epoch-bound milestone-chain
  proof; authoritative readiness and first-failure generations must be derived
  from verified first-occurrence receipts, never plain snapshots. Evidence:
  145 full and 22 focused passes plus clean static checks at the frozen hashes;
  the reviewer made no edits.
- Operational-evidence re-review rejects the frozen repair at C0/I1/M0. A
  single in-budget one-sample spike or dip inside an otherwise constant
  post-warmup baseline is falsely rejected as growth for many positions
  (including 120, 240, 420, and 480), while boundary positions pass. The
  sequence detector mistakes the two sustained sides of the same baseline for
  two sustained levels. Period-61/82/129/200 recurrence and translation,
  rising duty, seeded stationary/random traces, true growth families, alias
  mutation, deep ownership, and the 10-million-sample resource bound otherwise
  cleared. Evidence: 897 passes and clean static checks at frozen hashes; the
  reviewer made no edits. A surgical full-evaluator TDD correction is active.
- Task 13 journal-proof publication re-review rejects the round-7 freeze at
  C0/I1/M0. Four targets are preflighted together but linked sequentially
  without batch rollback: an injected artifact-2 failure leaves artifact 1,
  and a parent swap immediately after link leaves the runner-owned final inside
  the renamed pinned directory. Existing exact retries, response validation,
  race-winner preservation, and descriptor-relative single-output safety
  otherwise cleared. Evidence: 393 scoped passes with one root-only skip,
  12 proof-unit passes, 18 named adversarial passes, exact hash matches, and
  clean static checks. A two-phase/identity-safe batch cleanup correction is
  active; preexisting exact outputs and attacker winners must never be removed.
- Operational-evidence isolated-outlier correction is frozen without a commit
  for fresh independent review. The exemption is deliberately surgical: only
  an exact three-run canonical metric sequence whose middle run has count one
  and whose flanking values are identical is treated as a bounded isolated
  deviation. Unbracketed first/final deviations remain fail-closed. Evidence:
  933 focused passes; 36/36 exhaustive matrix nodes covering every internal
  index 1..479, spike/dip, amplitudes 1/10, and bytes/objects/both; 2,000 seeded
  adversarial families; and a 10,000-run/10-million-sample guard at 0.3579
  seconds and 3.560 MiB with exactly 10,000 traversals. Ruff lint/format,
  compileall, diff, and whitespace checks are clean. Frozen SHA-256:
  `acceptance_operational.py=c60658836e9f026243b445fb7f7e3a5abfeaec2e35c22b338d488a85f599ae56`,
  `test_acceptance_operational.py=b7f3f56f4ca6709d665516e6ea5b22eca4f7577e6600c7000dff6d6fd549480e`.
- Task 13 four-artifact publication correction is frozen without a commit for
  fresh independent review. All missing outputs are staged, hashed, validated,
  and file-fsynced before exposure; no-replace descriptor-relative links retain
  open runner inode identities through final validation; failure rolls back
  only runner-created finals in reverse order through pinned parent
  descriptors, attempts every cleanup, aggregates rollback errors, and fsyncs
  touched parents. Preexisting exact outputs, replaced temporary names, and
  destination race winners are preserved. Evidence: 19/19 batch adversarial
  tests, 138 report/proof tests, 12 proof-unit tests, clean Ruff lint/format,
  compileall, Compose static parsing at 11 services/5 networks, and clean
  whitespace checks. A wider 410-case run produced 408 passes, one guarded
  skip, and one reproducible pre-publication authority-start HTTP 409 that is
  tracked separately for diagnosis. Frozen SHA-256:
  `replay_20.py=f9ed5a38f992b60ed4ff7ea2835824bb8fbce9a93820b725da2f3ed53104a8eb`,
  `test_acceptance_report.py=7c7ab70526924eeedc754b2286c259eadd098995c4472abd73fc28314b442fbe`.
- Native source-profile exact-history proof is frozen without a commit for
  fresh independent review. The bounded Ed25519 milestone chain is signed
  exactly once outside the ingestion lock over an immutable captured envelope,
  then verified against caller-pinned key/site/ordered source commitments/
  epoch/epoch-start. The adversarial matrix covers slow-NTP backdating,
  shifted first failures, validly re-signed truncation/duplication/identity
  substitution, malformed/reordered/oversized chains, old-epoch replay, deep
  ownership, missing signer, source-secret exclusion, and concurrent ingest.
  One RED exposed signing under the tracker lock and was corrected. Evidence:
  17 focused proof passes and 162 full source-profile passes; Ruff lint/format,
  py_compile, and whitespace checks are clean. Frozen SHA-256:
  `source_profile.py=d27c9e7b090ab00d2a46ed6d261df7a500fd9058b5079b1db72af89ad82e0c40`,
  `test_source_profile.py=9376c8ba796b4f579aa5fbb05bc8e954c3c3933b4fc690d26b317bbd51bcf8a2`.
- Operational-evidence isolated-outlier review rejects its freeze at C0/I1/M0.
  Full-evaluator probes after warmup clipping accepted a two-sample middle
  deviation, a five-run pair of isolated deviations, and an unequal-outer
  multistep transition. Only the exact three-run/count-one/equal-flanks pattern
  may pass. Frozen hashes matched; 94 targeted and all 933 existing tests
  passed, so bounded fix round two must add these REDs without weakening first/
  final fail-closed behavior or other growth families.
- Task 13 four-artifact publication review rejects its freeze at C0/I3/M0.
  An exact concurrent-winner success omitted that parent directory's fsync;
  stage/preflight/final descriptor cleanup stopped at the first failure or
  replaced the primary error instead of exhaustively aggregating; and removed
  staging temporaries were not followed by parent fsync on pre-exposure
  failure. Exact reverse rollback and inode ownership otherwise cleared.
  Frozen hashes matched; 26 targeted and 126 full report tests passed. Bounded
  fix round two must make every cleanup exhaustive, durable, and causally
  aggregated.
- The reproducible wider-suite HTTP 409 is diagnosed as a restricted-host test
  artifact, not an acceptance-state defect. The controller's preserved
  underlying exception is `host boot identity is unavailable`: this macOS
  sandbox blocks the `sysctl kern.boottime` fallback, while the identical
  isolated test passes outside that restriction and target Linux uses
  `/proc/sys/kernel/random/boot_id`. The fail-closed boot identity check must
  not be weakened. The exact restricted run produced 420 passes, one guarded
  skip, and this one environment-only failure across 422 tests.
- Operational-evidence bounded fix round two is frozen without a commit for
  fresh independent re-review. It rejects non-exempt short interior excursions
  against the full canonical metric history before clipped stable-plateau
  acceptance, while preserving proven recurrence/modular orbits and true
  two-run stable plateaus. Evidence: 410 focused/control passes, 1,059 full
  operational passes, 3,000 seeded adversarial families, and a 10,000-run/
  10-million-sample guard at 0.4221 seconds and 3.560 MiB with exactly 10,000
  traversals. Ruff lint/format, compileall, diff, and whitespace checks are
  clean. Frozen SHA-256:
  `acceptance_operational.py=cee09ce67ce894ca9920219b5fc8017f0a5857a9b6d72949d0c0870433a043cc`,
  `test_acceptance_operational.py=ff395edd565843759a2213a9d6e60912b73fe323b9175fe400227fe7043060f5`.
- Task 13 four-artifact publication bounded fix round two is frozen without a
  commit for fresh independent re-review. Exact concurrent winners now fsync
  and revalidate every pinned parent; stage/preflight/validation/final cleanup
  attempts all unlink/fsync/close operations while preserving the primary and
  aggregating cleanup causes; successful temporary removals fsync their
  directories. Evidence: 31 target-artifact cases, 12 proof units, 150 full
  report/proof passes, clean Ruff lint/format and compileall, Compose static
  parsing at 11 services/5 networks, and clean whole-worktree whitespace.
  Frozen SHA-256:
  `replay_20.py=d671c4e7e6592fe0afffbffb783a4af7f1b08f61ab318963f1ccae8ad6ebf6a6`,
  `test_acceptance_report.py=49c37c4c68468004e18ebc10f60d5b2e434a7d318c9d64fcfc9158f67f54e6ed`.
- Native source-profile exact-history review rejects its freeze at C1/I1/M0.
  The export-time SHA chain is circular with the equally re-signable aggregate
  snapshot: coordinated, fully re-chained and final-key re-signed forgeries
  could shift a first failure, backdate slow-NTP readiness, truncate or
  substitute a real failure, reorder same-generation receipts, or substitute a
  source while preserving caller-pinned commitments. Milestones need a
  cryptographically separate ingestion-time authenticator/trust domain whose
  final sequence/head/tag is assigned atomically under the tracker lock; export
  may then deep-copy that frozen chain and sign it once. Separately, proof
  issuance made five OpenSSL subprocess calls because it immediately
  self-verified the single signature. The repair must make issuance literally
  one final Ed25519/OpenSSL call, with standalone verification performed by the
  consumer. Evidence: all 162 frozen tests and 10 focused randomized/
  concurrency probes passed, demonstrating the missing coordinated-forgery
  coverage rather than a simple existing-test regression.
- Operational-evidence bounded fix round-two re-review is APPROVED at
  C0/I0/M0. Frozen hashes matched. Independent evidence covered 7,581 complete
  positional checks for exact singleton, boundary, two-sample, five-run,
  unequal-flank, stable-plateau, recurrence, and modular cases across bytes,
  objects, and both; 2,010 translated/rising-duty/late up/down/multistep growth
  traces all failed closed. The targeted run passed 672 cases and all 1,059
  frozen tests passed. Exact type defenses, heavy-analytic operator
  prohibition, final-inventory ownership, and the 10k-RLE bound remained
  intact. No reviewer edits were made.
- Task 13 four-artifact publication round-two re-review rejects its freeze at
  C1/I4/M0. A final validation hashed an open exact inode but did not re-bind
  the requested leaf name to that inode, so a same-size replacement could
  occupy the final name while the batch returned success. Exact concurrent
  winner files were not file-fsynced; ownership check then unlink could remove
  a replacement; post-open parent validation could leak its directory
  descriptor; and a link that succeeded before raising could escape rollback
  if the subsequent ownership probe also failed. Frozen hashes matched; 31
  focused and 138 full report tests passed, showing missing namespace/
  durability fault coverage. Fix round three must bind final names to validated
  inodes before success, sync winner files, close every parent-open path,
  conservatively register ambiguous links, preserve primary+cleanup causes,
  and avoid check-then-unlink ownership races.
- The read-only portable native-probe contract audit is complete. Slice A must
  accept primitive RTP codec, decoder dimensions/FPS rational, parser
  byte-size/source-timestamp/PTS, decoded PTS, and NvDs camera-NTP/PTS only;
  derive cumulative bitrate and caps internally; correlate decoder/NTP arrival
  in bounded arbitrary order while preserving the parser pad's intrinsic
  source-timestamp order; serialize complete observations to the existing
  tracker; and make invalid/overflow evidence an authoritative failure.
  Generation-owned leases must be idempotent/GC-safe/thread-safe and old leases
  inert after replacement. Exact-20 prewarm receipts may be created only after
  verifying both source-proof trust domains and all pinned site/epoch/ordered
  identity fields; plain snapshots, booleans, callbacks, SourcePlan values,
  and host-clock fallback are forbidden. No audit edits were made.
- Native source-profile exact-history fix round two is frozen and independently
  APPROVED at C0/I0/M0. A separate redacted 32-byte HMAC milestone trust
  capability, distinct from the URL commitment key and final Ed25519 signer,
  assigns receipt and terminal authentication under the ingestion lock.
  Transaction savepoints restore state, deltas, generations, high-water marks,
  close reservations, evictions, receipts, and terminal tag if authentication
  cannot complete. Export deep-copies under lock, signs once outside it, and
  does not self-verify; issuance makes literally one OpenSSL subprocess call.
  Six coordinated fully re-chained/final-re-signed history rewrites all fail,
  including shifted/backdated/truncated/substituted/reordered/cross-source
  cases. Evidence: 29 focused proof/auth/atomic passes, 175 full source passes,
  and 1,234 combined source/operational passes; Ruff lint/format, py_compile,
  and whitespace checks are clean. Frozen SHA-256:
  `source_profile.py=8d65a7930d5b9e6b52cfd8b54ecc933b92a1da8a728cd3d24f092ee0dec092ce`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`.
- Task 13 four-artifact publication fix round three reached 45 focused and
  164 full report/proof passes with clean static checks, but its independent
  re-review rejects the freeze at C0/I2/M1. A metadata failure immediately
  after opening an exact winner could leak that descriptor; a raced directory
  moved into private quarantine could not be restored with a hard link; and
  quarantine mkdir followed by open failure left the empty runner-owned
  directory behind. Fix round four must group winner metadata/close failures,
  restore every supported replacement type without overwrite, and remove/fsync
  a just-created quarantine when its open fails. No approval or freeze is
  recorded for the round-three hashes.
- Task 13 four-artifact publication fix round four is frozen without a commit
  for fresh independent re-review. Winner metadata acquisition now guards and
  groups descriptor close failures; directory replacement restoration uses a
  portable no-replace mkdir reservation followed by descriptor-relative
  rename/identity validation; and quarantine-open failure exhaustively removes
  the just-created directory and fsyncs the parent. Evidence: 48 target-
  artifact passes, 167 full report/proof passes, 12 proof-unit passes, clean
  Ruff lint/format and compileall, and clean scoped whitespace. Frozen SHA-256:
  `replay_20.py=27ad828f409f7591d02d6cfa42b3d517607ae06ae10f3348994bb17e9ef241ca`,
  `test_acceptance_report.py=a76ee479232fec18024769861a186c409c8fde65936715976b3fef9b8f84ce1d`.
- Task 13 four-artifact publication round-four re-review rejects its freeze at
  C0/I1/M0. The prior three quarantine/winner lifecycle findings are closed,
  but the exact-winner path discarded the precise metadata snapshot that had
  been hashed and fsynced, then took a fresh `fstat` after temporary cleanup.
  A same-UID mutation in that interval could become the newly blessed expected
  state for the local binding step. The later all-output validation catches
  persistent mutation but does not preserve exact causal winner identity.
  Fix round five must return/carry the original validated snapshot with the
  retained descriptor through cleanup and bind the leaf against that snapshot.
- Task 13 four-artifact publication fix round five is frozen without a commit
  for bounded independent re-review. The exact winner now carries the original
  metadata snapshot that was hashed and file-fsynced, retaining it with the
  descriptor through temporary cleanup and final leaf binding. Evidence:
  49 target-artifact passes, 168 full report/proof passes, 12 proof-unit
  passes, and clean Ruff lint/format, compileall, and scoped whitespace.
  Frozen SHA-256:
  `replay_20.py=7ba827028ace58796ad36a51095603461d5d0ae83a4d4184407e363121631baf`,
  `test_acceptance_report.py=a4bfb9f39b27889315b6f9e37e72d340183e613b915bbd949da26966eb28f1f5`.
- Task 13 native-probe Slice A is frozen without a commit for fresh exact-hash
  review. The pure-Python bridge accepts primitive RTP codec, decoder format/
  FPS rational, parser bytes/source timestamp/PTS, decoded PTS, and NvDs
  camera-NTP/PTS only; correlates bounded parser-ordered cross-branch state;
  derives cumulative bitrate/caps; serializes tracker callbacks; and reports
  overflow/regression/provenance failures through a new authoritative
  generation-owned callback path. Leases are bounded, thread-safe,
  idempotently closed/GC-safe, and stale generations inert. Exact-20 prewarm
  receipts are issued only after both source-proof trust domains and all
  caller pins verify. Evidence: 35 new parameter-expanded cases plus all 175
  frozen source-profile cases (210 combined), clean Ruff lint/format,
  compileall, and whitespace, plus a real tracker integration probe deriving
  4,000 kbps and exact max callback time. Frozen SHA-256:
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`,
  `source_probe.py=9ee22d2f25d4f2ceb48b0bdb7ec771d1d00f8ade8b4c0094e7ebe94f808a78ba`,
  `test_native_source_probe.py=4ccf09ae203c54e93ae03683e7d2d3786efa71068ff0ccb27f8d22fca96f4eef`.
- Task 13 four-artifact publication round-five exact-hash re-review is
  APPROVED at C0/I0/M0. The reviewer made no edits. Frozen hashes remained
  `replay_20.py=7ba827028ace58796ad36a51095603461d5d0ae83a4d4184407e363121631baf`
  and
  `test_acceptance_report.py=a4bfb9f39b27889315b6f9e37e72d340183e613b915bbd949da26966eb28f1f5`.
  Independent evidence: 20 targeted exact-winner/race/rollback/quarantine
  cases passed, with clean Ruff lint/format, compileall, and scoped diff
  checks. Controller evidence remains 49 focused target-artifact passes, 168
  report/proof passes, and 12 proof-unit passes. The publication slice is
  frozen for the integrated Task 13 commit.
- Task 13 native-probe Slice A exact-hash review rejects the initial freeze at
  C3/I2/M0. The receipt constructor was publicly forgeable; ready aggregate
  proofs produced through direct tracker callbacks could issue a purported
  native receipt without any `NativeSourceProbeBridge`; and failed receipt
  verification retained the exact milestone-authenticator key in traceback
  locals. Completed exact-triple replay also orphaned decoder/NTP PTS entries
  and exhausted capacity, while external callbacks under the bridge `RLock`
  allowed reentrant later triples to overtake an earlier callback batch and
  even continued parser/decoded callbacks after reentrant close. The reviewer
  made no edits and preserved all four frozen hashes. Existing tests remained
  green at 35 native, 175 source-profile, and 210 combined, demonstrating
  missing adversarial coverage rather than an ordinary regression. Bounded fix
  round one is active with the same implementer; DeepStream Slice B was
  interrupted before integration against the rejected contract.
- Controller combined frozen-proof checkpoint before the Slice A repair:
  `test_source_profile.py`, `test_native_source_probe.py`,
  `test_acceptance_operational.py`, `test_acceptance_report.py`, and
  `test_acceptance_journal_proof.py` passed 1,437 tests in 257.52 seconds with
  the safe offline uv cache. This validates the previously approved behavior
  but does not override the native review's adversarial findings.
- Native-probe Slice A bounded fix round-one TDD RED is recorded before
  production edits: the complete native-probe file produced 20 failures, 31
  passes, and 3 errors in 4.75 seconds. The failing matrix covers all nine
  close/false/raise callback-position combinations, reentrant batch ordering,
  bounded completed-replay idempotency/conflicts, secret-bearing traceback
  paths, direct receipt construction, direct-callback/no-bridge issuance, and
  exact-20 transactional live-lease claims. A controller subset independently
  reproduced six of these failures in 2.17 seconds.
- A read-only Task 14 preparation audit is complete without code or document
  edits. The five required runbooks/model/limits documents are absent and the
  README remains demo-only. Task 14 must add operator, incident-response,
  deployment, model-register, and known-limits documentation; explicitly
  separate the investor demo from the controlled pilot; include a fillable
  handover manifest; retain human-confirmation, NVR/local-video, model-rights,
  exact-20/frozen-workload, and no-autonomous-action boundaries; and leave
  CUDA/L4, real-source, 8-hour, 72-hour, restore-drill, and operator-training
  gates PENDING until their exact target-host artifacts exist. The canonical
  target commands and thresholds remain in `docs/pilot/ready_to_start.md` and
  `deploy/pilot/TARGET_ACCEPTANCE.md`; Task 14 will link to them rather than
  fork them.
- Task 13 native-probe Slice A bounded fix round one is frozen without a
  commit for exact-hash independent re-review. The repair makes all external
  bridge callbacks use one serialized dispatch owner, including deferred
  concurrent/reentrant terminal failure and close; revalidates current
  authoritative tracker readiness/failure while atomically claiming the exact
  20 live bridge-owned leases; bounds retained one-shot receipt capabilities;
  and scrubs ordinary exception tracebacks while clearing then propagating
  `BaseException`. Completed replay tombstones remain bounded and duplicate
  triples are inert. Controller evidence: 240 combined native/source-profile
  tests passed in 40.74 seconds; the implementer also completed 20/20 repeated
  concurrency stress runs; scoped Ruff lint/format, `py_compile`, and
  whitespace checks are clean. Frozen SHA-256:
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`,
  `source_probe.py=b96124a005e6da8e8c9f46ac20ddd873fcb15a17aaa63d22eea03365b47f923b`,
  `test_native_source_probe.py=b2d0479f219c35b676b74b24ebef5f3a1105f3d4e45c26ecbd0eb894e283a3a8`.
- The read-only Task 13 Slice C audit is complete without edits. It identifies
  five release-blocking contract gaps: V1 acceptance schemas/fingerprint
  semantics were extended in place instead of frozen for non-authorizing
  historical verification; target injection uses
  `Callable[..., object]`/`getattr`/`hasattr`; injected GPU identity can fall
  back to the signed expectation; no verified exact-20 native prewarm proof
  gates collector-journal construction or the endurance clock; and effective
  throughput remains a signed free scalar rather than a derivation from unique
  completed work over a measured monotonic window. Slice C must therefore add
  canonical V2 manifest/launch/report/mount/execution contracts, immutable
  historical V1 verification, a mandatory typed runtime factory/process and
  fully observed GPU inventory, exact native-proof-before-journal ordering,
  measured offered/completed throughput at at least 1.25 times the frozen
  workload, and exclusive fresh V2 journal creation. Unversioned/incomplete V1
  state must never resume; exact completed V2 recovery may be read-only.
- The read-only Task 13 Slice D audit is complete without edits and rejects
  the current authority integration. The protected authority still accepts an
  observer-supplied final candidate, runs neither the standard nor frozen
  operational evaluator, has no authority-owned repeatable repository/runtime
  snapshot provider, and signs a V2 proof graph with no evaluator identities
  or input/output bindings. Recovery therefore replays a signed assertion
  rather than an authority-derived decision, and the protected SQLite schema
  is V1/migrating rather than fresh campaign-bound V2. Slice D must remove the
  candidate from a strict finalize request; persist one immutable authority
  snapshot; reconstruct the run and operational boundary; run both evaluators
  without short-circuiting; require both to pass; store evaluator code/image,
  canonical input/output, and decision digests; and use an insert-once
  `RUNNING -> SNAPSHOT_COMMITTED -> EVALUATED -> FINALIZED ->
  PROOF_PUBLISHED -> ATTESTED` recovery machine. A new acyclic proof/
  attestation schema must bind and carry independently replayable evaluator
  inputs/outputs. Failed evaluation produces no acceptance attestation.
  Fresh protected DBs must bind exact site/campaign/gate/manifest/evaluator
  identities and reject V1, unknown schemas, reused campaigns, or partial
  unbound state before writes. The approved operational evaluator remains
  frozen.
- Task 13 native-probe Slice A fix-round-one exact-hash re-review rejects the
  freeze at C3/I2/M0; all four hashes remained pinned and the reviewer made no
  edits. Exact-type leases created through low-level object allocation could
  copy a valid bridge/generation pair and satisfy receipt issuance; an
  exact-type receipt clone could copy the seal/fields and consume after the
  original; and a receipt constructed before transactional claim writes
  remained usable from traceback locals after an injected claim rollback.
  Non-inflight terminal delivery also left no reservation, allowing a new
  generation's normal callbacks to overlap a blocked old close/failure
  callback. Finally, an injected post-delivery `_commit_completed_locked`
  exception occurred outside cleanup and stranded dispatch ownership until
  explicit close. Existing 240 tests and Ruff passed, while separate probes
  confirmed that prior secret redaction, completed-replay bounds, reentrant
  order, current-state, stale/mixed identity, and direct-callback findings are
  closed. Bounded fix round two is active with the same implementer under TDD;
  it must add canonical bridge-issued lease identity, bounded verifier-owned
  one-shot receipt identity, claim-before-receipt atomicity, reservations for
  every terminal dispatch, and cleanup around post-delivery commit failures.
- Native-probe Slice A bounded fix-round-two TDD RED is recorded before
  production edits: seven focused cases failed with 63 deselected in 6.60
  seconds while `source_probe.py` still matched the rejected round-one hash.
  The failures cover blocked non-inflight close/failure overlap with a rebound
  generation (two), stranded waiters after Exception/BaseException in
  post-delivery housekeeping (two), accepted low-level exact-type lease clones,
  a traceback-reachable receipt from a rolled-back claim transaction that
  still consumed, and a copied-slot/seal receipt clone that consumed after the
  original. The implementer is now repairing bounded generation-owned
  capability authority and terminal/dispatch cleanup.
- Task 13 native-probe Slice A bounded fix round two is frozen without a
  commit for fresh exact-hash review. Canonical bridge-issued lease weakrefs
  reject low-level exact-type clones; one generation-owned claim authority is
  reserved across all 20 states before receipt construction and binds the
  canonical issued receipt by identity, so copied receipts and
  rolled-back/traceback-reachable objects cannot consume. Every terminal path,
  including non-inflight close/failure, now holds a dispatch reservation until
  the external terminal callback completes, and post-delivery state commit is
  BaseException-safe with cleanup and waiter notification. Controller
  evidence: 245 combined native/source-profile tests passed in 42.22 seconds;
  implementer stress ran the concurrency quartet 20 times (80 executions) and
  all seven new regressions five times (35 executions); scoped Ruff
  lint/format, `py_compile`, and whitespace checks are clean. Frozen SHA-256:
  `source_probe.py=d9307a1ae27325fd907aeafcd4eed70537e764fc0daeecfe6f567c7e2805335a`,
  `test_native_source_probe.py=ee68a0a1650bb74df9d87892044ba34b78ee93645c9f29215709683fd797f35b`,
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`.
- The read-only Task 13 DeepStream Slice B audit is complete without edits.
  Current graph tests pass but do not wire or enforce the native source
  authority: no typed lease factory/generation ownership/monotonic-ns
  injection, no `configure_source_for_ntp_sync`, no RTP/parser/decoder probes,
  host-time and zero-PTS fallbacks remain, heartbeat precedes missing-NTP
  rejection, rebuild destroys the old source before replacement viability,
  and stop owns no leases. Slice B must add one typed generation object per
  camera, actual primitive extraction into its lease, fail-closed
  `CLOCK_TIME_NONE`/zero/malformed handling, camera-NTP-before-
  heartbeat/publication/evidence, exact lease/writer cleanup, and a
  transactional staged rebuild that retains and restores the old
  bin/writer/lease on every add/unlink/link/sync failure. Tests must cover
  partial startup, all invalid primitive matrices, no configured/host
  fallback, camera-local NTP failure, every rebuild rollback branch, late
  retired-writer messages, and exception-safe exact-once stop.
- Task 13 native-probe Slice A fix-round-two exact-hash review rejects the
  freeze at C0/I1/M0; the reviewer made no edits and all hashes remained
  pinned. All prior clone, one-shot, rollback, secret, replay, terminal,
  reentrant, concurrent, and post-delivery findings are closed. The sole
  remaining issue is the initial baseline `_commit_completed_locked` call,
  which still sits outside the universal BaseException cleanup. Injected
  `RuntimeError` and direct `BaseException` both stranded the dispatch owner,
  blocked the next callback, and did not close until manual cleanup. Frozen
  evidence otherwise remained 245 combined passes, 70 native passes, 175
  source-profile passes, 20/20 stress iterations, and clean Ruff checks.
  Bounded fix round three is active with the same implementer and must wrap
  the baseline commit in the same terminal cleanup/wakeup/rebind discipline.
- Native-probe Slice A bounded fix-round-three TDD RED is recorded before
  production edits: both focused baseline cases failed (RuntimeError and
  direct BaseException), with 70 deselected in 1.26 seconds. Each failure
  showed the queued callback did not wake and the pre-cleanup close count
  remained zero because the initial `forwarded_at=None` commit left the
  generation active with its dispatch owner retained.
- Task 13 native-probe Slice A bounded fix round three is frozen without a
  commit for final exact-hash review. Initial baseline commit and later
  post-delivery commit now share universal BaseException terminal cleanup, so
  both ordinary and direct abort paths close once, wake waiters, make the
  stale lease inert, and permit replacement binding. Controller evidence: 247
  combined native/source-profile tests passed in 44.45 seconds; the
  implementer ran 20 rounds of the ten baseline/post-delivery/concurrency
  tests (200 executions); scoped Ruff lint/format, `py_compile`, and
  whitespace checks are clean. Frozen SHA-256:
  `source_probe.py=c49bac0582ae85c32e55e7ae42b00ff4064cc4370102ed5478e82b3f34ec269b`,
  `test_native_source_probe.py=461965663c10d46d75f668ce3d97cabc6c2ac554b18c71b35f60d171b4b91634`,
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`.
- Task 13 native-probe Slice A round-three exact-hash review is APPROVED at
  C0/I0/M0. The reviewer made no edits. Focused evidence was 11 passes, the
  combined frozen suite was 247 passes, ten fresh-process
  baseline/post-delivery/concurrency stress iterations passed, and Ruff
  lint/format was clean. Initial baseline RuntimeError/direct-BaseException
  cleanup now closes exactly once, wakes the queued callback as false, leaves
  the stale lease inert, and permits replacement bind. All prior canonical
  lease/receipt identity, rollback, one-shot, secret, bounded replay,
  terminal-fencing, overlap, and deadlock findings remain closed. Final hashes
  are the round-three freeze:
  `source_probe.py=c49bac0582ae85c32e55e7ae42b00ff4064cc4370102ed5478e82b3f34ec269b`,
  `test_native_source_probe.py=461965663c10d46d75f668ce3d97cabc6c2ac554b18c71b35f60d171b4b91634`,
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`.
- Task 13 DeepStream Slice B TDD RED is recorded before production edits.
  Frozen Slice A and starting DeepStream hashes matched. Four focused cases
  failed with 43 deselected, demonstrating the absence of a typed native
  lease/monotonic-ns generation owner, destructive rebuild without rollback
  ownership, missing native NTP configuration, and invalid/missing camera NTP
  still reaching heartbeat/host fallback. The implementer is proceeding to
  GREEN and must expand the fake-GStreamer matrix across all primitive and
  transactional failure branches before freezing.
- The read-only historical-V1 compatibility audit is complete without edits.
  Commit `400fe18` is the first shipped acceptance implementation; its parent
  has no acceptance module and no trust-chain module existed. Exact V1
  manifest fields were schema/site/sources/modules plus config/model/engine/
  image digests, with no launch. Exact V1 report fields were run/site/
  manifest/generated/gate/environment/pass/reasons/metrics/modules/exceptions,
  with no launch, execution, trust, worst-camera, drop, or queue summaries.
  The signed envelope contained only V1 schema, report, and HTML digest; V1
  verification metadata used SHA-256 of the exact PEM file bytes under
  `public_key_sha256`, not SPKI. Canonical JSON sorted object keys, preserved
  arrays/defaults/nulls, emitted UTF-8 without a newline, and rejected NaN.
  Slice C must preserve those exact bytes/semantics behind explicit V1 schema
  dispatch and a distinct non-authorizing historical result, while all
  expanded manifest/source/module/report/envelope/metadata behavior becomes
  V2 with an explicit `public_key_spki_sha256`. Golden fixtures must be
  byte-for-byte artifacts from an isolated `400fe18` checkout with no private
  key and pinned hashes; every execution/controller/target entry point must
  reject historical V1 as authority.
- Task 13 DeepStream Slice B is frozen without a commit for independent
  exact-hash review. A typed per-camera source generation now owns bin,
  bounded writer, and canonical native lease; actual RTP/decoder/parser/
  decoded/NvDs primitives use freshly injected monotonic time; native NTP is
  configured per RTSP source; invalid/zero/bool/CLOCK-NONE values fail closed
  without configured or host-clock fallback; and camera NTP gates heartbeat,
  metadata, and evidence. Startup/stop cleanup and staged rebuild cover exact
  20, partial attachment, add/unlink/link/sync/rollback failure, old-generation
  restoration, successful exact retirement, and stale event inertness.
  Controller evidence: 80 focused tests passed in 0.69 seconds; implementer
  combined evidence was 327 passes in 286.33 seconds; scoped Ruff lint,
  `py_compile`, and whitespace checks are clean. Ruff format check reports
  that the three Slice B files would be reformatted; this is disclosed to the
  reviewer and no hash-changing formatter was run during the freeze. Frozen
  SHA-256:
  `deepstream.py=1e87aa1ce0d171187cb5c8665f4b007e29618815846e6a3f78fedbc1654f2de2`,
  `test_deepstream_graph.py=022ffb45e06525658cb59cffda4cad90fdedb5828918ce1365bb82ad38d217bf`,
  `test_deepstream_native_integration.py=990c98ae873e8b2652331c0a15b097dd5d7d16bd4209a587b0f4673cdf6c2f10`.
  All four approved Slice A hashes remain unchanged. This is portable
  graph-contract evidence only; NVIDIA/real-RTSP/capacity acceptance remains
  externally PENDING.
- Task 13 DeepStream Slice B exact-hash review rejects the initial freeze at
  C2/I5/M2; the reviewer made no edits and independently reproduced 80
  DeepStream passes, 247 frozen Slice A passes, clean Ruff/diff checks, and all
  seven frozen hashes. Native RTCP configuration and primitive extraction are
  correct, but target `main()` still supplies no production native factory;
  primitive enqueue acceptance (or even no generation) can mark a camera
  online before a fully correlated bridge callback; queued old NvDs frames
  have no generation-safe authorization; stale writer messages are forwarded
  to the collaborator; evidence writers are bound/handled before NTP
  authority; rollback drops staged cleanup ownership after removal failure;
  malformed caps can escape camera-local recovery; the shared timestamp model
  was narrowed unnecessarily; and metadata source lookup is positional.
  Production factory construction remains explicitly assigned to sequential
  Slice C because it requires the V2 launch/trust/prewarm boundary. Bounded
  Slice B fix round one is active with the same implementer for every adapter
  correctness finding, including an additive generation-owned correlated-NTP
  capability if required; any approved Slice A file changed by that fix must
  be independently re-reviewed at new exact hashes before Slice B can pass.
- A parallel read-only Slice B fix-design audit made no edits and fixed the
  safe state machine before implementation: existing `observe_*` booleans keep
  their accepted/enqueued meaning; a lease-owned read-only correlation result
  becomes available only after the exact callback-forwarded commit; each
  generation advances through staged, live-unauthorized, authorized,
  quiescing, and retired states; evidence requires active-writer identity plus
  a post-authority fragment boundary; and reconnect cutover must use a
  mandatory acknowledged block/flush boundary because source ID and PTS alone
  cannot distinguish queued old NvDs frames from a replacement. Rollback
  restores graph ownership but requires fresh correlation for the new stream
  epoch. Pending correlation is inert, not a malformed-timestamp failure.
- DeepStream Slice B fix-round-one TDD RED is recorded while all production
  hashes still matched the rejected freeze. Seven focused regressions failed
  with 36 deselected: malformed RTSP caps escaped; accepted-but-uncorrelated
  NTP made no completion query; missing generation still became online;
  queued old NvDs metadata entered the replacement lease; source lookup
  remained positional; the shared timestamp contract rejected its existing
  fallback value; and pre-authority evidence open/close messages reached the
  collaborator. The evidence RED includes running-time/location fields and a
  pre-authority fragment so the fix must enforce a real post-authority
  boundary, not merely observe message order. Further real-bridge and failed
  cleanup-ownership RED coverage is required before GREEN is frozen.
- The completed Slice B fix-round-one RED matrix is 14 failures with 104
  deselected (controller reproduction: 21.23 seconds) before production edits.
  It adds real bridge pending/baseline/in-flight/failed/closed/rebound
  correlation tests, an acknowledged block/flush cutover and fail-closed
  negative acknowledgment, failed rollback removal retained for stop retry,
  and initial writer non-binding. This freezes the full reviewer reproduction
  set before GREEN rather than relying on protocol fakes alone.
- Controller review of the first GREEN exposed two additional source-epoch
  cleanup gaps, so the same bounded fix round was extended with RED tests
  before further production edits. The focused command produced 3 failures,
  1 pass, and 43 deselected in 3.34 seconds: source-build failure left the old
  generation authorized, source-add failure left its evidence writer logically
  bound, and successful cutover followed by old-generation removal failure had
  no retained cleanup registry for `stop()` retry. The flush-failure variant
  already passed. Required GREEN behavior is fail-closed revocation across
  every early rebuild failure plus bounded ownership of retired generations
  until cleanup succeeds; stale callbacks and bus messages must remain inert.
- A subsequent controller concurrency audit extended the same bounded round
  before freeze. Two interleaving regressions failed with 47 deselected:
  an old generation could complete correlation and mark the camera online
  while replacement construction was blocked, and `_SourceGeneration` did
  not bind its authorization to the supervisor stream epoch. This exposed
  both the pre-`QUIESCING` reauthorization window and the possibility of
  anchoring old source time into a newly advanced epoch before the later
  authorization recheck. GREEN must enter `QUIESCING` at rebuild entry,
  restore `live_unauthorized` only after an early failure, carry an explicit
  authorized epoch, and make the post-correlation state/epoch recheck,
  source-time anchor, and authorization atomic against lifecycle cutover.
- Slice C1 now has a fresh read-only implementation map with no shared-file
  edits. Historical commit `400fe18` must be copied into a self-contained
  verification-only `acceptance_legacy_v1.py`; its exact compact canonical
  JSON, smaller manifest/run/report/envelope shapes, and raw-PEM
  `public_key_sha256` semantics may not share validators with live contracts.
  Current expanded acceptance types become explicit V2, with
  `public_key_spki_sha256` and exact schema dispatch in a small verification
  boundary—never parse-by-fallback. Historical verification returns an exact
  non-authorizing result and every trust, controller, target, journal-proof,
  report, and recovery boundary must require V2 before any lock, DB, process,
  collector, or clock effect. Golden fixtures will be captured from an
  isolated `400fe18` archive with fixed inputs and an ephemeral Ed25519 key;
  only the public key and immutable signed artifacts/hashes are retained.
  The private key is destroyed and no deterministic re-signing claim is made.
- Slice B fix round one was extended once more before freeze to cover
  cross-epoch concurrency and real-bridge replay. The initial interleaving
  matrix failed 2 tests with 47 deselected: correlation could commit while
  replacement construction was blocked, and authorization carried no stream
  epoch. Follow-on RED proved both authorized and never-authorized old
  generations needed quiescing in the recover-to-rebuild handoff, and stale
  quiescing/retired primitives needed to be inert. The rollback real-bridge
  test then proved cached pre-epoch completion must stay offline until a
  wholly post-restoration parser/decoder/NTP correlation completes. Finally,
  the symmetric staged-to-active real-bridge regression failed 1 test with
  51 deselected because the replacement cutover boundary was zero instead of
  `50_000_000`. GREEN now binds authorization to exact supervisor epoch,
  serializes lifecycle transition against mapper/heartbeat/object/evidence
  commits, uses an authority revision plus strict completion-monotonic
  not-before fence, atomically quiesces before advancing the epoch, makes old
  stale primitives inert, and advances the replacement fence at successful
  cutover. The focused matrices are green; full-slice freeze is in progress.
- Task 13 DeepStream Slice B fix round one is frozen without a commit for a
  fresh exact-hash independent review. The final implementation closes all
  initial reviewer adapter findings plus the controller's early-failure,
  retirement-ownership, interleaving, epoch, primitive-lifecycle, rollback
  replay, and staged-cutover replay findings. Implementer evidence after
  scoped formatting: 2 focused real-bridge passes, 99 DeepStream passes, and
  349 combined source-profile/native-probe/DeepStream passes; Ruff lint and
  format, `py_compile`, and whitespace checks are clean. Controller reproduced
  the exact seven hashes, 99 DeepStream passes, Ruff lint/format, and
  whitespace checks. Frozen SHA-256:
  `source_probe.py=53acf44c80b690d7e17536ab95e2b8df1eee0c3b3e3293faddd963869269b724`,
  `deepstream.py=b95ecbfc8d41474777d6386a75732ba8c31e14e0e769f65aebb477904becc118`,
  `test_native_source_probe.py=81f4ff863199f8d289a76db281d8fd5e6a7e64766324112d92ae5335cd596256`,
  `test_deepstream_graph.py=d1b5422ac5cbf47be5f65fa3b01fef2702310fb03fb08d7a30314bec3b735070`,
  `test_deepstream_native_integration.py=0b47952490551c85618cb604b7cf6d2638697739df0bb951b91e2bd9d6cfb7c7`,
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`.
  Controller subsequently reproduced all 349 combined passes in 86.62
  seconds at the same frozen hashes.
  This remains portable contract/fake-GStreamer evidence only; NVIDIA,
  DeepStream/TensorRT, real-RTSP, exact-20 capacity, endurance, and soak gates
  are externally PENDING.
- Slice C2 has a fresh read-only implementation map with no edits. It confirms
  the current target path still uses a callable/object/getattr process seam,
  lets injected factories bypass source validation, falls back from missing
  observed GPU identity to signed expectation, constructs/reuses the collector
  journal before native prewarm, trusts scalar throughput, and leaves
  production DeepStream without its native factory. After C1 freezes V2 names,
  C2 will add typed runtime request/factory/process and full observed GPU
  inventory contracts; compose exactly 20 production tracker/bridge/lease
  bindings; consume the non-serializable exact-20 receipt inside the child and
  expose only an O_EXCL bounded launch-bound completion projection; require
  launch/identity/native proof/prewarm before fresh V2 journal, collector, or
  endurance clock; derive offered/completed unique work over a measured
  monotonic interval at >=1.25x the frozen workload; and separate exclusive
  new-run journal creation from read-only exact-completed recovery. V1/mixed/
  incomplete state cannot resume or migrate.
- The C2 restart/prewarm tension is resolved fail-closed for V2: a real runtime
  process restart creates a new native epoch and therefore must complete a new
  exact-20 60-second prewarm before analytics authority resumes. V2's reviewed
  restart fault window will be long enough to measure that requirement rather
  than retaining the historical roughly-three-second expectation or silently
  carrying pre-restart authority across a dead process.
- Fresh exact-hash Slice B review rejects fix round one at C1/I3/M0; the
  reviewer made no edits, all seven hashes stayed exact, and it independently
  reproduced 349 passes plus clean Ruff/format/whitespace checks. C1: a scalar
  maximum completion time is insufficient because a pre-fence parser
  primitive can combine with post-fence decoder/NTP primitives and authorize
  the new epoch; each per-frame constituent must be strictly post-fence (or
  the bridge generation must reset). I1: acknowledged `FLUSH_START` followed
  by rejected `FLUSH_STOP` cannot restore a live old source because GStreamer
  keeps it flushing; the blocked/quiesced resource needs retained retry
  ownership. I2: writer cleanup marks `_writer_unbound` before the collaborator
  succeeds, making transient failure non-retryable, while build-time unbind
  failure can lose ownership entirely. I3: `OverflowError` still escapes both
  RTP and decoder caps helpers instead of entering camera-local failure.
  Bounded fix round two is assigned to the same implementer under TDD; Slice C
  remains gated until a new exact-hash review approves Slice B.
- Slice B fix-round-two RED is frozen before new production edits: one command
  selected 11 cases and produced 10 failures / 1 passing all-post-fence
  control in 0.78 seconds. Failures cover the immutable correlation's missing
  parser/decoded/NTP constituent times; build-time writer cleanup ownership;
  RTP and decoder `OverflowError` escape; rejected `FLUSH_STOP` lifecycle and
  stop ownership; parser-before, decoded-before, and NTP-before fence
  permutations; and premature writer-unbind completion. This is the complete
  independent-review reproduction matrix; the implementer is now proceeding
  to the minimal GREEN changes.
- Slice B fix round two is frozen without a commit for a new exact-hash
  independent review. An added real-collaborator RED matrix exposed that
  `SplitMuxEvidenceSinkFactory` dropped its binding before directory removal
  and parent-directory fsync completed: both injected failure arms failed on
  the first implementation (`2 failed in 0.35s`). The GREEN implementation
  retains an identity-specific cleanup-pending binding until removal, fsync,
  and staging release all succeed; retries perform real remaining work and
  delayed writer messages are inert. A separate two-stop regression proves
  the runtime retains the exact writer after the first failed stop and retries
  it without re-closing its lease. Final implementer evidence is 359 combined
  source-profile/native-probe/DeepStream passes in 156.02 seconds, 49 evidence
  passes in 3.08 seconds, clean scoped Ruff lint, `py_compile`, and whitespace
  checks. Source-profile files remain byte-identical and the evidence diff was
  reduced to semantic-only changes. Frozen SHA-256:
  `source_probe.py=767ee70e98b667e71eb512786819c2269e5319cb24253bb6a73a6bce3dbb5e0f`,
  `source_profile.py=2859dab24a1d37a1c518eac0178b639443807abaf061792132bbc389c8d0a0ed`,
  `deepstream.py=f0b23b14d49708f5e53171574dd1990d487f9a9bfb7ddce92603fe5622f49896`,
  `evidence.py=53707dcd7718268670cee1978b4f6ac558b070fcfe9cd1157816b0b67be412ec`,
  `test_native_source_probe.py=f3d24dd96a54ba49dcfa41fb3a69f7d2f2387ecd3b3cd35c1c5f6cb68221b7ec`,
  `test_source_profile.py=ae9aacbd5c32e5b15987aee95a33846f5be76b497436b34d7f06ab0a913da2c2`,
  `test_deepstream_graph.py=10d3e1fedac31f255aeb09e1e8da6f936176fdbabaeb0f1c943d167f4605a430`,
  `test_deepstream_native_integration.py=fc82e86d768f6dd3a583ac17e3ca63b3540a83d6fdf0cc3f6660315f1f4c3c1a`,
  and
  `test_evidence.py=cee68305f9055943b427d765757c874c90b0896bdd1b9f21b4cb636b7d6b9521`.
  This remains portable contract/fake-GStreamer evidence only; NVIDIA,
  DeepStream/TensorRT, real-RTSP, exact-20 capacity, endurance, and soak gates
  remain externally PENDING.
- The controller independently reproduced the Slice B round-two freeze at the
  exact nine hashes: all 408 combined source-profile/native-probe/DeepStream/
  evidence tests passed in 237.05 seconds. Scoped Ruff lint, Ruff format for
  the seven already-formatted source/graph files, `py_compile`, and
  `git diff --check` also passed. The exact-hash independent review remains in
  progress; no Slice B approval or Task 13 commit is recorded yet.
- A fresh read-only whole-plan reconciliation found five locally implementable
  earlier-task integration gaps that cannot be hidden in Task 14
  documentation: signed camera-scoped zone/line configuration plus a
  production event-processing path; bounded integrity-checked pending/ready
  evidence preview wired into the production API; zero-user bootstrap and an
  audited admin-only user/password/TOTP/session lifecycle; base Compose
  packaging that renders without unapproved acceptance/notification secrets
  while fail-closed optional overrides require them; and a pinned non-root ops
  image/job contract containing the backup/restore tools. These are added as
  reviewed implementation slices after Task 13 and before handover docs.
  Controlled evidence export, physical camera replacement/re-acceptance, and
  infrastructure/master-key rotation remain documented change-control
  procedures rather than ordinary CRUD. The `/login` target check is a
  documentation-only `/pilot/login` correction. No files were edited by the
  reconciliation agent.
- Fresh exact-hash Slice B round-two review rejects the freeze at C0/I1/M0.
  All nine hashes matched and the reviewer made no edits. The accepted fixes
  close the prior correlation, flush, writer-unbind, real-writer retry, and
  caps-overflow findings, but `SplitMuxEvidenceSinkFactory.__call__` creates a
  fresh `.incoming/<camera>/<uuid>` directory before sink/property
  configuration and releases only its byte reservation on construction
  failure. Repeated failures can therefore accumulate unbounded directories
  and inodes. The reviewer attempted the combined suite but its sandboxed uv
  cache was denied and its escalated retry was interrupted without a result;
  it makes no test claim. The controller's independent 408-pass result remains
  valid at the reviewed hashes. Bounded fix round three is assigned to the
  same implementer under TDD, including failed directory-removal/fsync
  ownership and retry before any later UUID allocation.
- Slice B fix-round-three RED is frozen before production edits. Two focused
  parameterized tests produced six failures in 0.55 seconds: both sink
  construction and property-configuration failures leave UUID generation
  directories, and injected directory-removal/parent-fsync cleanup failures
  prematurely release the 100-byte staging reservation instead of retaining
  bounded cleanup ownership. GREEN must retry the exact pending directory
  before allocating another generation path and may not accumulate failed
  UUID directories.
- Controller review extended round three before freeze with three concurrency
  and partial-filesystem cases. RED produced two failures and one passing
  different-camera control in 5.74 seconds: a partially successful generation
  `mkdir` remained unowned, and a simultaneous same-camera construction
  reached the sink factory instead of failing before retry/UUID/path mutation.
  GREEN therefore needs a bounded per-camera construction phase plus cleanup
  ownership registered before `mkdir`, while retaining concurrency across
  different cameras.
- Slice B fix round three is frozen without a commit for another fresh
  exact-hash review. The final ten focused lifecycle cases pass in 0.44
  seconds, all 59 evidence tests pass in 1.47 seconds, and all 418 combined
  source-profile/native-probe/DeepStream/evidence tests pass in 44.18 seconds.
  Scoped Ruff lint, `py_compile`, conflict-marker, and whitespace checks are
  clean. The seven non-evidence hashes remain exact from round two; the new
  hashes are
  `evidence.py=8e367d05ab3830d03ae7d6bd041c63b6429a8acddf9c1b12333f789efca22913`
  and
  `test_evidence.py=48d4eae188de98a4767936d9f9a4d1141cffc03a683c442d1aa620dc7d9e87ab`.
  Construction ownership is claimed before `mkdir`, failed cleanup is retried
  before any later same-camera UUID or disable, active same-camera
  construction is rejected before mutation, different cameras remain
  concurrent, and cleanup-pending writer callbacks stay inert. Independent
  review is active; no Slice B approval or Task 13 commit is recorded yet.
- The controller independently reproduced the round-three freeze: all 418
  combined tests passed in 80.85 seconds at the exact nine hashes; scoped Ruff
  lint, `py_compile`, and `git diff --check` also pass.
- Fresh exact-hash Slice B round-three review rejects the freeze at C0/I1/M0.
  The reviewer made no edits, confirmed all nine hashes, independently passed
  all 418 tests in 45.19 seconds, and passed scoped Ruff/whitespace checks.
  The remaining gap spans the real factory/runtime boundary: if retained
  construction cleanup fails again during the first `stop()`,
  `DeepStreamDataPlane` clears `_graph` before re-raising, so a second
  `stop()` no longer calls `disable(camera_id)` and falsely succeeds while the
  factory still owns one directory and a 100-byte staging reservation.
  Bounded fix round four is assigned to the same implementer under TDD. The
  runtime must retain a finite exact-camera disable obligation across graph
  clearing, remove it only after collaborator success, and retry it on a later
  stop/start boundary without double-closing leases.
- Slice B fix-round-four RED is frozen before production edits. The exact
  real-factory two-stop regression collected one case and failed in 0.34
  seconds: after the second stop, directory-removal attempts remained at two
  instead of three, `_graph` was already `None`, the generation path still
  existed, the ring still charged 100 bytes, and the lease had correctly
  closed only once. This independently reproduces the lost cleanup obligation.
- After the two-stop test became GREEN, a separate startup-gate RED proved a
  retained `camera-01` obligation was skipped: `start()` reached NVIDIA
  binding load and raised `NvidiaBindingsUnavailable` without calling the
  evidence collaborator. GREEN must retry/fail on retained evidence cleanup
  before graph construction, host validation, binding load, or other new-run
  effects.
- Slice B fix round four is frozen without a commit for another fresh
  exact-hash review. The runtime now owns a bounded exact-camera evidence
  disable set, seeds it before graph clearing, attempts every retained camera
  on every stop, removes only successful identities, and preflights the set
  before any new start effect. Four focused lifecycle tests pass in 0.33
  seconds and all 420 combined Slice B tests pass in 83.59 seconds; scoped
  Ruff lint, `py_compile`, conflict-marker, and whitespace checks are clean.
  Changed SHA-256:
  `deepstream.py=f52235fb22d44824aa2fb672108b04ca3814a639413976cb3bfa45cdf9a2eaf9`
  and
  `test_deepstream_native_integration.py=b5a9337d182b25941d22f9cece38d7585ba9a2d12b359bfe2290f5631676c3c6`.
  The other seven round-three hashes remain exact. Independent review is
  active; no Slice B approval or Task 13 commit is recorded yet.
- The controller independently reproduced the round-four freeze: all 420
  combined tests passed in 59.82 seconds, scoped Ruff lint and
  `git diff --check` pass, and all nine SHA-256 values match the freeze.
- Fresh exact-hash Slice B round-four review rejects the freeze at C0/I1/M0.
  The reviewer made no edits, matched all nine hashes, and independently
  passed all 420 tests in 44.98 seconds. Fragment-adoption failure still calls
  `factory.disable(camera_id)` outside the new retry ledger; if disable also
  fails, writer shutdown and recovery are skipped, the generation remains
  authorized/bound, and no retry identity is retained. Bounded fix round five
  is assigned to the same implementer under TDD. The failure path must fence
  authority first, seed the exact-camera cleanup ledger before the
  collaborator, guarantee recovery despite cleanup failure, and retry that
  camera before constructing a replacement so repeated failures cannot
  accumulate stale writers.
- C1 operational-version reconciliation preserves the independently approved
  `acceptance_operational.py` and `test_acceptance_operational.py` byte for
  byte at
  `cee09ce67ce894ca9920219b5fc8017f0a5857a9b6d72949d0c0870433a043cc`
  and
  `ff395edd565843759a2213a9d6e60912b73fe323b9175fe400227fe7043060f5`.
  Its 1,059-case frozen suite passes. The evaluator is a pure,
  side-effect-free leaf with deliberate exact-V1 input checks, so the later
  live V2 boundary will use canonical composition and exact reparse into the
  frozen algorithm, bind all constituent/evaluator digests in an outer V2
  snapshot/result, and never subclass, alias, rename, or expose the V1
  evaluator as execution authority. Historical report V1 remains
  verification-only; the other currently live acceptance/trust/authority/
  report contracts still require the clean V2 migration identified by C1.
- Slice B fix-round-five RED is frozen before production edits: two exact
  regressions failed in 0.40 seconds. Adoption plus disable failure left the
  generation `authorized` rather than `quiescing` and aborted subsequent
  shutdown/recovery; repeated source construction reached `gst.Bin` before
  retrying the retained exact-camera disable, proving no pre-allocation gate
  existed.
- Slice B fix round five is frozen without a commit for another fresh
  exact-hash review. All evidence disable calls now route through one durable
  exact-camera ledger. Adoption failure fences the generation first, then
  independently attempts ledger cleanup, writer NULL, and camera recovery;
  no cleanup exception can skip later actions or escape the bus callback.
  Source-bin construction retries the exact pending camera before any
  GStreamer element or evidence-writer allocation. Seven focused lifecycle
  tests pass in 0.24 seconds and all 422 combined Slice B tests pass in 45.34
  seconds; scoped Ruff lint, `py_compile`, conflict-marker, and whitespace
  checks are clean. Changed SHA-256:
  `deepstream.py=d6fdfae72d64d5f457d417aea553f0f08a81d28c5e4b8fcd2580ffaed19893d5`
  and
  `test_deepstream_native_integration.py=ea26b54e3935c449b327e37001df5e45886e3350d84547d4837345627bbb08b8`.
  The other seven hashes remain exact. Independent review is active; no Slice
  B approval or Task 13 commit is recorded yet.
- The controller independently reproduced the round-five freeze: all 422
  combined tests passed in 45.71 seconds, scoped Ruff lint and
  `git diff --check` pass, and all nine SHA-256 values match the freeze.
- Task 13 DeepStream Slice B round-five exact-hash review is APPROVED at
  C0/I0/M0. The reviewer made no edits, matched all nine frozen hashes,
  independently passed all 422 targeted tests in 47.00 seconds, and passed
  scoped Ruff/whitespace checks. The approved slice includes shared
  one-stack topology, native parser/decoder/NTP correlation with per-
  constituent epoch fences, generation-safe cutover/rollback, camera-local
  malformed-cap recovery, pre-authority/stale-writer evidence fencing, and
  durable bounded construction/unbind/disable cleanup across failure,
  stop/start, adoption, and replacement paths. Slice B is complete. This is
  portable contract/fake-GStreamer evidence only; native NVIDIA/DeepStream,
  exact-20 RTSP, throughput/headroom, endurance, and soak acceptance remain
  externally PENDING and belong to later target slices.
- Task 13 Slice C1 acceptance-version integrity started with a fresh
  implementer and an isolated fixture-only child. The child generated the
  immutable historical V1 verification corpus from `git archive 400fe18`
  using an ephemeral Ed25519 key and retained only the public key, signed
  report artifacts, verification metadata, and fixture manifest under
  `tests/pilot/fixtures/acceptance_v1_400fe18/`. Controller inspection found
  exactly six retained files and no private-key marker; all manifest hashes
  match and independent `openssl pkeyutl -verify -rawin` reports
  `Signature Verified Successfully`. Before any C1 production edit, the
  implementer froze an explicit RED:
  `tests/pilot/test_acceptance_version_integrity.py` produced 12 failures and
  2 passing controls in 0.30 seconds. The failures cover the absent explicit
  live V2 names/schemas/SPKI fields, exact-schema dispatcher/concrete
  verifiers, and read-only `acceptance_legacy_v1` module. The controls prove
  SPKI normalization stability and absence of a retained private key. C1
  GREEN implementation is active; no C1 approval or Task 13 commit exists.
- Controller comparison against `git show 400fe18:protector/pilot/acceptance.py`
  caught and removed two premature hardenings from the read-only legacy
  verifier: historical V1 did not add `O_NONBLOCK` to its bounded read and did
  not validate the inner signed-envelope schema tag. The implementation now
  preserves those historical quirks, the original caught-exception set, and
  the lack of an exact 64-byte signature check; the exact metadata dispatcher
  remains responsible for selecting V1 versus V2. A dedicated unchecked-inner-
  schema regression was added. The implementer passed its legacy/golden slice
  with 8 passes and 7 deselections; the controller independently passed the
  expanded legacy/frozen/private subset with 9 passes and 6 deselections in
  0.26 seconds.
- C1 first GREEN checkpoint migrates the live acceptance manifest/run/report,
  trust, authority, proof, controller, replay, and publication family to
  explicit V2 names and schema tags without V1 aliases or V2-to-V1 fallback.
  An additional RED isolated the still-ambiguous SPKI-valued
  `VerifiedDetachedArtifact.trust_key_sha256` and live
  `TargetRunAttestationV1`; both are now V2/`*_spki_sha256`. A separate
  strictness RED proved byte-to-string coercion was still accepted by the
  signed V2 envelope. The signed envelope and verification metadata now use a
  local strict/frozen/extra-forbid model. Controller verification passes all
  17 version-integrity cases in 0.30 seconds and `git diff --check`; one
  import-order Ruff item remains for the implementer to clean before freeze.
  `measured-gpu-inventory.v1` is deliberately reserved for Slice C2's typed
  observed-GPU V2 boundary, and the independently approved operational/DeepStream
  files remain untouched.
- Read-only auth-gap preflight confirms 18 existing auth/security tests pass
  and the primitives are sound (Argon2id, encrypted TOTP, atomic replay
  protection, opaque 15-minute sessions, CSRF, throttling, role checks), but
  there is no safe first-admin bootstrap or admin user lifecycle. The bounded
  post-Task-13 slice will add a one-shot zero-user-only bootstrap, normalized
  case-insensitive usernames, durable `auth_generation`, last-active-admin
  protection, admin-only create/role/active/password/TOTP/session-revoke
  operations, immediate session invalidation, and atomic redacted site-scoped
  auth audit. It will not add an unauthenticated bootstrap API, default
  credentials, user deletion, or durable session tokens.
- Read-only packaging preflight confirms base Compose currently interpolates
  acceptance/Telegram-only required variables even when those capabilities
  are not selected; Compose interpolation happens before profile filtering.
  The bounded packaging slice will keep a renderable core Compose file and
  move acceptance and notification services/secrets/networks into separate
  fail-closed overlays. Backup/restore scripts already enforce strong fresh-
  target and signed/encrypted evidence gates, but no deployable job contains
  all required tools. A dedicated digest-pinned, non-root ops image plus
  separate least-privilege backup and restore job overlays is required;
  successful container exit alone will never count as an accepted restore.
- Read-only event/evidence preflight confirms the shared DeepStream graph,
  timestamp/epoch-safe zone-line engine, WAL-first candidate service, encoded
  fragment rings, bounded preview workspace, immutable object publication,
  and candidate-only human-review semantics already exist and are heavily
  tested, but production never composes them. The post-Task-13 implementation
  is split into six reviewable slices: separately signed camera-scoped
  analytics config and compiler; immutable config/provenance persistence;
  generation-fenced internal candidate writes; a bounded non-blocking runtime
  observation worker using the existing event engine/rings; crash-safe
  pending-preview receipts after immutable remote verification; and a
  site-authorized, audit-before-response, size/hash/key-checked preview reader
  plus admin draft/activate workflow. No FFmpeg, database, HTTP, or object
  storage work may run on the GStreamer/GLib callback thread; no continuous
  raw-video reference or automatic action is introduced.
- Task 14 read-only preflight confirms all five planned runbooks are absent
  and the plan also needs a sixth `handover_manifest.md` to satisfy its
  immutable artifact-inventory requirement. Documentation must split the
  investor M2 demo from the controlled pilot, keep target L4/exact-20/8h/72h
  and restore/rollback/rotation evidence explicitly PENDING until real
  artifacts exist, reproduce canonical commands rather than abbreviations,
  and provide named-operator drills for confirmed, rejected, source-outage,
  evidence-pending/failure, and notification-failure cases. Camera replacement
  is change-controlled/reaccepted rather than hot CRUD; TOTP/master-key
  rotation remains an implementation gap, not an invented SQL procedure.
  Entrance-only lawful-gallery face recognition is documented only as a
  separate unimplemented opt-in future subsystem because the current pilot
  scope excludes face recognition.
- Fixture-child finalization disclosed that its last temporary-directory
  removal had been interrupted. Controller inspection found the exact
  `/private/tmp/kuzet-acceptance-v1-400fe18.vjNqbA` archive workspace still
  contained `ephemeral-private.pem`; the exact temporary workspace was
  removed and a follow-up search found no `ephemeral-private.pem` under
  `/private/tmp`. The tracked golden fixture remains public/signed material
  only and is unchanged.
- C1 bounded debugging preserved the host-reboot fence while correcting the
  API-restart integration fixture to reuse one simulated host boot identity.
  Typed V2 durable serialization then exposed recursive `exclude_none=True`
  dropping required-null baseline resource fields; all durable request paths
  now reparse and serialize exact V2 contracts without deleting nested
  required nulls. Finally, the rooted integration exposed the prohibited
  unsigned bare-run fallback in `_attested_final_response`; it is removed and
  target finalization now requires the run signer, protected proof store,
  rooted V2 attestation, and sealed journal proof.
- C1 is frozen without a commit at exact hashes recorded in the controller
  handoff. The expanded 37-case integrity matrix proves signed legacy V1
  rejection before production trust/process/state effects across controller,
  start/sample/fault inject+recover/finalize, cached response/row/effect
  recovery, proof publication, writer, and report CLI. Implementer evidence:
  40 focused passes in 22.69 seconds, 123 authority/controller/proof/version
  passes, 347 report/trust passes with 1 skip, clean scoped Ruff and
  whitespace checks. Controller independently reproduced 40 passes in 19.00
  seconds, 123 passes in 49.34 seconds, 347 passes plus 1 skip in 49.65
  seconds, clean Ruff, `py_compile`, and `git diff --check`. Frozen
  operational and approved Slice-B hashes remain exact. A fresh exact-hash
  independent C1 review is active; no approval or Task 13 commit exists.
- Fresh exact-hash C1 review rejects the freeze at C0/I1/M0. The reviewer made
  no edits, matched all 34 supplied hashes (the 17 C1 files, six public golden
  fixture artifacts, frozen operational pair, and nine approved Slice-B
  files/tests), independently passed the 40-case focused suite in 20.69
  seconds, the 123-case authority/controller/proof/version suite in 56.08
  seconds, and the report/trust suite with 347 passes plus one skip in 54.32
  seconds; scoped Ruff and whitespace checks pass. The sole Important finding
  is that `scripts/pilot/acceptance_report.py verify` requires every rooted V2
  trust/evidence argument and calls `_verified_report_inputs` before inspecting
  the outer verification-metadata schema. The exact historical V1 fixture
  therefore cannot use its promised metadata-plus-public-key,
  verification-only CLI path, and supplied V2 arguments can cause V2 reads,
  verification, and temporary-key work before V1 refusal. Direct V1 library
  verification remains correct. C1 bounded fix round one is assigned to the
  same implementer under TDD: add actual CLI pre-effect tripwires, dispatch the
  exact outer schema first, route V1 only to the non-authorizing historical
  verifier, and require/re-evaluate full rooted evidence only for V2. All other
  frozen C1, operational, Slice-B, and fixture bytes remain locked.
- A fresh read-only C2 target-runtime contract audit completed with no edits
  and no NVIDIA claims. It confirms the current target lane is
  non-authoritative: injected factories bypass source validation; the process
  boundary is `object` plus `getattr`/`hasattr`; absent observed GPU evidence
  falls back to the signed expectation; the full observed inventory is
  discarded behind a digest; a caller scalar supplies effective throughput;
  the general/migrating collector journal is created before native prewarm;
  and production provides no exact-20 native lease factory. C2 will be an
  additive V2 authority lane around the frozen C1 and Slice-B code. Its RED
  matrix covers typed request/factory/process contracts, complete observed GPU
  inventory, one production tracker with exactly twenty reviewed
  bridge/lease bindings, child-only consumption of the nonserializable native
  receipt, a bounded launch-bound O_EXCL completion projection, strict
  `launch -> identity -> fresh >=60s exact-20 prewarm -> new journal ->
  collector -> gate clock` ordering, unique offered/completed work measured
  over monotonic time at `>=1.25x` the centrally derived frozen rate, separate
  exclusive V2 creation versus byte-preserving read-only completed recovery,
  and a new runtime-restart epoch whose policy leaves enough time for another
  full prewarm. Existing V1/current/mixed/incomplete journals, caller scalar
  capacity, old receipts/epochs, and the historical roughly-three-second
  restart policy are non-authorizing. The later Slice-D proof graph must bind
  the C2 source/GPU/prewarm/work/journal evidence so the legacy target lane
  cannot regain authority.
- C1 CLI fix-round-one RED is frozen before production changes. Nine focused
  actual-boundary regressions fail with 39 deselections in 1.80 seconds while
  `scripts/pilot/acceptance_report.py` remains byte-identical at
  `ada853c2c896775b765656747fe25338b0e562786f9bda5c9c074ea07eeb1aee`.
  The failures cover a real subprocess verification of the exact V1 fixture,
  V1-only dispatch with V2 effect tripwires, malformed/missing/unknown
  metadata invoking no verifier, mutated V1 refusal without V2 work, V1 plus
  V2-only argument refusal before verification, and incomplete V2 rooted
  inputs failing before verification/effects. All nine currently fail at the
  parser's unconditional rooted-V2 requirements, exactly reproducing the
  independent review finding.
- C1 CLI fix-round-one GREEN is under broad verification. Generate retains
  parser-required rooted V2 inputs. Verify now performs a bounded outer-schema
  read first; exact V1 accepts only metadata plus public key and invokes only
  the historical non-authorizing dispatcher, while malformed/unknown metadata
  and mixed V1/V2 arguments fail before any verifier or V2 effect. Exact V2
  requires the complete rooted argument set before trust/evidence work and
  still re-evaluates the signed report against its rooted evidence. The ten
  report-CLI cases pass with 38 deselections in 0.90 seconds. After a
  mechanical import-order correction, the controller independently passes the
  expanded 49-case version-integrity/rooted-route suite in 26.92 seconds;
  scoped Ruff, `py_compile`, and whitespace checks pass. Final broad evidence,
  exact hashes, and fresh re-review remain pending.
- C1 CLI fix round one is frozen at
  `scripts/pilot/acceptance_report.py=69cfb92853c53834f829e45cb2732a0d40e53d20484fdb01d27cb2ba8b7d23ce`
  and
  `tests/pilot/test_acceptance_version_integrity.py=5f22948d0c1f9ad460267e428b0d6331b210eb609bda03b36e567b245be72171`.
  Implementer evidence after the import-order correction: 49 focused passes
  in 17.33 seconds; 132 authority/controller/proof/version passes in 52.03
  seconds; 347 report/trust passes plus one skip in 59.14 seconds; clean
  scoped Ruff, `py_compile`, and whitespace checks; successful OpenSSL legacy
  verification; exact six-file public fixture with no private key. The
  controller independently passed the 49-case focused suite. All other C1,
  operational, fixture, and Slice-B hashes remain locked. A new independent
  exact-hash fix reviewer is active; C1 is not approved until its verdict.
- Independent minimal-design review found one C2/Slice-B integration
  contradiction that the fake factories did not exercise. The approved
  `_rebuild_source` stages `factory.acquire()` for a replacement before
  retiring the rollback-capable old generation, while the exact native tracker
  permits only one bound callback per camera and the bridge permits only one
  live lease. A production exact-20 factory therefore cannot satisfy the
  current replacement seam. Treating every second acquisition as process
  fatal is fail-closed but violates camera-local recovery by advancing and
  interrupting all twenty stream epochs; it is allowed only as an
  unrecoverable fallback. Before C2, narrowly reopen only `deepstream.py` and
  its graph/native-integration tests for a transactional generation-lease
  handoff seam: stage an inert facade, atomically activate a fresh exact inner
  lease at cutover, restore the retiring facade with a fresh inner lease on
  rollback, and leave the other nineteen cameras unchanged. Source-probe,
  source-profile, evidence, and operational bytes stay frozen unless tests
  prove the three-file amendment impossible. The amendment requires its own
  TDD matrix, full Slice-B suite, and fresh exact-hash review. C2 then proceeds
  in sequential typed-contract/GPU, exact-20 child/receipt, unique-work/
  completion, host-order/journal/collector, restart-policy, and portable
  integration slices. The legacy `replay_20.run_target` lane remains
  historical and explicitly non-authorizing.
- Fresh exact-hash C1 CLI fix re-review rejects round one at C1/I0/M0. All 17
  C1, two operational, nine Slice-B, and six public fixture hashes matched
  before and after; no files were changed. A deterministic no-write race
  classified the first CLI capture as `acceptance-verification.v1`, changed
  the bytes seen by the generic library dispatcher to V2, invoked only the V2
  verifier, and returned CLI success with no rooted V2 arguments, trust,
  evidence, or report reevaluation. Possession of a report-signing key could
  therefore be elevated into apparent acceptance authority. Stable-file
  tripwires pass but do not cover mutation between captures. C1 bounded fix
  round two must freeze a RED for that exact swap, bind version selection and
  direct version-specific verification to one captured metadata/bundle
  identity, and compare V2 rooted expectations against the envelope from the
  same verified capture rather than rereading mutable paths. The reviewer
  could not complete its pytest retry after the sandboxed uv cache failed and
  the later retry was interrupted; it makes no independent broad-suite claim.
- The original C1 implementer was resumed twice for fix round two but produced
  no file or hash change and no RED before its stalled turn was interrupted.
  A fresh focused implementer now owns the same bounded TDD correction. This
  reassignment does not inherit approval: it must freeze the deterministic
  swap RED, preserve the historical V1 module byte-for-byte, implement the
  capture-aware V2 result and single-capture CLI flow, reproduce the broad
  suites, and undergo another fresh exact-hash review.
- C1 fix-round-two RED is now frozen before its production correction. The
  three new capture-boundary cases fail with 51 deselections in 4.03 seconds:
  the V2 capture bundle API is absent, the CLI calls rooted inputs without a
  captured report-key payload and still rereads via its generic verifier, and
  a failed V2 capture is never attempted before rooted/generic work. Command:
  `PYTORCH_ENABLE_MPS_FALLBACK=1 UV_CACHE_DIR=/private/tmp/kuzet-uv-cache uv
  run --offline pytest -q tests/pilot/test_acceptance_version_integrity.py -k
  'capture_verified_v2_bundle or uses_verified_bundle_report or
  failed_v2_capture'`. This is the expected RED for the immutable V2 bundle
  and single-capture CLI flow; no production implementation was present.
- A fresh read-only post-Task-13 audit confirms four locally implementable
  areas remain after acceptance authority: the target entrypoint must compose
  generation-fenced candidates with bounded event/evidence workers and
  durable preview receipts; administrator bootstrap/lifecycle and
  `auth_generation` invalidation are missing despite existing Argon2/TOTP/
  CSRF primitives; core Compose currently expands optional acceptance and
  notification variables and needs separately renderable fail-closed
  overlays plus pinned non-root backup/restore jobs; and all five Task-14
  runbooks plus the handover manifest are absent. Exact lawful twenty-source
  input, Linux NVIDIA/DeepStream/TensorRT execution, measured 8h/72h capacity,
  live PostgreSQL/site storage/TLS/NTP checks, fresh-target restore, and named
  operator/customer sign-off remain external gates. These findings add no
  production-ready claim and do not change the MVP reel or Gradio paths.
- The second C1 fix-round-two implementer produced the intended new RED tests
  but then remained running through repeated controller prompts without any
  production-file change or progress report. It was interrupted after the
  controller had independently reproduced and recorded RED. A third fresh,
  narrowly scoped implementer is assigned only the immutable V2 capture and
  CLI flow; approval still requires GREEN evidence and an independent review.
- A separate read-only Task-13 architecture audit confirms the strict
  dependency order `C1 -> transactional lease handoff -> typed target/C2 ->
  authority snapshot + dual evaluation -> proof publication/pass-only
  attestation`. For the three-file lease amendment it requires inert staged
  facades, one exact live inner lease per camera, cutover activation only
  after block/link, fresh old-generation reacquisition on rollback, and
  camera-local fail-closed recovery with the other nineteen epochs unchanged.
  C2 should be additive typed modules/entrypoint rather than an extension that
  makes legacy `run_target` authoritative: full observed GPU identity,
  child-only exact-20 prewarm receipt consumption, a bounded no-replace
  completion projection, centrally derived unique-work headroom, fresh
  campaign journals, and restart re-prewarm. Finalization must remove the
  caller-supplied candidate, capture an immutable authority snapshot, run both
  standard and frozen operational evaluators without short-circuiting, and
  progress durably through snapshot/evaluation/finalization/proof/attestation;
  failed evaluation may sign run evidence but never an acceptance attestation.
- C1 fix-round-two reaches focused GREEN: the exact three previously failing
  capture-boundary tests now pass with 51 deselections in 1.15 seconds. The
  implementation adds an immutable exact-byte V2 bundle, reuses the initial
  metadata capture, carries the captured report key into policy pinning, and
  compares the captured signed report directly; the V1 path invokes the
  historical verifier directly. Broad verification and independent review
  remain mandatory before C1 approval.
- Controller verification for C1 fix round two is clean at the frozen
  candidate hashes: `acceptance.py=b465add826fcd87c579266c7d5b7bbc76b3334b4eef4ebf9c5e15f7f9c9c78c8`,
  `acceptance_report.py=9c1b4860c9b5509ab2b57757962e0617f9cd94fe643c55a75e5a8f9045ac7dc1`,
  and
  `test_acceptance_version_integrity.py=91b6e5945cdbe7e276074e160510efa48611a33d906b19f2a5e526699294e9c7`.
  Results: 54/54 version-integrity passes; 138/138 authority/controller/
  trust-controller/proof/version passes; 347 report/trust passes plus one
  intentional skip; scoped Ruff and `py_compile` pass; `git diff --check`
  passes. Historical V1 remains `4dddfb...b61210`; frozen operational source
  and test remain `cee09c...043cc` and `ff395e...60f5`. A distinct read-only
  reviewer now owns the exact-hash C1 verdict.
- Independent C1 fix-round-two review rejects the candidate at C0/I1/M0 even
  though it judges the production implementation to close the elevation path.
  The Important is test evidence: the existing metadata case mutates before
  CLI capture and patches an unused reader; the report mutator is attached to
  the intentionally unused generic verifier so no swap occurs; and the key
  case presents the wrong key before bundle capture. The bounded fix loop is
  test-only: wrap the real initial/bundle capture, mutate each filesystem path
  immediately after successful capture, assert the mutation occurred, and
  prove direct V1 rejection or exact captured V2 report/key authority. The
  reviewer independently confirmed all candidate/frozen hashes, five fixture
  hashes, OpenSSL verification, 54 focused passes, one rooted compatibility
  pass, clean Ruff, and clean whitespace.
- The C1 bounded test-only fix is frozen at
  `test_acceptance_version_integrity.py=e228ee3340c41184fb298dd2893dca65769363fe4a2bdad99f2defcfb5005801`;
  both production hashes remain unchanged. The metadata regression now
  captures actual V1 bytes and replaces the path with a valid V2 bundle before
  direct historical verification. The report regression captures signed
  report A, replaces its envelope path with valid report B, and proves A is
  compared. The key regression captures signing key K1, replaces its path
  with K2, and proves rooted policy pinning receives exact K1 bytes. Each
  asserts the swap occurred and tripwires generic/reread paths. Controller
  evidence: three focused passes with 51 deselections, 54/54 full
  version-integrity passes, clean scoped Ruff, and clean whitespace. The same
  independent reviewer is rechecking only this bounded correction.
- C1 immutable V2 capture and CLI verification are APPROVED C0/I0/M0 at the
  frozen production/test hashes above. The independent re-review confirmed
  that all three regressions now cross a real successful capture boundary,
  mutate the filesystem afterward, and would fail the rejected round-one
  dispatcher/reread flow. Reviewer evidence: three race passes with 51
  deselections, 54/54 version-integrity passes, clean scoped Ruff and
  whitespace, unchanged frozen V1/operational hashes, and exact five-artifact
  public V1 fixture. Resumption point advances to the three-file
  transactional source-generation lease handoff; C2 remains blocked until
  that amendment is separately tested and reviewed.
- A fresh nested implementer now owns the lease-handoff amendment under the
  exact three-file scope. Pre-amendment hashes are
  `deepstream.py=d6fdfae72d64d5f457d417aea553f0f08a81d28c5e4b8fcd2580ffaed19893d5`,
  `test_deepstream_graph.py=10d3e1fedac31f255aeb09e1e8da6f936176fdbabaeb0f1c943d167f4605a430`,
  and
  `test_deepstream_native_integration.py=ea26b54e3935c449b327e37001df5e45886e3350d84547d4837345627bbb08b8`.
  Source-probe/profile/evidence production and test hashes were rechecked
  exact before delegation. The required TDD result is a DeepStream-owned
  inert transactional facade with cutover-only inner acquisition, fresh old
  reacquisition on rollback, stale-callback fencing, and camera-local
  fail-closed restore failure; no factory/probe widening is authorized unless
  the RED matrix proves this seam impossible.
- Lease-handoff RED is frozen at
  `test_deepstream_native_integration.py=c377a4ba3179611fb4ac31b68871186c17bf9579f2628cdbc2bfc80586a1c17d`
  while both production and graph-test hashes remain pre-amendment exact.
  Seven cases fail with 66 deselections: inert staged facade/single-live
  acquisition, selected-camera-only cutover, sync rollback with fresh old
  inner, failed old reacquisition with nineteen-camera isolation, in-flight
  callback drain before replacement acquisition, BaseException activation
  rollback, and exact-once stop after failed restore. The primary failure is
  the intended contradiction: `_build_source_generation` calls
  `factory.acquire` while the old camera lease is still live, so the
  one-live-per-camera factory refuses every staged replacement. The controller
  independently reproduced all seven failures before production changed.
- Lease-handoff focused GREEN now passes all seven cases with 66 deselections
  in 0.42 seconds. The current implementation uses one stable
  `_TransactionalSourceProbeLease` facade per generation: replacement builds
  inert, the old facade drains in-flight calls and closes its inner only at
  cutover, then the replacement acquires its inner; rollback closes the
  replacement inner and reacquires a fresh old inner before sync/unblock.
  Failed restore leaves the affected camera inert and force-recovers it while
  the nineteen untouched generations retain identity and lease state. Legacy
  Slice-B expectation reconciliation and the complete 422-test suite remain
  pending; these candidate hashes are not yet frozen or reviewed.
- A parallel read-only admin-lifecycle audit is complete for the later
  post-Task-13 slice. It confirms the current login uses Python `casefold()`
  against SQL `lower()`, users lack normalized identity and
  `auth_generation`, session revocation is cookie-local, `add_user` is
  unaudited, user audits are not site-attributable, and no first-admin or
  lifecycle API exists. The bounded design assumes the already enforced
  single-site database: migration `0005` adds unique NFKC+casefold
  `normalized_username` and positive `auth_generation`; one site-row lock
  serializes zero-user bootstrap and last-admin checks; every credential,
  role, active, or explicit-revoke mutation increments generation and inserts
  the redacted site audit atomically; sessions compare the durable generation
  on every request. A secret-file-only one-shot bootstrap CLI precedes API
  start, while admin routes cover list/create/role/active/password/TOTP/
  session-revoke with CSRF, optimistic generations, no credential material in
  audit, and post-commit bounded in-memory purge. PostgreSQL concurrency
  remains a real-target verification in addition to portable SQLite tests.
- Lease-handoff integration verification reached 73/73 native cases and 47/47
  graph cases, but the expanded full Slice-B run exposed one bounded
  BaseException rollback defect: 429 passed and
  `test_baseexception_from_old_inner_close_still_reacquires_fresh_old_inner`
  failed. The facade clears its inner before calling `inner.close()`, but
  `_rebuild_source` records `old_lease_deactivated=True` only after that call;
  a `KeyboardInterrupt` from close therefore skips fresh-old reacquisition.
  The implementer is fixing the state-transition ordering and must preserve
  the primary BaseException after successful rollback, then rerun all 430
  cases. No review or candidate freeze occurs before that GREEN.
- The partial-detach fix is GREEN at final candidate hashes
  `deepstream.py=c6e4321e733377afaeb2c7a0d032b302dcea3582623db3fe7b760beaee4008c9`,
  `test_deepstream_graph.py=0d9f90f6ecb3dcf5fb84211595eb1a0a3334245fd3e84a43286e911df42d5b26`,
  and
  `test_deepstream_native_integration.py=b26e92cd11834e3f49725dea0b72e5b69ec33c9fd0945e9ffa0353d01b706711`.
  Controller evidence on these exact bytes is 430/430 full Slice-B passes in
  44.93 seconds; the implementer additionally reports 8 focused passes and
  121 graph/native passes. Scoped Ruff, formatter check, `py_compile`,
  whitespace, and conflict-marker checks pass; all six frozen probe/profile/
  evidence hashes remain exact. Scope caveat: the implementer ran
  `ruff format`, which reported `2 files reformatted`, and no pre-amendment
  byte snapshot is recoverable from temp or unreachable Git blobs. Because
  the reformatted files are within the explicitly reopened three-file scope,
  the candidate is frozen rather than guessed back; its independent reviewer
  must review the whole exact files and explicitly account for that expanded
  mechanical diff before approval.
- The transactional source-generation lease handoff is independently
  APPROVED at C0/I0/M0. The reviewer confirmed all three exact candidate
  hashes and all six frozen probe/profile/evidence hashes, reviewed the whole
  formatter-expanded three-file scope, and found no actionable lifecycle,
  authority, rollback, concurrency, stale-callback, cleanup, copy, or
  serialization defect. Fresh reviewer evidence is 121/121 graph/native
  passes and 430/430 full Slice-B passes, with clean scoped Ruff, formatter,
  `py_compile`, and whitespace checks. The structural `SourceProbeLease`
  annotation is imprecise but not a runtime capability defect; a shallow
  facade copy aliases the exact same bridge lease and cannot retain authority
  after that generation is closed. Resumption advances to the additive typed
  target/NVIDIA C2 authority lane. The legacy `replay_20.run_target` path
  remains expressly non-authorizing, and no target-GPU result may be claimed
  in this Apple environment.
- C2 slice 1 is delegated to a fresh implementer under a new-file-first TDD
  scope: typed target launch/process/factory contracts, full observed-GPU
  identity, exact-twenty source binding, and a fresh native-prewarm receipt
  with single-consume/no-replace bounded projection. Existing seam hashes at
  delegation are `acceptance.py=b465add8...c78c8`,
  `acceptance_authority.py=2fdbede3...9807`,
  `container_runner.py=9ac31913...9900`,
  `deepstream.py=c6e4321e...8c9`,
  `replay_20.py=63af42bb...3dc`, and
  `test_container_runner.py=edaaa946...217`. The legacy replay target path
  is frozen as non-authorizing for this slice: injected or generic
  process-like objects, launch expectations, caller throughput scalars, or a
  digest without the complete observed inventory cannot create acceptance
  authority. This Apple host can validate contracts and hostile fakes only;
  native NVIDIA/DeepStream execution stays pending.
- A second read-only post-Task-13 gap audit confirms the implementation order
  after the acceptance freeze. Administrator lifecycle must reserve migration
  `0005` and add NFKC+casefold identity, positive `auth_generation`, sole-site
  locking for first/last-admin invariants, atomic redacted audits, and
  secret-file-only bootstrap. Production analytics/event/evidence then uses
  additive signed camera-rule configuration, immutable active revisions and
  event provenance, generation/epoch-fenced machine writer receipts, a
  bounded nonblocking runtime worker around the existing shared graph/ring,
  immutable verified preview upload receipts, and a site-authorized bounded
  preview reader. Packaging follows the real entrypoints: a renderable core
  Compose plus separately selected runtime, acceptance, Telegram, backup, and
  fresh-target restore overlays with a pinned non-root operations image.
  Task-14 docs and a digest/status handover manifest come last. The audit
  specifically confirms that the current native main drains no observations
  into `EventEngine`/`SiteEventService`, candidate rows lack runtime/config
  provenance, production has no preview provider, base Compose eagerly
  expands optional service inputs, and all handover documents are absent.
  Existing reviewed primitives should be wrapped rather than reopened.
- The read-only finalization audit is complete and freezes an additive V3
  design rather than widening historical V2. Current V2 accepts a caller or
  adapter `candidate`, never invokes either acceptance evaluator inside the
  authority, and signs structurally valid run evidence regardless of pass;
  its proof cannot replay evaluator identities or results. V3 therefore
  removes the candidate/finalizer seam, commits one canonical no-replace
  authority snapshot, runs the standard and frozen operational evaluators in
  independent try boundaries without short-circuiting, derives acceptance
  only as `C2 && standard && operational`, and separates signed run evidence
  from a pass-only acceptance attestation. Durable progression is
  `RUNNING -> SNAPSHOT_COMMITTED -> EVALUATED -> FINALIZED ->
  PROOF_PUBLISHED -> ATTESTED`, with exact recovery only from immutable
  artifacts and identical pins. The additive V3 proof has
  534/4,374 entries and 536/4,376 lines for 8h/72h by appending one snapshot,
  one standard evaluation, one operational evaluation, and one final decision
  to the ordinary evidence. A per-site transactional contiguous repository
  high-water/hash chain is required before snapshotting; caller UUID/time or
  sequence-with-rollback-gaps is not authority. Historical V1/V2 proof,
  fixtures, and frozen operational bytes remain verification-only and
  byte-compatible.
- C2 slice-1 RED is independently frozen before production files exist.
  `test_acceptance_target.py` and `test_native_acceptance.py` collect-fail
  because `protector.pilot.acceptance_target` is absent (two collection
  errors in 0.30 seconds). The tests demand strict immutable full GPU
  inventory, exact ordered twenty-source launch binding, typed observation
  without a digest fallback, restart epoch/prewarm mismatch rejection,
  centrally derived rate properties, and a one-shot noncopyable native
  receipt projector with bounded canonical O_EXCL output. The production
  implementation must additionally ensure that arbitrary caller counters and
  a digest are not sufficient unique-work authority; that is either closed in
  this slice or left explicitly un-authorizing for the next bounded C2 slice.
- The independent RED-matrix reviewer found three authority-critical gaps
  before implementation: an arbitrary duck-typed factory could self-report a
  caller-built identity, a canonical caller-built prewarm projection could be
  confused with child receipt authority, and arbitrary counters plus a digest
  could manufacture apparent headroom from historical launch scalars. The
  slice is therefore bounded to strict typed observation/projection contracts
  that remain explicitly non-authorizing until private controller/child and
  unique-work capabilities are integrated in later C2 slices. The first
  implementer turn produced only RED tests and no checkpoint or production
  file despite repeated messages, so it was interrupted and resumed with this
  narrower fail-closed contract scope. Approval still requires new hostile
  tests, GREEN, and exact-file independent review.
- The C2 integration audit fixes the remaining dependency sequence. C2.2 must
  extend the exact Docker runner to retain and reverify the complete observed
  GPU inventory, then introduce a private controller-owned process/factory
  and protected descriptor-relative request/response channel; public
  Protocol helpers stay non-authorizing. C2.3 must add a manifest-role-signed
  exact-20 source-profile attestation and a real child lease owner for one
  tracker, twenty bridges/current leases, proof issuance, live receipt
  consumption, and native projection; source commitments cannot be caller
  values. C2.4 derives a finite unique-work schedule centrally from the
  verified manifest and enabled shared graph, records unique post-analytics
  completions, recomputes a bounded ledger, and alone derives the >=25%
  throughput headroom—no launch scalar, caller counter, digest, or universal
  camera/GPU coefficient participates. C2.5 enforces exact ordering:
  trust/profile -> protected channel -> Docker/full GPU identity -> child
  exact-20 >=60s prewarm -> unique-work gate -> private C2 capability -> new
  O_EXCL journal -> collector -> gate clock. A runtime restart is a
  controller-owned new process/epoch with full GPU reobservation and fresh
  prewarm, never historical `docker restart`. The audit also found that the
  current production native main supplies no lease factory even though graph
  start requires one, and the Docker process currently discards the complete
  GPU object after hashing it. Those are locally implementable gaps, not
  evidence of target execution.
- C2 slice-1 implementation is frozen for exact-file review at
  `acceptance_target.py=8d736d275a8600265bd5450f1ed494ea137eb5eea8718a7edbf28442d12612c7`,
  `native_acceptance.py=8244bc8a327c2ede8ef645572c9bfe6bb1b003bbf5b37c9ee26a2bda98d25999`,
  `test_acceptance_target.py=96ffe60776f91c9298bf7f2ec726bbae45362e02b22142e594c464c0ff21bf24`,
  and
  `test_native_acceptance.py=9d05bef08d6214553afa5aa487aa4f40f4f53d3b3e8a4e285e8d46da8d01b7a6`.
  The final bounded close-failure RED was two failures proving output/parent
  descriptor errors masked or prevented the second close; its GREEN is two
  passes with ten deselections. Controller evidence is 24/24 focused passes
  and 153/153 passes across the slice, native-source receipt, and V2 capture
  integrity tests. Scoped Ruff, formatter, `py_compile`, and whitespace
  checks are clean. All four artifacts carry literal `authorizing=false`;
  there is no accepted/headroom property, and the fake factory, caller JSON,
  counters, and digest are observation-only. Full target authority remains
  pending C2.2–C2.5; the reviewer must not approve this slice as hardware or
  capacity evidence.
- Independent review rejects C2 slice 1 at C0/I1/M0 for one bounded descriptor
  lifecycle defect. `_open_parent` opens the directory and performs `fstat`
  outside cleanup protection; an `fstat` failure leaks the descriptor.
  Reviewer reproduction observed `OSError` with no close attempt, while the
  other contract/capability/authority boundaries were clean. The original
  implementer is resumed for a two-branch TDD correction only: prove close is
  attempted after `fstat` failure and prove a simultaneous close failure is
  grouped after the primary. The same reviewer will recheck new exact hashes.
- The bounded parent-descriptor fix is GREEN. Its exact selector moved from
  two failures/twelve deselections to two passes/twelve deselections; full
  slice is 26/26 and related compatibility is 155/155. `_open_parent` now
  catches `BaseException` from parent `fstat`, attempts the descriptor close,
  and emits either the primary or an ordered group containing the primary
  followed by close failure. New hashes are
  `native_acceptance.py=482a5a173f4258c33941444caf92df8c77e1d9abb12e997a5e54c373a9bbab98`
  and
  `test_native_acceptance.py=ea800a5c563a7728f8e6043af5c4460c57125b25890d26f772f6ed997299bf08`;
  the other two slice hashes are unchanged. Ruff, formatter, `py_compile`,
  and whitespace checks are clean; exact-hash re-review is in progress.
- C2 slice 1 is independently APPROVED at C0/I0/M0 after the bounded fix.
  Reviewer evidence is 26/26 focused and 165/165 expanded compatibility
  passes with clean Ruff, formatter, `py_compile`, and whitespace checks.
  Approval is explicitly limited to non-authorizing contracts and prewarm
  evidence; it does not complete C2, certify a GPU, or authorize capacity.
  Resumption advances to C2.2a: exact runner retention/reverification of the
  full typed observed GPU object and private construction of runner-owned
  processes, before the protected controller/child channel is added.
- C2.2a is delegated to a fresh implementer under the exact two-file scope
  `container_runner.py=9ac31913b8ed2d6d429107c9284cbdc3274bac19239e06d6b5668b7352f89900`
  and
  `test_container_runner.py=edaaa946b02fd597990d528e38fdfa8362bc20b5a70e0472e1c1741d0ecdb217`.
  RED must prove private process issuance, complete immutable observed
  inventory retention, strict reparse, and drift rejection. The resulting
  runner remains a prerequisite, not an authority lane; controller IPC,
  native child issuance, unique-work measurement, journal ordering, and all
  NVIDIA claims stay outside this slice.
- C2.2a RED is frozen and controller-reproduced before production change:
  twelve failures with seventeen deselections. The public process constructor
  accepts no issuer token, no complete typed inventory is retained/exposed,
  nine inventory-field drifts collapse into the old digest/generic path, and
  NVIDIA container-toolkit drift is not re-observed at all. The exact selector
  is `nonissuer or retains_and_reverifies or
  complete_inventory_field_drift`; production remained at its delegated
  pre-hash during RED.
- After the first moving GREEN, the independent reviewer reproduced four
  still-open capability/lifecycle defects: shallow copy duplicated the live
  container control wrapper, mutating the returned Pydantic `__dict__`
  changed stored inventory, the issuer token was a directly importable module
  global, and the mandatory second observation could fail without container
  reconciliation. The implementer converted the expanded hostile matrix into
  a non-aborting RED of six failures, one existing restart-requery pass, and
  thirty deselections. The failures also cover deepcopy/pickle, an untyped
  callback, and ordered `KeyboardInterrupt` plus cleanup failure. No
  second-round production correction preceded this RED.
- C2.2a is frozen for exact-byte review at
  `container_runner.py=e3afab9e0984f6624c5a1bbbea5a625fe87f5f5e7b3edca066d1c62bbe49129d`
  and
  `test_container_runner.py=416cf602f44f19c460460e523de78484824e1a9c98da83713d5554951ae69cc5`.
  The hostile selector is 7/7 GREEN, full runner tests are 40/40, and the
  controller independently reproduced 66/66 runner plus approved target/
  native contract passes. Scoped Ruff, `py_compile`, and whitespace checks
  pass. Both whole files pre-existed outside Ruff formatter normalization and
  remain formatter-dirty; the implementer deliberately did not mechanically
  rewrite the broad in-scope files, so the reviewer is inspecting their exact
  complete bytes rather than accepting an unreviewed format expansion. The
  candidate stores the initial inventory as immutable canonical bytes,
  returns a fresh strict model, rejects copy/deepcopy/pickle, re-observes all
  GPU/toolkit facts on verify/restart, and reconciles post-start failure with
  ordered BaseException grouping. It remains non-authorizing.
- C2.2a is independently APPROVED at C0/I0/M0 on the frozen hashes.
  Reviewer evidence is 40/40 runner, 66/66 runner plus approved target/native,
  and 156/156 legacy acceptance-report passes, with clean Ruff, `py_compile`,
  and whitespace. The inherited whole-file formatter delta is explicitly
  non-gating and was inspected in full. Approval proves portable runner
  ownership/inventory behavior only; it is not an NVIDIA observation.
  Resumption advances to C2.2b, an additive exact controller-owned
  Docker-process observation wrapper with no injectable factory/process and
  no acceptance semantics.
- C2.2b is delegated to a fresh implementer under two new files only:
  `acceptance_target_controller.py` and its focused test. The wrapper must
  derive every Docker image/network/GPU/runtime expectation from the strict
  request, call the exact runner internally with no public process/factory/
  run/clock/inventory seam, require the exact issuer-minted process type, and
  build a non-authorizing runtime identity after full re-verification.
  Post-launch failure must remove the exact process once with ordered
  BaseException preservation. Protected IPC and command/mount content
  authentication remain the next boundary rather than being implied here.
- C2.2b RED is frozen and controller-reproduced before production creation:
  the focused test collection fails because
  `protector.pilot.acceptance_target_controller` does not exist (one error in
  0.43 seconds). The bounded identity convention is
  `process_id=docker:<container-id>` and
  `runtime_boot_id=container:<container-id>`; in-place Docker restart is
  deliberately excluded from authority, so later accepted restart must
  launch a new container/process/epoch.
- C2.2b implementation is locally GREEN at
  `acceptance_target_controller.py=609e669484e060030e2c29db81007019b2257a01b33bdc7af6f586bbcaaefdcb`
  and
  `test_acceptance_target_controller.py=d2401aa16eb63f6f57dc5e5a5eb07d55c9344475dc30becd4eec92ad5d319c1b`.
  Controller evidence is 11/11 focused, 78/78 controller/runner/target/native,
  and 156/156 legacy acceptance-report passes; both new files pass Ruff,
  formatter, `py_compile`, and whitespace checks. The exact wrapper derives
  every runner expectation from the strict request, accepts only the exact
  issuer-minted process, binds full inventory/container/network/controller
  identity, rejects copying/serialization, and owns bounded cleanup/
  reverification. It is still explicitly non-authorizing. Per the user's
  request to avoid micro-review loops, this candidate will be included in one
  broad independent Task-13 review after the remaining authority components
  are integrated rather than receiving another standalone review turn.
- The user explicitly rejected further micro-review churn. Remaining Task 13
  work is therefore running as three large independent implementation batches:
  signed exact-20 native source authority, centrally derived unique-work
  authority, and additive V3 snapshot/dual-evaluator/final-proof authority.
  Each batch froze a real missing-module RED before production creation. One
  independent broad review and one bounded fix loop will cover the integrated
  Task 13 candidate before its commit.
- Task 14 handover documentation began with eight expected failures: six
  required files were absent, README did not separate the investor MVP from
  the unvalidated pilot, and the authoritative gate links were absent.
  GREEN adds the operator, incident-response, deployment, model-register,
  known-limits, and handover-manifest documents plus the explicit README
  boundary. The focused suite is 8/8; its test passes Ruff and the complete
  documentation batch passes `git diff --check`. All hardware/site evidence,
  digests, named sign-offs, 8-hour replay, and 72-hour soak remain visibly
  PENDING rather than being fabricated from Apple-host results.
- Task 13 C2.3 exact-20 native source authority is GREEN in four new files.
  The missing-module RED preceded implementation. Focused verification is
  7/7; the expanded source/profile/probe/DeepStream/native/target set is
  404/404, with clean Ruff, format check, `py_compile`, and whitespace.
  Frozen hashes are
  `acceptance_source_profile.py=fc913300f375b045b2bcd2d4ca9a7d46e5e330a1ea596ee6ec35339f47875d52`,
  `native_source_authority.py=f8114f738af6262bdde5566bf195ebeb292bfb6945bb273e7c22f5a7db4eda58`,
  `test_acceptance_source_profile.py=fe80388fba514dfb69234921d4aecf593930c0dc2353779dc611da0c0706297f`,
  and
  `test_native_source_authority.py=6a47711e6ea458e9cda5f37f41bc67c640f2832180faadd064871ae63d8e4051`.
  This proves signed/immutable portable contracts and hostile fakes only; real
  NVIDIA, lawful RTSP secrets, and physical exact-20 acceptance remain
  external.
- Task 13 C2.4 unique-work authority is GREEN in four new files after the
  expected two missing-module collection REDs. Focused verification is 17/17
  and the expanded target/native/controller/runner/work set is 95/95, with
  clean Ruff, formatter, `py_compile`, and whitespace. Frozen hashes are
  `acceptance_work.py=9e259029b640de77afb5311f1a4bf30f5485d1bf693a3be3a5061a40d46ae2ea`,
  `work_authority.py=bed04c34f3fd7405d0866aee66b5f1406bfd866ef0f4a48810421b315308941f`,
  `test_acceptance_work.py=0a8301d973b6884ae43af3680d3a9b97cf1a281e244e37224d353b5a2c9f54d5`,
  and
  `test_work_authority.py=41904e36806ffe695a8db8e7a9842a7cedd7fda019934e85285fcec19ffb7429`.
  The schedule/headroom evidence is derived from verified signed context and
  exact completed work, not launch scalars. DeepStream callback/child IPC
  integration and real NVIDIA execution remain pending.
- Task 14's one independent review returned C0/I4/M0: missing actionable
  support routes, incomplete deployed-image digest inventory, non-executable
  migration/backup/restore handover steps, and phrase-only tests that missed
  those omissions. One batched correction added three failing regressions,
  then completed the PENDING support roster, all image-family digest rows,
  real migration/provision/backup/restore entrypoints and required fresh-target
  receipt, credential rotation, and stronger drill/manifest assertions.
  Task 14 is now 11/11 focused with clean Ruff and whitespace; no further
  wording review loop is planned.
- Task 13 additive V3 snapshot/evaluation/finalization/proof batch is frozen
  GREEN in four production files and four focused tests. The four
  missing-module REDs preceded implementation. Focused V3 is 19/19; targeted
  historical V1/V2 smoke is 66/66; Ruff, formatter, `py_compile`, and
  whitespace are clean. A broader regression reached 1,105 passes with no
  failures before one exceptionally slow legacy operational parameter was
  manually interrupted, so it is explicitly not recorded as a complete-suite
  pass. Historical V1/V2 and frozen operational hashes remain unchanged.
  Production controller/provider wiring is still required before the
  integrated Task 13 review and commit.
- Post-Task-13 administrator lifecycle has a frozen RED in four new test files:
  25 expected failures and one 404 control pass after the existing auth/security
  baseline passed 27/27. Planned GREEN remains bounded to migration 0005,
  normalized identity, durable `auth_generation`, zero-user secret-file
  bootstrap, last-admin protection, admin lifecycle routes, immediate session
  invalidation, and atomic redacted audit. No acceptance or handover file is
  in that agent's scope.
- Cloud-continuation checkpoint: the Codex app exposes only the Local host and
  explicitly does not support cloud handoff of this current local worktree.
  All code, tests, hashes, external gates, and the resumption point are durable
  in this worktree and ledger. On resume: finish auth GREEN; wire the additive
  V3/C2 providers into the production acceptance controller; run one broad
  integrated Task 13 review/fix/commit; then implement the event/evidence
  composition and packaging batches, commit Task 14, run whole-branch
  verification, and finish the branch without push/merge/deploy.
- Replacement-controller resume proof: the connected GitHub app resolved
  `codex/kuzet-20-camera-pilot` to
  `ae18d636c2df333591bc747a855b4e4730ff3267`, exactly the required
  `ae18d63` checkpoint. Repository metadata and the committed `AGENTS.md`,
  design, plan, and this ledger were read in that order before any local
  implementation work. No write was made to `main`, no PR was opened, and no
  deployment was attempted.
- Administrator lifecycle is offline GREEN after a fresh independent source
  review of the complete checkpointed candidate. The review found no contract
  defect across NFKC-plus-casefold identity, positive `auth_generation`,
  zero-user/sole-site bootstrap, last-admin locking, atomic redacted audit,
  and immediate durable session invalidation. Scoped production, lifecycle,
  and legacy auth/security sources compile; `git diff --check` is clean; Ruff
  WASM 0.16.1 reports no E/F/W finding and only ten pre-existing whole-file
  `I001` import-order findings caused by formatter-version drift. The pinned
  environment could not be installed because this cloud denies PyPI package
  downloads, so pytest collection did not begin and no test pass is claimed.
  Exact deferred commands are:
  `uv run pytest tests/pilot/test_auth_api.py
  tests/pilot/test_api_security.py
  tests/pilot/test_api_security_migration.py -q`;
  `uv run pytest tests/pilot/test_auth_lifecycle_migration.py
  tests/pilot/test_auth_lifecycle_repository.py
  tests/pilot/test_auth_lifecycle_api.py tests/pilot/test_bootstrap_admin.py
  -q`; and `uv run ruff check migrations/versions/0005_auth_lifecycle.py
  protector/pilot/api/auth.py protector/pilot/api/dependencies.py
  protector/pilot/api/routes_auth.py protector/pilot/api/app.py
  protector/pilot/storage/models.py protector/pilot/storage/repositories.py
  scripts/pilot/bootstrap_admin.py tests/pilot/test_auth_lifecycle_*.py
  tests/pilot/test_bootstrap_admin.py`. PostgreSQL 16+ online migration plus
  concurrent first-admin and last-active-admin locking remain an explicit
  external gate because `psql`, `pg_isready`, `initdb`, `postgres`, Docker,
  and Podman are absent. The current resumption point is production V3/C2
  acceptance-controller integration, followed by its broad Task-13 review.

## Replacement cloud implementation closeout — 2026-07-31

- Before implementation, the connected GitHub app read the repository and
  resolved `codex/kuzet-20-camera-pilot` to the exact full SHA
  `ae18d636c2df333591bc747a855b4e4730ff3267`. It then read the committed
  `AGENTS.md`, design, plan, and this ledger in the required order. The
  checkpoint matched the required `ae18d63` start. No work targeted `main`;
  no PR, merge, or deployment was performed.
- The remaining cloud-safe production scope is implemented: one shared
  multistream runtime; bounded/leaky observation and event queues; supervised
  per-camera source recovery, epochs, timestamps, and state; a hardware-decode
  adapter; cross-camera batching; shared models; immutable configuration and
  rule provenance; writer-bound PostgreSQL persistence; bounded event,
  evidence, preview, and operational-metadata retention; strict database-role
  and machine-auth boundaries; migrations `0006_event_provenance` through
  `0008_runtime_persistence`; and fail-closed runtime composition.
- Continuous video remains in the customer NVR. Only bounded event evidence
  and metadata enter pilot storage. Every alert remains a human-confirmed
  candidate. No police, fire-system, door, or other automatic action was
  added. Face recognition and watchlist collection remain excluded. Heavy
  X-CLIP/ViT and whole-frame OWLv2 remain shadowed or disabled pending lawful
  site-specific validation.
- Task 13 now includes controller-owned acceptance V3 authority, exact signed
  source/profile/work bindings, protected capture/snapshot/proof state,
  restart continuation through a fresh third runtime epoch, authenticated
  external executor and observer acknowledgements, durable transition
  journals, strict signed reports, and append-only recovery/publication
  behavior. Portable fake/replay evidence remains explicitly
  non-authorizing.
- The target runner finalizes only through the packaged authenticated
  loopback route
  `/api/internal/acceptance/v3/collectors/{collector_id}/finalize`. It uses
  bounded, no-redirect, no-retry transport, strictly validates the bounded V3
  result, and requires the exact collector and accepted bound verdict. The
  controller, Compose, runner, and handover commands use the same exact
  STATE, PROOF, SNAPSHOT, CHANNEL, and CAPTURE roots.
- Packaging adds digest-pinned runtime, API, acceptance-controller, admin,
  backup, restore, retention, and optional Telegram compositions; non-root,
  read-only, no-new-privilege service boundaries; explicit secrets and
  networks; render-only runtime command validation; strict bind-mount
  contracts; and hash-locked dependencies. Docker and Podman were unavailable,
  so the files were rendered and statically validated only.
- Task 14 provides the Ready-to-Start checklist, deployment, operator, and
  incident runbooks, model register, known limits, support and training
  records, handover manifest, credential rotation, migrations, backup,
  restore, rollback, and exact external acceptance instructions. The investor
  reel, clip manifest, Gradio application, and demo audit/scenario modules are
  byte-unchanged from the replacement checkpoint.

### Replacement TDD and review record

- The integrated review first found that the target runner constructed and
  finalized a separate local V3 controller. The frozen RED required the exact
  packaged route; the fix removed local V3 authority construction and made
  that route the sole finalization path.
- The next hostile pass found that a latest-frame cursor could overtake a
  same-camera backlog, and that DeepStream published a frame heartbeat before
  all selected detections. RED evidence included a 128-observation/64-item
  batch and a premature periodic cursor. The fix uses an atomic
  sequence-bearing drain, post-publication completed-frame watermarks,
  per-camera monotonic frontiers, epoch-scoped drop fencing, and serialized
  epoch recovery. Zero-detection frames still complete without inventing an
  observation.
- The same pass found that the worker discarded degraded
  `SiteEventStatus`, allowing candidate-journal exhaustion to remain silent.
  REDs covered startup, observation, periodic, malformed, secret-bearing, and
  unbounded status results. The worker now retains only bounded/redacted
  health and fails closed on `candidate_journal_full` or
  `candidate_journal_write_failed` before counting the observation complete.
- A final hostile pass found one stale first status snapshot when the pending
  evidence-depth probe failed. Its RED returned
  `degraded=False, reasons=()`. The service now snapshots reasons after all
  journal probes; the first returned status reports
  `pending_evidence_depth_failed`. That reason is visible but is not confused
  with the two terminal candidate-loss reasons.
- Two deterministic test defects were corrected without weakening production
  contracts: the restart-before-drain test now injects the supervisor clocks,
  and the DeepStream packaging test verifies dependency pins in the
  hash-locked requirements file copied by the Dockerfile.
- Final fresh independent whole-branch verdict on the exact frozen
  implementation bytes: **C0 / I0 / M0**. No replacement-review minors are
  parked. Hardware, provider, and customer-acceptance gates below are explicit
  external blockers, not local review findings.

### Available cloud verification

- Independent focused and contract verification: **190 passed, 2
  dependency-guarded skips**. This includes event worker 11/11; supervisor
  17/17; parametrized worker/supervisor/GStreamer limits 13/13; DeepStream
  no-argument contracts 33/33; packaged V3 route behavior 1/1; first status
  snapshot 1/1; isolated production worker-failure loop 1/1; continuation
  contract and behavior 11/11; operational retention, JSONB compatibility,
  mount modes, target launch, and strict validator 27/27; trusted YAML 18/18;
  packaging 34/34; handover docs 21/21; and authority YAML 2 passed plus 2
  dependency-guarded skips.
- PGlite accepted the operational-retention SQL and the regenerated migration
  sequence through `0008`, including runtime claim, configuration, epoch,
  event, evidence, storage, and downgrade checks. `libpg-query` parsed 105/105
  PostgreSQL statements; nine SQLite trigger bodies were intentionally
  outside that parser.
- `compileall`, `py_compile`, `git diff --check`, and conflict-marker checks
  are clean. Ruff WASM 0.16.1 reports zero E/F/W findings across 195 Python
  files under the repository's Python 3.12 configuration. All 13 production
  YAML files parse; 29/29 Markdown shell fences and 2/2 shell files pass
  `bash -n`; all 21 relative Markdown links resolve. Offline lock validation
  resolves 127 packages.
- The strict configuration contains exactly 20 unique camera identities and
  source indices. Its canonical site hash is
  `027ed8d3984c6a77c9390b20fc920daef85fadc7497161e59d3cdac799799825`.
- Full pytest is not claimed in this cloud. `pytest`, SQLAlchemy, FastAPI,
  Alembic, psycopg, Boto3, Prometheus client, and the pinned `av` wheel were
  unavailable offline. Docker, Podman, PostgreSQL executables, and
  `nvidia-smi` were absent. No CUDA, DeepStream, TensorRT, live PostgreSQL,
  Kazakhstan object-storage, live RTSP, exact-20, 8-hour, or 72-hour result
  was fabricated.

### External gates and exact next execution

- `docs/pilot/ready_to_start.md` freezes the exact pending V3 8-hour and
  72-hour target commands. They invoke `scripts/pilot/replay_20.py --mode
  target` for exactly 28,800 and 259,200 seconds, followed by
  `acceptance_report.py generate` and `verify`.
- Required target fixtures are the lawful signed 20-source manifest, source
  hashes and rights, three signed source profiles and nonces, site/runtime/
  capacity/mount artifacts, pinned image/model/engine/code/network/adapter/
  observer digests, independent adapter and observer roots, role keys,
  controller and machine tokens, and fresh private state/output roots.
- An authorized Kazakhstan target operator must still execute NVIDIA
  driver/toolkit, DeepStream, TensorRT engine-build and digest checks; lawful
  exact-20 RTSP or frozen-corpus execution; live PostgreSQL 16 migration,
  role, and concurrency checks; Kazakhstan-resident object-store lifecycle,
  versioning, encryption, and restore checks; browser, TLS, and notification
  checks; named operator training; and signed customer exceptions.
- Acceptance requires measured effective throughput with at least 25%
  headroom; GPU at most 75%; VRAM at most 80%; availability at least 99.5%;
  drops below 1%; queue age p95 below 1 second and p99 below 2 seconds; RTSP
  recovery within 30 seconds; candidate-to-event p95 at most 1 second; first
  preview p95 at most 2 seconds; and no crash, OOM, unbounded growth,
  cross-camera leakage, unaudited review, or notification before
  confirmation. No universal cameras-per-GPU coefficient is asserted.

## Final resumption point

Tasks 13 and 14 are complete for the safely implementable cloud scope. Human
review starts at
`ae18d636c2df333591bc747a855b4e4730ff3267..codex/kuzet-20-camera-pilot`.
The exact review head is the dedicated-branch commit containing this closeout
entry; publication is recorded by that branch ref because a commit cannot
self-reference its own SHA. There is no remaining cloud acceptance claim to
manufacture. After approval, resume only with the exact PostgreSQL/storage,
NVIDIA, exact-20, 8-hour, restore-drill, and 72-hour commands in the committed
runbooks, archive the signed artifacts and exceptions, and keep every
conditional analytic shadowed or disabled unless its lawful site gate passes.
