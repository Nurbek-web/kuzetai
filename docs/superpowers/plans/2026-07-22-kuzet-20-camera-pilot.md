# Kuzet AI 20-Camera Controlled Pilot Implementation Plan

> **For the implementation team:** Execute this plan task by task. Keep the current investor-demo pipeline working; production-pilot code lives under `protector/pilot/`. Use test-driven development and stop promotion of any model whose licence, target-site test, or capacity gate fails.

**Goal:** Deliver a human-in-the-loop pilot for the customer's exact 20 RTSP streams in 20 calendar days after a signed Ready-to-Start gate.

**Architecture:** A NVIDIA data plane ingests and supervises the 20 streams, keeps encoded evidence rings, batches GPU inference with DeepStream/TensorRT, and writes versioned candidate events to a local SQLite WAL crash journal before replaying them into PostgreSQL. A separate FastAPI control plane serves a responsive operator console, enforces TOTP/RBAC/audit, and sends one notification only after human confirmation. The existing NVR remains the system of record for continuous video.

**Technology:** Python 3.12, `uv`, FastAPI, SQLAlchemy/Alembic, PostgreSQL, SQLite WAL, S3-compatible evidence storage, NVIDIA DeepStream 9.1/GStreamer, TensorRT FP16, Prometheus, pytest, Docker Compose. DeepStream production tests run on an NVIDIA L4 host; the Apple M2 environment runs contracts, unit tests, API tests, and a fake/replay data plane. Pin the tested DeepStream container by digest. NVIDIA's current documentation marks legacy `pyds` bindings deprecated, so use Service Maker where practical and keep every NVIDIA binding behind the runtime adapter. See the [DeepStream 9.1 release notes](https://docs.nvidia.com/metropolis/deepstream/dev-guide/text/DS_Release_notes.html).

---

## Non-negotiable delivery rules

- Do not modify the behaviour of `protector/pipeline.py`, the investor reel, or the current Gradio demo while building the pilot.
- Do not run one Python/OpenCV/model process per camera. Use one shared, batched data plane with bounded, leaky queues.
- Every observation carries `camera_id`, source timestamp, monotonic sequence, model artifact ID, and runtime health context.
- Every alert is a candidate until an authorised operator confirms it. No automatic police call, door lock, fire-system actuation, or disciplinary action.
- Fire/smoke and weapon models are fail-closed. Missing commercial rights, missing artifact hash, failed site test, or failed capacity test means `disabled` or `shadow`, never silent production use.
- Fight/fall remain best-effort shadow analytics and cannot notify during this pilot.
- Face recognition, attendance, official watchlists, emotion inference, and native mobile applications are not part of this plan.
- A live 20-camera video mosaic is not part of the pilot; the console shows health, events, thumbnails, and requested evidence playback.
- Day 1 starts only when the Ready-to-Start checklist has all 20 named feeds, their codec/resolution/bitrate, NTP source, camera map, site access, compute, notification channel, and model-rights decisions.

## Current-model decision

| Current component | Day-20 decision | Required production action |
|---|---|---|
| `yolov8n-pose.pt` | Demo only; pose is unnecessary for core zones | Use a commercially cleared person detector exported to TensorRT; use tracker bottom-centre geometry |
| Hadi/WUHP weapon weights | Demo only until rights and target-site validation are documented | Register exact hashes/licences; otherwise replace with a cleared detector and keep weapon disabled |
| OWLv2 verifier | Candidate-only shadow verifier | Run only on bounded ROI candidates; never on every frame or every camera |
| Local fire/smoke weight | Demo only until rights and field tests pass | Register, export, benchmark, and promote through the fire gate; otherwise disable |
| X-CLIP + frame ViT violence stack | Not an operational alert | Keep outside the hot path; any experiment writes shadow events only |
| `IncidentFuser` | Reuse concepts, not frame-index timing | Build a timestamp-based, idempotent event engine with per-camera state |

The first commercially safe baseline to evaluate for people is an Apache-2.0 detector such as YOLOX, or a properly licensed NVIDIA/OEM people model. Do not select by licence label alone: store the exact model-card terms and artifact hash in the registry. Fire and weapon procurement is a Day-0 decision because the current weights are not a contractual asset merely because they run in the demo.

## Target repository layout

```text
protector/pilot/
  config.py                 # validated site/runtime settings
  domain.py                 # versioned cameras, observations, events, reviews
  gates.py                  # licence/site/capacity promotion state machine
  runtime/
    protocol.py             # DataPlane protocol used by fake and DeepStream adapters
    fake.py                 # deterministic M2/replay implementation
    supervisor.py           # camera state, reconnect, sequence and health logic
    deepstream.py            # NVIDIA-only Service Maker/GStreamer adapter
    evidence.py             # encoded fragment ring and clip assembly
    event_engine.py         # timestamp-based debounce/idempotency/state isolation
  storage/
    db.py
    models.py
    repositories.py
    journal.py               # local SQLite WAL crash spool before PostgreSQL ACK
    object_store.py
  api/
    app.py
    auth.py
    dependencies.py
    routes_auth.py
    routes_cameras.py
    routes_events.py
    routes_internal.py
  web/
    templates/
    static/
  notifications/
    base.py
    telegram.py
  metrics.py
  cli.py
configs/pilot.example.yaml
configs/models/*.yaml
deploy/pilot/
  Dockerfile.api
  Dockerfile.runtime
  docker-compose.yml
  prometheus.yml
migrations/versions/
scripts/pilot/
  model_audit.py
  replay_20.py
  build_engine.py
  acceptance_report.py
tests/pilot/
```

## Versioned contracts

Implement these interfaces before the NVIDIA work begins:

```python
class DataPlane(Protocol):
    def start(self, site: SiteConfig) -> None: ...
    def stop(self) -> None: ...
    def health(self) -> list[CameraHealth]: ...

class EvidenceStore(Protocol):
    def reserve(self, event_id: UUID, camera_id: str, start_at: datetime, end_at: datetime) -> EvidenceReservation: ...
    def finalise(self, reservation: EvidenceReservation) -> EvidenceRef: ...

class NotificationConnector(Protocol):
    async def send_confirmed(self, event: EventView, idempotency_key: str) -> DeliveryResult: ...
```

`ObservationV1` fields: `schema_version`, `observation_id`, `camera_id`, `stream_epoch`, `source_time`, `timestamp_quality`, `monotonic_seq`, `module`, `class_name`, `confidence`, normalised `bbox`, `track_id`, `model_artifact_id`, `runtime_state`, and `received_at`. `timestamp_quality` is `camera_rtcp` or `host_ntp_fallback`; a source restart creates a new `stream_epoch`.

`CandidateEventV1` fields: `event_id`, `camera_id`, `module`, `opened_at`, `last_seen_at`, `peak_confidence`, `reason`, `model_artifact_id`, `gate_mode`, `evidence_status`, `review_status`, and `dedupe_key`.

Allowed state transitions:

```text
observation -> candidate -> confirmed -> escalated
                         -> rejected
                         -> expired

model: disabled -> shadow -> operator
       any gate failure -> disabled
```

Only `confirmed` events may enter the notification outbox. Shadow events are visible in the dashboard but cannot enter that outbox.

---

### Task 1: Freeze configuration and production dependencies

**Files:**

- Modify: `pyproject.toml`
- Create: `protector/pilot/__init__.py`
- Create: `protector/pilot/config.py`
- Create: `configs/pilot.example.yaml`
- Create: `tests/pilot/test_config.py`

**Steps:**

1. Write failing tests for exactly 20 unique camera IDs, allowed H.264/H.265 codecs, positive bitrates, per-camera analytic frequencies, Kazakhstan storage endpoints, bounded queue sizes, and required Ready-to-Start fields.
2. Run `uv run pytest tests/pilot/test_config.py -q` and confirm the import/test failure.
3. Add pilot dependencies as an optional dependency group: FastAPI, Uvicorn, SQLAlchemy, Alembic, psycopg, boto3, Jinja2, python-multipart, pydantic-settings, pyotp, argon2-cffi, itsdangerous, Prometheus client, and httpx. Do not add NVIDIA bindings to the M2 dependency set; they come from the pinned target image.
4. Implement immutable Pydantic settings with secrets accepted only from environment variables or Docker secrets, never committed YAML.
5. Make `configs/pilot.example.yaml` a non-secret, commented 20-camera template with `analytics_hz` per module.
6. Run the new test, `uv run ruff check protector/pilot tests/pilot`, and the existing test suite.
7. Commit: `feat(pilot): add validated site configuration`.

### Task 2: Define domain contracts and model gates

**Files:**

- Create: `protector/pilot/domain.py`
- Create: `protector/pilot/gates.py`
- Create: `tests/pilot/test_domain.py`
- Create: `tests/pilot/test_gates.py`

**Steps:**

1. Write failing tests for JSON round-trips of `ObservationV1`, strict schema versions, UTC timestamps, normalised bounding boxes, deterministic dedupe keys, and legal state transitions.
2. Write gate tests proving that a model without `sha256`, source, explicit commercial-rights record, class list, preprocessing definition, target-site report, or 20-stream capacity report cannot become `operator`.
3. Implement frozen Pydantic domain models and a pure `ModelGate.evaluate()` function returning reasons, not booleans only.
4. Add a hard invariant: `shadow` and `disabled` events cannot create notification outbox records.
5. Run `uv run pytest tests/pilot/test_domain.py tests/pilot/test_gates.py -q`.
6. Commit: `feat(pilot): define event contracts and fail-closed model gates`.

### Task 3: Add PostgreSQL persistence and migrations

**Files:**

- Create: `protector/pilot/storage/db.py`
- Create: `protector/pilot/storage/models.py`
- Create: `protector/pilot/storage/repositories.py`
- Create: `protector/pilot/storage/journal.py`
- Create: `alembic.ini`
- Create: `migrations/env.py`
- Create: `migrations/versions/0001_pilot_core.py`
- Create: `tests/pilot/test_repositories.py`
- Create: `tests/pilot/test_journal.py`

**Steps:**

1. Test uniqueness of observation IDs and dedupe keys, camera/event filters, append-only audit records, atomic review transitions, idempotent outbox insertion, journal replay after a process restart, and acknowledgement only after a PostgreSQL commit.
2. Create tables for sites, cameras, camera health samples, model artifacts, gate reports, candidate events, evidence, users, reviews, audit entries, notification outbox, and delivery attempts.
3. Use database constraints for state values and uniqueness; do not depend only on API validation.
4. Keep raw continuous video out of the schema. Store only evidence object keys, hashes, codec, time range, and source reference. The bounded SQLite WAL journal buffers versioned events/evidence work during a control-plane outage and exposes its depth as a metric.
5. Run migrations against a disposable PostgreSQL service, then run repository tests twice to prove migration idempotency.
6. Commit: `feat(pilot): persist cameras events gates and audit records`.

### Task 4: Build authentication, authorisation, and the API shell

**Files:**

- Create: `protector/pilot/api/app.py`
- Create: `protector/pilot/api/auth.py`
- Create: `protector/pilot/api/dependencies.py`
- Create: `protector/pilot/api/routes_auth.py`
- Create: `protector/pilot/api/routes_cameras.py`
- Create: `protector/pilot/api/routes_events.py`
- Create: `protector/pilot/api/routes_internal.py`
- Create: `tests/pilot/test_auth_api.py`
- Create: `tests/pilot/test_event_api.py`

**Steps:**

1. Write API tests for password hashing, TOTP enrolment/verification, secure cookie flags, login throttling, role denials, CSRF on mutations, audit entries, pagination, filters, and stale/duplicate review requests.
2. Implement roles `viewer`, `operator`, and `admin`. Only operators/admins can confirm or reject; only admins can change cameras, users, or model gate mode.
3. Implement `/api/cameras`, `/api/events`, `/api/events/{id}`, `/api/events/{id}/review`, `/api/audit`, and internal authenticated observation/health ingestion.
4. Require an idempotency key for review and notification-producing mutations.
5. Redact RTSP credentials and secrets from all API responses and logs.
6. Run `uv run pytest tests/pilot/test_auth_api.py tests/pilot/test_event_api.py -q`.
7. Commit: `feat(pilot): add secured operator API`.

### Task 5: Implement the fake/replay data plane and camera supervisor

**Files:**

- Create: `protector/pilot/runtime/protocol.py`
- Create: `protector/pilot/runtime/fake.py`
- Create: `protector/pilot/runtime/supervisor.py`
- Create: `tests/pilot/test_supervisor.py`
- Create: `tests/pilot/test_fake_runtime.py`

**Steps:**

1. Test the camera state machine `starting -> online -> degraded -> offline -> reconnecting`, capped exponential backoff, source-time regression, duplicate sequence rejection, and isolation between camera IDs.
2. Create a deterministic fake runtime that replays fixtures, injects disconnects, and publishes the same versioned messages as DeepStream.
3. Expose metrics for last frame age, reconnect count, source-time skew, scheduled samples, dropped samples, queue age, and degraded reason.
4. Prove in a test that one camera's disconnect or stale timestamp cannot alter another camera's tracker/event state.
5. Run `uv run pytest tests/pilot/test_supervisor.py tests/pilot/test_fake_runtime.py -q`.
6. Commit: `feat(pilot): add deterministic multistream supervisor`.

### Task 6: Build the NVIDIA DeepStream data plane

**Files:**

- Create: `protector/pilot/runtime/deepstream.py`
- Create: `deploy/pilot/Dockerfile.runtime`
- Create: `configs/models/person_primary.yaml`
- Create: `deploy/pilot/deepstream/person_primary.txt`
- Create: `deploy/pilot/deepstream/nvtracker.yml`
- Create: `tests/pilot/test_deepstream_graph.py`

**Steps:**

1. Test graph configuration without importing NVIDIA bindings on M2: 20 sources, one mux, `batch-size=20`, `live-source=1`, bounded leaky queues, unique source IDs, GPU memory type, and no appsink/NumPy copy in the core path.
2. In the NVIDIA-only adapter, build one dynamic source bin per feed: RTSP depay/parser, encoded tee, NVDEC branch, and reconnect/error bus handling.
3. Batch decoded surfaces through `nvstreammux`, one FP16 person `nvinfer`, NvDCF tracker, and `nvdsanalytics`. Publish only metadata from a pad probe.
4. Put optional fire and weapon branches behind leaky queues and valves so failure or slowness cannot block person/zones or health reporting.
5. Pin the validated DeepStream 9.1 container by digest with its CUDA/TensorRT compatibility. Prefer Service Maker APIs; if a binding gap forces temporary legacy `pyds`, isolate it in this adapter and record its replacement issue. Refuse to start when engine compute capability or model hash differs from the registry.
6. On the L4 host run a 20-feed 8-hour replay; store JSON metrics and graph logs as build artifacts.
7. Commit: `feat(pilot): add batched DeepStream runtime`.

### Task 7: Add encoded evidence rings and clip assembly

**Files:**

- Create: `protector/pilot/runtime/evidence.py`
- Create: `protector/pilot/storage/object_store.py`
- Create: `tests/pilot/test_evidence.py`
- Create: `tests/pilot/test_object_store.py`

**Steps:**

1. Test fragment rotation, pre/post-roll selection, keyframe boundaries, expiry, bounded disk use, camera isolation, SHA-256 calculation, interrupted upload recovery, and deletion after retention.
2. Write 1–2 second encoded fragments from the source-side tee; retain a bounded 15-second ring per camera on the NVMe spool.
3. On candidate creation, pin the required fragments and produce a 4–10 second clip. Remux compatible H.264; use bounded NVENC transcode for H.265/browser-incompatible evidence.
4. Upload to Kazakhstan-resident S3-compatible storage or encrypted local evidence volume and atomically finalise the evidence row.
5. Return a thumbnail/first playable preview before post-roll finalisation; expose `pending`, `ready`, and `failed` states.
6. Run `uv run pytest tests/pilot/test_evidence.py tests/pilot/test_object_store.py -q`.
7. Commit: `feat(pilot): create bounded event evidence pipeline`.

### Task 8: Implement timestamp-based event fusion, zones, loitering, and lines

**Files:**

- Create: `protector/pilot/runtime/event_engine.py`
- Create: `tests/pilot/test_event_engine.py`
- Create: `tests/pilot/test_zone_analytics.py`

**Steps:**

1. Port geometry concepts from `protector/zones.py`, but test with normalised polygons, source timestamps, tracker resets, missing frames, and per-camera state.
2. Test N-of-M/time-window debounce using timestamps rather than frame indices; reject duplicate observations and cached display results.
3. Implement intrusion, loitering duration, directional line crossing, cooldown, merge windows, peak-confidence tracking, and evidence reservation.
4. Append candidate events to the bounded local WAL journal, then replay them idempotently into PostgreSQL. Queue overflow or journal write failure forces a visible degraded state; it must never drop silently.
5. Run `uv run pytest tests/pilot/test_event_engine.py tests/pilot/test_zone_analytics.py -q`.
6. Commit: `feat(pilot): add idempotent site event engine`.

### Task 9: Build the model registry, export tools, and conditional analytics gates

**Files:**

- Create: `scripts/pilot/model_audit.py`
- Create: `scripts/pilot/build_engine.py`
- Create: `configs/models/fire_candidate.yaml`
- Create: `configs/models/weapon_candidate.yaml`
- Create: `tests/pilot/test_model_audit.py`
- Create: `tests/pilot/test_model_promotion.py`

**Steps:**

1. Test that an artifact with unknown/ambiguous commercial rights fails before engine export or deployment.
2. Record source URI, exact SHA-256, licence evidence, classes, preprocessing, training/evaluation provenance, thresholds, TensorRT version, GPU architecture, and engine hash.
3. Export rights-cleared ONNX artifacts to FP16 TensorRT on the target L4. INT8 is allowed only with a versioned calibration corpus and a no-regression event report.
4. Run fire at approximately 1 Hz full-frame and weapon at approximately 1 Hz with person/ROI prioritisation. Use a heavy verifier only on strong bounded candidates; queue overflow must drop verifier work and expose a metric.
5. Create signed site matrices with positive scenes and hard negatives. The output for each module is exactly `operator`, `shadow`, or `disabled`, with reasons.
6. Do not include fight/fall in operational promotion tests; shadow experiments use separate artifact IDs and queues.
7. Commit: `feat(pilot): gate conditional models by rights quality and capacity`.

### Task 10: Build the responsive operator console

**Files:**

- Create: `protector/pilot/web/templates/base.html`
- Create: `protector/pilot/web/templates/login.html`
- Create: `protector/pilot/web/templates/dashboard.html`
- Create: `protector/pilot/web/templates/event_detail.html`
- Create: `protector/pilot/web/static/pilot.css`
- Create: `protector/pilot/web/static/pilot.js`
- Create: `tests/pilot/test_web_views.py`

**Steps:**

1. Test authenticated rendering, role-dependent controls, empty/error/loading states, escaping of notes, event filters, camera health, and evidence states.
2. Show 20 camera health cards, degraded reasons, searchable event table, module/gate badges, event detail, evidence preview, source timestamp, model version, notes, and confirm/reject controls.
3. Use server-rendered templates plus small progressive JavaScript/SSE updates; do not ship the demo Gradio UI as the production console.
4. Ensure a mobile browser can acknowledge/reject events; a native app remains Phase 2.
5. Run API/view tests and a keyboard-only/manual responsive review.
6. Commit: `feat(pilot): add secure operator console`.

### Task 11: Add reviewed-event notification delivery

**Files:**

- Create: `protector/pilot/notifications/base.py`
- Create: `protector/pilot/notifications/telegram.py`
- Create: `protector/pilot/notifications/worker.py`
- Create: `tests/pilot/test_notifications.py`

**Steps:**

1. Test that candidate, shadow, rejected, and expired events cannot notify; confirmed events produce exactly one outbox record despite retries.
2. Implement one connector selected at kickoff. Keep Telegram as the default only if the customer approves it and network policy permits it.
3. Include site/camera, source time, category, operator, evidence link, and event ID; never include RTSP credentials or unrestricted object-store URLs.
4. Use expiring signed evidence links, exponential retry, delivery audit, and a dead-letter state visible to operators.
5. Commit: `feat(pilot): notify only after authorised confirmation`.

### Task 12: Add observability, backup/restore, and deployment hardening

**Files:**

- Create: `protector/pilot/metrics.py`
- Create: `deploy/pilot/Dockerfile.api`
- Create: `deploy/pilot/docker-compose.yml`
- Create: `deploy/pilot/prometheus.yml`
- Create: `scripts/pilot/backup.sh`
- Create: `scripts/pilot/restore.sh`
- Create: `tests/pilot/test_metrics.py`
- Create: `tests/pilot/test_retention.py`

**Steps:**

1. Add Prometheus metrics for per-camera availability, last-frame age, reconnects, scheduled/dropped samples, queue age, model latency, candidate rate, evidence latency/failure, GPU/VRAM, disk, and notification delivery.
2. Add health/readiness endpoints that distinguish source outage, degraded analytics, and control-plane failure.
3. Run containers as non-root where supported, use read-only filesystems, explicit volumes, no host network, secret mounts, TLS reverse proxy, log rotation, resource limits, and Kazakhstan-resident storage configuration.
4. Implement encrypted database/evidence backups and a destructive-safe restore drill into a fresh target. A backup is not accepted until restore is demonstrated.
5. Add retention workers for fragments, evidence, audit, and metrics; prove disk use remains bounded.
6. Commit: `feat(pilot): harden and observe pilot deployment`.

### Task 13: Automate replay, failure injection, and acceptance reporting

**Files:**

- Create: `scripts/pilot/replay_20.py`
- Create: `scripts/pilot/acceptance_report.py`
- Create: `tests/pilot/test_acceptance_report.py`
- Create: `docs/pilot/acceptance_matrix_template.csv`
- Create: `docs/pilot/ready_to_start.md`

**Steps:**

1. Build a replay manifest for the exact 20 customer streams or lawful captured samples. Record codec, resolution, bitrate, expected analytic schedule, and source hash.
2. Inject camera loss, malformed timestamps, network pause, runtime restart, API restart, object-store outage, model timeout, and full verifier queue.
3. Run an 8-hour integration replay by Day 7 and a continuous 72-hour soak on Days 16–18.
4. Generate a signed HTML/JSON report with: uptime excluding source failure, reconnect p95/max, queue age p95/p99, scheduled-drop percentage, detection-to-event latency, first-preview latency, GPU/VRAM maxima, disk trend, and every exception.
5. Fail core acceptance on crash/OOM, unbounded disk/queue, cross-camera leakage, missing evidence, unaudited review, or notification without confirmation.
6. Report each AI module separately as `pass/operator`, `shadow`, or `disabled`; never turn demo confidence into a site accuracy percentage.
7. Commit: `test(pilot): automate twenty-stream acceptance evidence`.

### Task 14: Handover, operator training, and regression protection

**Files:**

- Create: `docs/pilot/operator_runbook.md`
- Create: `docs/pilot/incident_response.md`
- Create: `docs/pilot/deployment_runbook.md`
- Create: `docs/pilot/model_register.md`
- Create: `docs/pilot/known_limits.md`
- Modify: `README.md`

**Steps:**

1. Document start/stop, camera replacement rules, degraded states, review/escalation workflow, evidence export, credential rotation, backup/restore, rollback, and support contacts.
2. Record every deployed container digest, configuration hash, model/engine hash, migration revision, and gate report in the handover manifest.
3. Train named operators using confirmed, rejected, source-outage, evidence-pending, and notification-failure scenarios.
4. Run final verification:

   ```bash
   uv run pytest tests/ -q
   uv run ruff check protector tests cli.py
   git diff --check
   docker compose -f deploy/pilot/docker-compose.yml config
   ```

5. On the NVIDIA host, archive the successful 72-hour report, restore-drill output, field matrix, model register, and signed exception list.
6. Commit: `docs(pilot): add deployment and operator handover`.

---

## Calendar and ownership

| Days | Video/platform + CV | Backend/frontend | DevOps/QA/site | Exit condition |
|---|---|---|---|---|
| 0–2 | Model/right decisions; source profiling | Contracts, schema, auth skeleton | Ready-to-Start; L4/cloud; network/NTP | All 20 feeds and compute available; no unknown production weights |
| 3–7 | DeepStream core, tracker, zones/lines, evidence ring | Events/API/dashboard/auth | PostgreSQL/journal/object store/TLS; 8-hour replay | Stable 20-feed core and correct evidence |
| 8–11 | Conditional fire/weapon branches and profiling | Review/outbox/notification/UI | Metrics, backup/restore, on-site setup | Latency/reconnect gates; failed models disabled |
| 12 | Artifact and scope freeze | Scope freeze | Formal checkpoint | New features require change request |
| 13–15 | Site positives/hard negatives, threshold tuning | Workflow fixes only | Security checks, operator drills | Signed per-model pass/shadow/disabled result |
| 16–18 | Reliability fixes only | Reliability fixes only | 72-hour soak and failure injection | Platform thresholds pass with bounded resources |
| 19 | Regression and manifest | Documentation | Restore drill and training | Acceptance pack complete |
| 20 | Handover | Handover | Signed exceptions; shadow support starts | Controlled pilot operational |

Required parallel staffing: one video/platform lead, two CV engineers, one backend engineer, one frontend/integration engineer, one DevOps/security engineer, one QA/site engineer, plus part-time PM and privacy/legal review. With materially fewer people, reduce scope or extend the date; do not hide the staffing gap inside lower testing quality.

## Day-20 acceptance thresholds

- Exact 20 streams simultaneously for 72 hours.
- Analytical service availability at least 99.5%, excluding upstream source outage.
- Scheduled analysis sample drops below 1%.
- Queue age p95 below 1 second and p99 below 2 seconds.
- RTSP recovery within 30 seconds after source return.
- GPU utilisation at or below 75% and VRAM at or below 80% under the frozen replay; otherwise reduce sampling or add a second L4 before signing capacity.
- Candidate-to-event p95 at or below 1 second; first evidence preview p95 at or below 2 seconds.
- No crash, OOM, unbounded queue/disk growth, cross-camera state leakage, unaudited state transition, or notification before human confirmation.
- Fire and weapon quality are evaluated with a signed event-level site matrix and remain independent from core platform acceptance.

## Commercial implementation boundary

The fixed 19.8 million KZT engineering price buys the bounded scope above for one site and 20 named streams, plus 30 calendar days of shadow support covering core defects, monitoring, and one threshold-tuning cycle. It does not buy production HA/SLA, independent penetration testing/certification, continuous archive storage inside Kuzet, new cameras, native mobile apps, face/watchlist access, source-code assignment, or unlimited model retraining. Infrastructure is billed against the agreed cloud or on-premises allowance at actual supplier cost.

## Definition of done

The pilot is done only when the customer can see the state of all 20 cameras, review timestamped candidate events and evidence, confirm/reject with an audit trail, receive one approved notification after confirmation, operate zones/lines/loitering, and read a pass/shadow/disabled report for every conditional analytic. A polished demo running on selected clips is not completion.
