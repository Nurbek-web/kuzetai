# Kuzet AI 20-Camera Controlled Pilot Design

Date: 2026-07-22

## Decision

Build and sell a controlled, human-in-the-loop pilot for the customer's exact 20 RTSP cameras. The Day-20 handover is an operational pilot and acceptance report, not the complete production system described in the original specification.

The pilot must demonstrate a reliable multistream platform first. Analytics that have not passed the signed site test matrix remain in shadow mode and cannot trigger autonomous action.

## Commercial Boundary

- Fixed software, integration, deployment, training, and 30-day shadow-support price: **19,800,000 KZT**, excluding VAT.
- Kazakhstan-resident cloud allowance for the first month: **800,000 KZT**. Recommended cloud-pilot total: **20,600,000 KZT**, excluding VAT.
- Optional on-premises L4 server allowance: **11,500,000 KZT**. Recommended on-premises pilot total: **31,300,000 KZT**, excluding VAT.
- Cameras, cabling, UPS/rack work beyond the stated allowance, OEM analytics licences, face-recognition SDK licences, and government/watchlist integrations require written supplier quotes and are excluded from the fixed price.
- Continuous video remains in the customer's existing NVR. Kuzet stores event clips, thumbnails, metadata, audit records, and a short encoded ring buffer.

## Firm Day-20 Scope

1. Connect and supervise the exact 20 supplied RTSP streams with source timestamps, health state, reconnect logic, and independent per-camera state.
2. Provide a responsive web dashboard with camera status, incident list, filters/search, evidence preview, review status, and operator notes.
3. Produce 4-10 second evidence clips from an encoded pre/post-event ring buffer.
4. Provide person detection/tracking, restricted zones, loitering, and directional line crossing.
5. Provide TOTP two-factor authentication, basic role-based access, TLS, audit history, backup, and restore.
6. Provide one notification connector selected during kickoff.
7. Require operator confirmation before escalation. The system does not automatically contact police, actuate fire systems, lock doors, or punish individuals.

## Conditional Pilot Analytics

- Fire and smoke candidate alerts.
- Handgun, long-gun, and knife candidate alerts.
- Physical-fight and fall analytics in shadow/beta mode only.

A conditional analytic becomes visible to operators only if its commercial rights are documented and it passes the agreed Day-12 laboratory and site gates. Failure leaves the analytic disabled or shadow-only without blocking delivery of the firm platform scope.

## Phase 2 / Excluded From Day 20

- Face recognition, attendance, official police/watchlist matching, and liveness.
- Emotion inference.
- Native iOS and Android applications and direct APNs/FCM delivery.
- Universal ONVIF/camera certification beyond the exact supplied 20 streams.
- Production high availability, formal penetration-test certification, autonomous actions, and universal accuracy claims.

Entrance-only face recognition remains the preferred Phase-2 architecture, but it requires dedicated entrance cameras, a licensed SDK, lawful authority, a Kazakhstan-resident biometric database, an official gallery interface, and human confirmation.

## Runtime Architecture

The hot video path uses NVIDIA DeepStream/GStreamer and hardware decode. Frames remain on the GPU where practical. One shared set of TensorRT FP16 engines processes batches assembled across cameras; no camera owns a private model copy.

Each frame and inference sample carries `camera_id`, capture timestamp, monotonic sequence, unique sample ID, model version, and health context. The event engine accepts only unique timestamped observations; cached display results are never counted as fresh votes.

Continuous encoded feeds populate per-camera ring buffers. Detection creates an event record immediately and commits the configured pre/post-event evidence without writing raw decoded frames to disk.

## Analytics Architecture

- Person/zones/lines: commercially cleared person detector plus independent per-camera tracker and bottom-centre geometry. Pose is not on the critical path.
- Weapon: fine-tuned RF-DETR or D-FINE candidate detector; cropped asynchronous OWLv2/Grounding-DINO verification only after profiling; human review.
- Fire/smoke: OEM analytic for the fastest contractual path, or a rights-cleared RF-DETR/D-FINE model maintained in shadow mode until acceptance.
- Fight/fall: temporal tracked-person sequences using an OEM analytic or NVIDIA TAO/X3D-class model. Current X-CLIP and frame ViT do not generate customer alarms.
- Face: separate Phase-2 entrance service, never part of the general 20-camera detector loop.

## Infrastructure

Pilot baseline:

- NVIDIA L4 24 GB; second-GPU expansion path if the load gate fails.
- At least 16 physical CPU cores, 64 GB ECC RAM, mirrored 1 TB NVMe, 10GbE, and UPS.
- PostgreSQL for structured state and an S3-compatible Kazakhstan-resident object store or local encrypted volume for evidence.
- Existing NVR retains continuous footage.

No H100 is required.

## Acceptance Model

The contract reports event-level results on a frozen customer-site corpus, not a generic model-card percentage.

Platform gate:

- 72 uninterrupted hours with all 20 streams.
- Analytic availability at least 99.5%, excluding upstream camera outage.
- Analysis queue age p95 below 1 second and p99 below 2 seconds.
- Dropped scheduled analysis samples below 1%.
- GPU utilization at or below 75% and VRAM at or below 80% under the agreed replay.
- RTSP recovery within 30 seconds.
- No crash, OOM, unbounded queue, cross-camera state leakage, or unbounded disk growth.

Operational analytics are candidate alerts requiring human confirmation. The signed acceptance matrix defines the supported camera views, object visibility, lighting, occlusion, event duration, staged trials, and permitted false-alert rate.

## Delivery Organization

Meeting the calendar deadline requires parallel staffing: video/platform lead, two CV engineers, backend engineer, frontend/integration engineer, DevOps/security engineer, QA/site engineer, and part-time PM/legal/privacy support.

Hardware delivery is not on the critical path. Kazakhstan cloud capacity or an in-stock server must be reserved on Day 1.

## Success Definition

On Day 20 the customer can monitor the exact 20 streams, see health failures, configure zones/lines, review timestamped candidate incidents, open evidence clips, acknowledge or reject alerts, receive one configured notification, and inspect an audit trail. The handover includes an explicit pass/fail/exception report for every conditional analytic.
