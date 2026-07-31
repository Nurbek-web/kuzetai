# Controlled-pilot known limits

This repository is an investor MVP plus an unvalidated controlled-pilot
implementation. It is **not production-ready** and has not demonstrated a
20-camera workload on NVIDIA hardware.

- No full-suite pass is claimed for this revision. The current cloud handover
  environment has no Docker daemon, CUDA, DeepStream, TensorRT, or NVIDIA GPU;
  completed checks must be listed exactly in the SDD ledger and must not be
  inferred from a development-host label.
- No RTX 4090, RTX 5090, L4, or other GPU is claimed to support 20 streams
  until the exact frozen workload measures effective throughput with at least
  25% headroom and passes the 8-hour and 72-hour gates.
- The retained-runtime continuation contract is implemented and independently
  reviewed in code. Production target mode requires three ordered signed
  source-profile attestations, three matching signatures, three unique launch
  nonces, a fresh third runtime epoch/channel, fresh prewarm and work
  authority, and a private append-only transition journal distinct from the
  collector state and the packaged controller's existing V3 authority journal.
  The exact 8-hour and 72-hour host commands in `ready_to_start.md` remain
  **PENDING external NVIDIA/site execution — NOT RUN**; their presence is not
  an acceptance result.
- Compose runtime activation remains **BLOCKED** separately. The runtime
  overlay is render-only until a reviewed host wrapper attests the rendered
  image/config, mounts, networks, identity, tmpfs, resource limits, and log
  limits before start. The raw target runner is the pending acceptance path.
- The model engine build path is an implementation blocker. This revision does
  not package a digest-pinned builder image with an exact entrypoint,
  least-privilege mount contract, bounded outputs, or atomic signed receipts.
  Host-side `uv` commands are not a substitute for an in-container
  DeepStream/TensorRT build contract.
- Live PostgreSQL role membership/ownership/`SET ROLE` probes, migration
  `0008_runtime_persistence`, and real concurrent role/function behavior
  remain PENDING on PostgreSQL 16+.
- Kazakhstan S3-compatible storage is not accepted until a reviewed
  bucket/resource policy enforces conditional create for every evidence,
  preview, and audit-archive write, versioning/lifecycle drift is monitored,
  and both positive conditional-PUT and negative unconditional-overwrite
  probes pass. Provider-side “best effort” is insufficient.
- Retention is finite and fail-closed, but target arrival-versus-drain,
  backlog-depth, and oldest-eligible-age evidence has not been measured. A
  running retention process is not a bounded-growth result. The packaged
  database snapshot cannot measure unregistered orphan object versions, and
  aggregate retention steady state remains unproven. Immutable audit/cycle
  receipt roots also require a signed per-cycle size/file bound, quota,
  campaign forecast, lifecycle, and alert threshold; they are not expected to
  drain to zero.
- A general evidence-export workflow is not packaged. Operators must use the
  customer NVR/customer-controlled process unless a separately reviewed,
  audited bounded export is installed.
- The optional notification worker remains disabled: its dedicated
  least-privilege PostgreSQL role and live ACL receipt are not yet packaged.
- Continuous raw video stays in the **customer NVR** or customer-controlled
  local path. Kuzet retains bounded event evidence and metadata only.
- All alerts are candidates until human confirmation. There are no automatic
  police, fire-system, or door actions.
- Current X-CLIP and ViT violence logic is a demo/shadow heuristic, not a
  production alarm.
- Current whole-frame OWLv2 processing is slow and unvalidated. It stays an
  asynchronous shadow verifier until rights, target-site quality, and capacity
  gates pass.
- Fire and weapon behavior on curated investor clips is not precision/recall
  evidence. Each needs a lawful site dataset and signed event-level matrix.
- Face matching is disabled. A future approved phase is **entrance-only** and
  may compare only against a **lawful gallery** supplied by the customer. There
  is no built-in criminal database or watchlist scraping.
- The pilot is scoped to one site and exactly 20 named sources. Camera
  replacement, material view changes, new analytics, new models, or new
  hardware require change control and repeated gates.
- This is not production HA/SLA, certification, independent penetration
  testing, indefinite archive storage, a native mobile app, or an autonomous
  emergency-response system.

See [deployment_runbook.md](deployment_runbook.md) and
[model_register.md](model_register.md) for the evidence still PENDING.
