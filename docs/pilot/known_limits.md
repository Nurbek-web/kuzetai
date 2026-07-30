# Controlled-pilot known limits

This repository is an investor MVP plus an unvalidated controlled-pilot
implementation. It is **not production-ready** and has not demonstrated a
20-camera workload on NVIDIA hardware.

- Apple M2 verification covers contracts, fake/replay runtime, APIs,
  persistence, orchestration, security checks, packaging, and non-NVIDIA graph
  validation. It does not prove DeepStream/TensorRT capacity.
- No RTX 4090, RTX 5090, L4, or other GPU is claimed to support 20 streams
  until the exact frozen workload measures effective throughput with at least
  25% headroom and passes the 8-hour and 72-hour gates.
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
