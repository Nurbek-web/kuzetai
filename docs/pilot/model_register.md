# Controlled-pilot model register

Status: **PENDING implementation review, site evidence, and target evidence**.
This register records deployment decisions; it does not convert demo behavior
into accuracy or acceptance.

Every enabled artifact requires lawful commercial **rights**, provenance,
license review, immutable **artifact SHA-256**, generated **engine SHA-256**,
TensorRT/CUDA/GPU compatibility, exact preprocessing/configuration hash, signed
site quality matrix, measured capacity headroom, reviewer, and approval date.
Missing or mismatched fields fail closed.

Model engine generation is currently **BLOCKED at implementation review**.
This revision has no digest-pinned builder image with an exact non-root
entrypoint, read-only input mounts, new bounded output paths, TensorRT and
calibration identity, timeout/byte limits, and atomically published signed
audit/build receipts. Do not substitute a host-side `uv` invocation or an
imagined runtime-container command. Every engine/build field below remains
`PENDING` until that contract is implemented and reviewed.

| Analytic | Intended pilot state | Rights/source record | Artifact and preprocessing SHA-256 | Engine/build/runtime identity | Signed site quality and measured capacity | Notes |
|---|---|---|---|---|---|---|
| Core detector/tracker used for zones/lines | PENDING | PENDING | PENDING | PENDING | PENDING | May become operator-visible only after the frozen target workload passes. |
| Fire/smoke | shadow | PENDING | PENDING | PENDING | PENDING | Independent signed event-level positive/hard-negative matrix required. |
| Weapon candidate detector | shadow | PENDING | PENDING | PENDING | PENDING | Independent signed event-level matrix; no demo-clip accuracy claims. |
| OWLv2 verifier | shadow | PENDING | PENDING | PENDING | PENDING | Bounded asynchronous ROI path only; whole-frame use is not a production alarm. |
| X-CLIP violence | shadow | PENDING | PENDING | PENDING | PENDING | Heavy asynchronous demo heuristic; cannot become operator mode in this pilot. |
| ViT violence | shadow | PENDING | PENDING | PENDING | PENDING | Heavy asynchronous demo heuristic; cannot become operator mode in this pilot. |
| Face matching | disabled | PENDING | PENDING | PENDING | PENDING | Not implemented in the pilot. Any future system is separate, entrance-only, and lawful-customer-gallery only. |

For each non-disabled artifact attach the exact source URI without credentials,
license/commercial-rights evidence hash, model-card hash, class list,
preprocessing and threshold hash, artifact byte size/SHA-256, export precision,
TensorRT/CUDA/driver/GPU compute identity, engine and build-receipt SHA-256,
calibration corpus hash when applicable, signed site matrix, signed frozen
workload/capacity report, promotion decision hash, named reviewers, and UTC
approval/expiry. Record both the configured mode and the runtime-observed
artifact identity.

## Change control

Changing weights, engine, precision, preprocessing, thresholds, image, driver,
CUDA/TensorRT version, source workload, or GPU invalidates the bound evidence.
Create a new register revision and repeat affected quality and capacity gates.
Never scrape police/watchlists or ship a criminal database.

A missing value is not a temporary operator override: the analytic remains
`shadow` or `disabled`. There is no universal cameras-per-GPU coefficient.
Capacity requires completed unique work under the exact frozen 20-source
schedule with at least 25% measured effective-throughput headroom.
