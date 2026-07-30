# Controlled-pilot model register

Status: **PENDING site and target evidence**. This register records deployment
decisions; it does not convert demo behavior into accuracy or acceptance.

Every enabled artifact requires lawful commercial **rights**, provenance,
license review, immutable **artifact SHA-256**, generated **engine SHA-256**,
TensorRT/CUDA/GPU compatibility, exact preprocessing/configuration hash, signed
site quality matrix, measured capacity headroom, reviewer, and approval date.
Missing or mismatched fields fail closed.

| Analytic | Intended pilot state | Rights | Artifact SHA-256 | Engine SHA-256 | Site quality/capacity | Notes |
|---|---|---|---|---|---|---|
| Core detector/tracker used for zones/lines | PENDING | PENDING | PENDING | PENDING | PENDING | May become operator-visible only after the frozen target workload passes. |
| Fire/smoke | shadow | PENDING | PENDING | PENDING | PENDING | Independent signed event-level positive/hard-negative matrix required. |
| Weapon candidate detector | shadow | PENDING | PENDING | PENDING | PENDING | Independent signed event-level matrix; no demo-clip accuracy claims. |
| OWLv2 verifier | shadow | PENDING | PENDING | PENDING | PENDING | Heavy asynchronous path only; current whole-frame path is not a production alarm. |
| X-CLIP violence | shadow | PENDING | PENDING | PENDING | PENDING | Demo heuristic; not an operator alarm. |
| ViT violence | shadow | PENDING | PENDING | PENDING | PENDING | Demo heuristic; not an operator alarm. |
| Face matching | disabled | PENDING | PENDING | PENDING | PENDING | Future feature gate only; entrance-only and lawful customer gallery only. |

## Change control

Changing weights, engine, precision, preprocessing, thresholds, image, driver,
CUDA/TensorRT version, source workload, or GPU invalidates the bound evidence.
Create a new register revision and repeat affected quality and capacity gates.
Never scrape police/watchlists or ship a criminal database.
