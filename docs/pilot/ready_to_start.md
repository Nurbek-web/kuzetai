# Kuzet AI controlled-pilot Ready-to-Start gate

Status: **PENDING — NOT READY**. Missing any mandatory checkbox keeps the pilot
fail-closed. This record does not claim that an L4 or any 20-camera workload has
passed.

## Mandatory signed inputs

- [ ] One authoritative site ID and exactly 20 named, lawful customer feeds or
  captured replay fixtures; unique camera/source indices; codec, resolution,
  FPS, bitrate, schedules, provenance, and exact file SHA-256 values frozen in
  the acceptance manifest.
- [ ] Customer source-field matrix covers every view, visibility level,
  lighting condition, occlusion, duration, positive, and hard-negative case.
- [ ] Linux NVIDIA L4 node is installed; a documented second-GPU path exists if
  the frozen workload cannot keep at least 25% measured throughput headroom.
- [ ] Kazakhstan-resident evidence/object storage and encrypted local spool are
  provisioned. Continuous video remains in the customer NVR.
- [ ] PostgreSQL, TLS certificates, NTP, DNS, ingress, and explicit storage and
  notification egress allowlists are verified.
- [ ] Commercial rights, source provenance, model/config/engine/container
  digests, TensorRT/GPU compatibility, and signed site gates are complete.
- [ ] Named operators, roles, TOTP enrolment, human-confirmation workflow, and
  written notification-channel approval are complete.
- [ ] External OpenSSL report/audit public and private keys and age backup keys
  are mounted from approved secret paths. No key is stored in this repository.
- [ ] Provisioning manifest, replay manifest, capacity evidence, exception list,
  and event-level fire/weapon matrix have named reviewers and detached
  signatures.
- [ ] Every open exception has an owner, expiry, compensating control, and
  customer sign-off.

Fight/fall/X-CLIP/ViT remain shadow-only. Fire and weapon remain shadow or
disabled until their separate signed event-level matrices, model rights, hashes,
quality gates, and measured capacity gates pass. Every alert remains a candidate
until a human confirms it; no police, fire-system, or door action is automatic.

The standalone `acceptance_report.py` CLI never accepts a raw
`signature_verified` flag. By default it demotes fire/weapon `pass/operator`
dispositions to `shadow`. After the existing audited
`ModelGate.evaluate_conditional` workflow produces a
`ConditionalModelGateResultV1`, an operator may supply its bounded,
non-symlink JSON file with one repeatable
`--conditional-gate-decision /run/config/weapon-gate-decision.json` flag. The
decision must be unique per module, operator-approved for the exact site, and
its `decision_sha256` must equal the hash frozen in the acceptance manifest.
Missing, duplicated, or unbound decisions remain shadow; no gate result is
claimed by this template.

## Target-only 8-hour integration replay

Required fixtures: the signed 20-source manifest, lawful captured corpus or
direct `/run/secrets/...` source references, reviewed runtime/site manifests,
model/engine/container digests, mounted report signing keys, and a fresh bounded
artifact directory. Report generation refuses to replace any existing JSON,
HTML, detached-signature, or verification-metadata target, including symlinks;
use a new directory or an already-created empty directory for every run.

```bash
export PYTORCH_ENABLE_MPS_FALLBACK=1
uv run python scripts/pilot/replay_20.py \
  --mode target \
  --manifest /run/config/acceptance-manifest.yaml \
  --site-config /run/config/site.yaml \
  --site-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-manifest /run/config/runtime-manifest.yaml \
  --runtime-manifest-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-report /run/config/measured-capacity.yaml \
  --measured-capacity-sha256 REPLACE_WITH_64_HEX \
  --control-plane-url http://api:8000 \
  --machine-token-file /run/secrets/machine_token \
  --collector-interval-seconds 30 \
  --duration-seconds 28800 \
  --out /srv/kuzet/acceptance/8h/run-record.json
uv run python scripts/pilot/acceptance_report.py generate \
  --manifest /run/config/acceptance-manifest.yaml \
  --run-record /srv/kuzet/acceptance/8h/run-record.json \
  --out-dir /srv/kuzet/acceptance/8h/report \
  --private-key /run/secrets/acceptance_signing_private_key \
  --public-key /run/config/acceptance_signing_public_key.pem
uv run python scripts/pilot/acceptance_report.py verify \
  --metadata /srv/kuzet/acceptance/8h/report/acceptance-verification.json \
  --public-key /run/config/acceptance_signing_public_key.pem
```

The target adapter invokes exactly one existing shared DeepStream entrypoint,
with no shell interpolation and bounded output/time. The CLI-owned collector
authenticates with the machine token, binds its `start`, periodic `sample`, and
`finalize` requests to the exact site, manifest hash, gate, and random collector
ID. The final record's `run_id` must equal that nonce, so a stale record with
the same site/manifest/gate is rejected. The CLI refuses an early process exit,
missing observations, response mismatch, unbounded response, forced kill, or
non-target final record. Child stdout/stderr are discarded; deployment-owned
logs remain separately rotated, and no process-wide file-size limit can truncate
the bounded evidence spool. The CLI never accepts a pre-existing run-record
file. The target control plane must expose the reviewed
machine-only `/api/internal/acceptance/start`, `/sample`, and `/finalize`
collector contract on its isolated network. A portable Apple run uses
`--mode portable`, is marked `test_only`, and cannot satisfy this gate.

Expected artifacts: canonical run record, canonical signed JSON envelope,
self-contained escaped HTML, detached signature, verification metadata, runtime
and API logs, graph/config/model/engine/container hashes, resource samples,
fault/recovery traces, and separate signed fire/weapon matrix.

8-hour verdict: **PENDING external NVIDIA/20-source execution**.

## Target-only 72-hour final soak

Use the same frozen inputs and a new CLI-owned output path:

```bash
export PYTORCH_ENABLE_MPS_FALLBACK=1
uv run python scripts/pilot/replay_20.py \
  --mode target \
  --manifest /run/config/acceptance-manifest.yaml \
  --site-config /run/config/site.yaml \
  --site-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-manifest /run/config/runtime-manifest.yaml \
  --runtime-manifest-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-report /run/config/measured-capacity.yaml \
  --measured-capacity-sha256 REPLACE_WITH_64_HEX \
  --control-plane-url http://api:8000 \
  --machine-token-file /run/secrets/machine_token \
  --collector-interval-seconds 30 \
  --duration-seconds 259200 \
  --out /srv/kuzet/acceptance/72h/run-record.json
uv run python scripts/pilot/acceptance_report.py generate \
  --manifest /run/config/acceptance-manifest.yaml \
  --run-record /srv/kuzet/acceptance/72h/run-record.json \
  --out-dir /srv/kuzet/acceptance/72h/report \
  --private-key /run/secrets/acceptance_signing_private_key \
  --public-key /run/config/acceptance_signing_public_key.pem
uv run python scripts/pilot/acceptance_report.py verify \
  --metadata /srv/kuzet/acceptance/72h/report/acceptance-verification.json \
  --public-key /run/config/acceptance_signing_public_key.pem
```

Do not tune configuration, workload, or models between measurement and report
generation. Preserve all exceptions and every fault observation.

The final report must show exact 20-stream concurrency for 72 hours,
availability at least 99.5% excluding only evidenced source outage, drops below
1%, queue p95 below 1 s and p99 below 2 s, reconnect at most 30 s after source
return, GPU at most 75%, VRAM at most 80%, candidate-to-event p95 at most 1 s,
first preview p95 at most 2 s, measured effective throughput with at least 25%
headroom, and no crash/OOM/unbounded growth/leakage/unaudited review or
pre-confirmation notification.

72-hour verdict: **PENDING external NVIDIA/20-source execution**. No RTX 4090,
5090, L4, or other GPU is accepted for 20 streams until this frozen workload is
measured.
