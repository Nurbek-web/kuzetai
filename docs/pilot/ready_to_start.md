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
dispositions to `shadow`. A repeatable `--conditional-gate-decision` input must
be an absolute, canonical `conditional-gate-attestation.v1` JSON file. It binds
the exact decision plus rights, artifact, engine, site-matrix, shadow-stage,
capacity, workload, and trusted-public-key hashes. Its sibling detached
Ed25519 signature is verified only with the conditional-role key pinned by the
offline-root-signed campaign policy. The report CLI independently replays that
same root chain, the target-run V2 attestation, and the complete bounded
journal proof before evaluation. Missing, unsigned, duplicated, hash-mismatched,
or unbound decisions remain shadow; no gate result is claimed by this template.

## Target acceptance authority provisioning

The dedicated loopback-only `acceptance-controller` owns the journal and
acceptance routes. The restartable pilot API has no acceptance routes and
rejects acceptance environment configuration. Partial controller configuration
fails closed.

```bash
export PILOT_ACCEPTANCE_ADAPTER_PATH=/opt/kuzet/bin/acceptance-adapter
export PILOT_ACCEPTANCE_ADAPTER_SHA256=REPLACE_WITH_REVIEWED_64_HEX
export PILOT_ACCEPTANCE_ADAPTER_POLICY_PATH=/opt/kuzet/reviewed/acceptance-adapter-policy.json
export PILOT_ACCEPTANCE_ADAPTER_POLICY_SHA256=REPLACE_WITH_REVIEWED_64_HEX
export PILOT_ACCEPTANCE_STATE_PATH=/srv/kuzet/acceptance-authority
export PILOT_ACCEPTANCE_PROOF_PATH=/srv/kuzet/acceptance-proofs/8h
export PILOT_ACCEPTANCE_PORT=8765
```

Compose sets
`PILOT_ACCEPTANCE_JOURNAL_PATH=/var/lib/kuzet/acceptance/authority.sqlite3`
and mounts the SQLite main, WAL, and SHM files individually. The image supplies
the root-owned, non-writable namespace around those three writable file
mounts. It separately sets
`PILOT_ACCEPTANCE_PROOF_DIR=/var/lib/kuzet/acceptance-proofs` and binds the
gate-specific host proof directory named by `PILOT_ACCEPTANCE_PROOF_PATH`.
Before startup, provision the exact triplet and private proof directory on
backed-up local storage:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  "${PILOT_ACCEPTANCE_STATE_PATH}"
sudo -u '#10001' env JOURNAL_PATH="${PILOT_ACCEPTANCE_STATE_PATH}/authority.sqlite3" \
  python3 - <<'PY'
import os
import sqlite3

path = os.environ["JOURNAL_PATH"]
with sqlite3.connect(path) as connection:
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    connection.execute("PRAGMA user_version=1")
PY
sudo install -o 10001 -g 10001 -m 0600 /dev/null \
  "${PILOT_ACCEPTANCE_STATE_PATH}/authority.sqlite3-wal"
sudo install -o 10001 -g 10001 -m 0600 /dev/null \
  "${PILOT_ACCEPTANCE_STATE_PATH}/authority.sqlite3-shm"
sudo chmod 0600 "${PILOT_ACCEPTANCE_STATE_PATH}/authority.sqlite3"
sudo chown root:root "${PILOT_ACCEPTANCE_STATE_PATH}"
sudo chmod 0755 "${PILOT_ACCEPTANCE_STATE_PATH}"
sudo install -d -o root -g root -m 0755 /srv/kuzet/acceptance-proofs
sudo install -d -o 10001 -g 10001 -m 0700 \
  "${PILOT_ACCEPTANCE_PROOF_PATH}"
```

All three files must be regular, have one hard link, and remain owned by
controller UID/GID `10001:10001` with mode `0600`. Never place them on `tmpfs`:
the append-only SQLite WAL journal must survive the commanded API restart.
They must share one `st_dev` on a local POSIX filesystem; network and FUSE
filesystems are outside the acceptance boundary.
The proof directory must be an absolute local-POSIX path owned by controller
UID `10001` with mode `0700`; every sealed proof is a single-link `0600`
regular file. Use `/srv/kuzet/acceptance-proofs/8h` and
`/srv/kuzet/acceptance-proofs/72h` as distinct fresh roots. Never point the
controller proof store at the host report-output directory: the controller
publishes sealed journal artifacts inside the container path, while the host
runner downloads one exact digest-bound copy to its gate output path.
Startup fails closed if the runtime UID can rename entries in the container
namespace, if any triplet member is missing or replaced, or if the persisted
journal was created in portable mode. This boundary trusts the host/root
provisioner and container runtime; root, same-UID host code, and injected native
code are outside its claim.

### Linux/Docker journal-bind smoke — PENDING external execution

This smoke cannot run on the Apple M2 development host because no Docker CLI or
daemon is available. Run it on the target Linux host after building/pulling the
reviewed API image. A pass is required before either endurance gate; do not
substitute these expected results for measured output.

```bash
set -euo pipefail
: "${PILOT_API_IMAGE:?set digest-pinned API image reference}"
: "${PILOT_ACCEPTANCE_STATE_PATH:?set provisioned state directory}"
state="${PILOT_ACCEPTANCE_STATE_PATH}"
main="${state}/authority.sqlite3"
wal="${main}-wal"
shm="${main}-shm"
image="${PILOT_API_IMAGE}"
cap=1073741824

fs_type="$(findmnt -T "${main}" -n -o FSTYPE)"
case "${fs_type}" in
  nfs*|cifs|smb*|fuse*|9p|ceph|glusterfs)
    echo "UNSUPPORTED_FILESYSTEM ${fs_type}" >&2
    exit 1
    ;;
esac
test "$(stat -c %d "${main}")" = "$(stat -c %d "${wal}")"
test "$(stat -c %d "${main}")" = "$(stat -c %d "${shm}")"
for file in "${main}" "${wal}" "${shm}"; do
  test -f "${file}"
  test "$(stat -c %u:%g:%a:%h "${file}")" = "10001:10001:600:1"
done

smoke_dir="$(mktemp -d)"
before="${smoke_dir}/before.stat"
after="${smoke_dir}/after.stat"
hold_script="${smoke_dir}/hold.py"
verify_script="${smoke_dir}/verify.py"
trap 'docker rm -f kuzet-journal-bind-smoke >/dev/null 2>&1 || true; rm -rf -- "${smoke_dir}"' EXIT
stat -c '%d:%i:%u:%g:%a:%h:%n' "${main}" "${wal}" "${shm}" >"${before}"

cat >"${hold_script}" <<'PY'
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from protector.pilot.acceptance_authority import SQLiteAcceptanceAuthorityJournal

path = Path("/var/lib/kuzet/acceptance/authority.sqlite3")
journal = SQLiteAcceptanceAuthorityJournal(
    path,
    max_database_bytes=1024 * 1024 * 1024,
    protected_namespace_owner_uid=0,
)
if journal.entry_count("linux-bind-smoke") == 0:
    journal.append(
        collector_id="linux-bind-smoke",
        kind="start",
        identity="start",
        payload={"smoke": "retained-wal-crash-recovery"},
        created_at=datetime.now(timezone.utc),
    )
reader = sqlite3.connect(path)
reader.execute("BEGIN")
reader.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()
writer = sqlite3.connect(path)
writer.execute(
    "INSERT INTO acceptance_session_usage "
    "(collector_id, sample_bytes) VALUES (?, 0)",
    (f"linux-bind-probe-{time.time_ns()}",),
)
writer.commit()
writer.close()
wal_bytes = Path(f"{path}-wal").stat().st_size
assert wal_bytes > 0
print(f"READY retained_wal_bytes={wal_bytes}", flush=True)
while True:
    time.sleep(30)
PY

cat >"${verify_script}" <<'PY'
import os
import sqlite3
from pathlib import Path

from protector.pilot.acceptance_authority import SQLiteAcceptanceAuthorityJournal

path = Path("/var/lib/kuzet/acceptance/authority.sqlite3")
triplet = (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
journal = SQLiteAcceptanceAuthorityJournal(
    path,
    max_database_bytes=1024 * 1024 * 1024,
    protected_namespace_owner_uid=0,
)
connection = sqlite3.connect(path)
try:
    assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
finally:
    connection.close()
assert journal.entry_count("linux-bind-smoke") == 1
assert len({candidate.stat().st_dev for candidate in triplet}) == 1
for candidate in triplet:
    metadata = candidate.stat()
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_mode & 0o777 == 0o600
    assert metadata.st_nlink == 1
assert journal.database_bytes <= 1024 * 1024 * 1024
journal.chain_head("linux-bind-smoke")
print(
    f"RECOVERED integrity=ok entry_count=1 bytes={journal.database_bytes} "
    "cap=1073741824"
)
PY
chmod 0444 "${hold_script}" "${verify_script}"

docker run --name kuzet-journal-bind-smoke --detach \
  --read-only --user 10001:10001 --entrypoint python \
  --mount "type=bind,src=${main},dst=/var/lib/kuzet/acceptance/authority.sqlite3" \
  --mount "type=bind,src=${wal},dst=/var/lib/kuzet/acceptance/authority.sqlite3-wal" \
  --mount "type=bind,src=${shm},dst=/var/lib/kuzet/acceptance/authority.sqlite3-shm" \
  --mount "type=bind,src=${hold_script},dst=/run/smoke.py,readonly" \
  "${image}" /run/smoke.py

timeout 60 sh -c \
  'until docker logs kuzet-journal-bind-smoke 2>&1 | grep -q "^READY retained_wal_bytes="; do sleep 1; done'
docker logs kuzet-journal-bind-smoke
docker kill --signal KILL kuzet-journal-bind-smoke >/dev/null
docker rm kuzet-journal-bind-smoke >/dev/null

docker run --rm --read-only --user 10001:10001 \
  --entrypoint python \
  --mount "type=bind,src=${main},dst=/var/lib/kuzet/acceptance/authority.sqlite3" \
  --mount "type=bind,src=${wal},dst=/var/lib/kuzet/acceptance/authority.sqlite3-wal" \
  --mount "type=bind,src=${shm},dst=/var/lib/kuzet/acceptance/authority.sqlite3-shm" \
  --mount "type=bind,src=${verify_script},dst=/run/smoke.py,readonly" \
  "${image}" /run/smoke.py

stat -c '%d:%i:%u:%g:%a:%h:%n' "${main}" "${wal}" "${shm}" >"${after}"
diff -u "${before}" "${after}"
missing="${state}/must-not-be-created.sqlite3"
test ! -e "${missing}"
if docker run --rm --entrypoint /bin/true \
  --mount "type=bind,src=${missing},dst=/var/lib/kuzet/acceptance/authority.sqlite3" \
  "${image}" 2>/dev/null; then
  echo "missing bind source was accepted" >&2
  exit 1
fi
test ! -e "${missing}"
echo "UNCHANGED_TRIPLET"
echo "MISSING_SOURCE_REJECTED"
```

Expected terminal evidence is one positive retained-WAL byte count followed by
`RECOVERED integrity=ok entry_count=1`, `UNCHANGED_TRIPLET`, and
`MISSING_SOURCE_REJECTED`. Preserve that output with the target acceptance
artifacts.

The executable must be an absolute, regular, executable file owned by root or
the runner UID, with no group/world write bit, and its bytes must match
`PILOT_ACCEPTANCE_ADAPTER_SHA256`. The runner snapshots and rechecks the exact
bytes. Operations run without a shell as:

```text
/run/config/acceptance-adapter sample   REQUEST_JSON RESPONSE_JSON
/run/config/acceptance-adapter ensure   REQUEST_JSON RESPONSE_JSON
/run/config/acceptance-adapter observe  REQUEST_JSON RESPONSE_JSON
/run/config/acceptance-adapter finalize REQUEST_JSON RESPONSE_JSON
```

The adapter receives a minimal environment, discarded stdout/stderr, a
60-second maximum, and new private request/response files. `sample` must return
the exact 20-camera delta counters, health states, queue ages, shared runtime
and API boot IDs, and resource snapshot. Runner-only `ensure` must idempotently
perform the requested site-reviewed effect by command ID; `observe` must report
the resulting state without causing an effect.
`finalize` may return lifecycle, boundary, queue, capacity, and exception
evidence, but cannot override camera/work/health/queue/resource/fault evidence:
the authority derives those fields from its journal. The site-owned adapter
must implement only the eight frozen test effects; it must not expose a general
shell, arbitrary target, or any police/fire/door action.

The authority records the host boot identity with the monotonic start time.
API-process restart is supported on the same boot. A host reboot invalidates
the active collector session; discard the incomplete output and begin a fresh
gate rather than joining incomparable monotonic clocks.

Target collection cadence is exactly 60 seconds. The authority checks both arrival and adapter completion
within five seconds of every scheduled sample, then assigns the canonical
scheduled timestamp. Fault commands use the frozen command offset, while their
degraded/recovered timestamp is the authority's post-adapter acknowledgement
time so recovery latency cannot be reported as zero.

The journal is finite: at most 10,000 entries per session, 40,000 entries
globally, four sessions, 2 MiB per ordinary entry, 32 MiB for the bounded final
record, and 1 GiB for the SQLite database. A 72-hour gate at the documented
60-second cadence requires 4,371 reserved
entries and is rejected before start if the complete gate cannot fit. After a
final record and signed report have both been independently verified, stop the
controller, checkpoint and archive the database together with any `-wal` and `-shm`
files on approved Kazakhstan-resident storage, then provision a new empty
private journal before the next acceptance campaign. Never rotate, truncate,
or copy only the main database during an active or unfinalized gate.

## Target-only 8-hour integration replay

Required host fixtures: the signed 20-source manifest; the pinned offline-root
fingerprint and public key; the signed trust policy; all five role public keys;
lawful captured corpus or host-readable direct-source secret references; the
reviewed runtime, site, capacity, and mount-contract artifacts; every frozen
model, engine, image, code, network, adapter, and observer digest; the reviewed
adapter and independent-observer executables, policies, and separate empty work
roots; host-readable machine and controller tokens; the report-role private
key; and fresh absolute collector-state and output paths. The commands below
run on the Linux host, so their input paths are host paths, not container-only
`/run/...` or `/opt/kuzet/...` paths. Report generation refuses to replace any
existing JSON, HTML, detached-signature, or verification-metadata target,
including symlinks; use a new directory or an already-created empty directory
for every run.

```bash
export PYTORCH_ENABLE_MPS_FALLBACK=1
uv run python scripts/pilot/replay_20.py \
  --mode target \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 8h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --site-config /srv/kuzet/reviewed/site.yaml \
  --site-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-manifest /srv/kuzet/reviewed/runtime-manifest.yaml \
  --runtime-manifest-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --runtime-image-id-sha256 REPLACE_WITH_64_HEX \
  --runtime-image-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-code-sha256 REPLACE_WITH_64_HEX \
  --mount-contract /srv/kuzet/reviewed/runtime-mount-contract.yaml \
  --mount-contract-sha256 REPLACE_WITH_64_HEX \
  --container-engine /usr/bin/docker \
  --nvidia-ctk /usr/bin/nvidia-ctk \
  --control-network kuzet-controlled-pilot_control \
  --camera-network kuzet-camera-lan \
  --control-network-id REPLACE_WITH_64_HEX \
  --control-network-config-sha256 REPLACE_WITH_64_HEX \
  --camera-network-id REPLACE_WITH_64_HEX \
  --camera-network-config-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-executable /srv/kuzet/bin/acceptance-adapter \
  --acceptance-adapter-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-policy /srv/kuzet/reviewed/acceptance-adapter-policy.json \
  --acceptance-adapter-policy-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-work-root /srv/kuzet/acceptance/8h/adapter-work \
  --acceptance-observer-executable /srv/kuzet/bin/acceptance-observer \
  --acceptance-observer-sha256 REPLACE_WITH_64_HEX \
  --acceptance-observer-policy /srv/kuzet/reviewed/acceptance-observer-policy.json \
  --acceptance-observer-policy-sha256 REPLACE_WITH_64_HEX \
  --acceptance-observer-work-root /srv/kuzet/acceptance/8h/observer-work \
  --collector-state /srv/kuzet/acceptance/8h/state/collector.sqlite3 \
  --control-plane-url http://127.0.0.1:8765 \
  --machine-token-file /srv/kuzet/secrets/machine_token \
  --acceptance-controller-token-file /srv/kuzet/secrets/acceptance_controller_token \
  --collector-interval-seconds 60 \
  --duration-seconds 28800 \
  --out /srv/kuzet/acceptance/8h/run-record.json \
  --out-attestation /srv/kuzet/acceptance/8h/target-run-attestation.json \
  --out-signature /srv/kuzet/acceptance/8h/target-run-attestation.sig \
  --out-journal-proof /srv/kuzet/acceptance/8h/target-journal-proof.jsonl
uv run python scripts/pilot/acceptance_report.py generate \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 8h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --run-record /srv/kuzet/acceptance/8h/run-record.json \
  --run-attestation /srv/kuzet/acceptance/8h/target-run-attestation.json \
  --run-signature /srv/kuzet/acceptance/8h/target-run-attestation.sig \
  --journal-proof /srv/kuzet/acceptance/8h/target-journal-proof.jsonl \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --out-dir /srv/kuzet/acceptance/8h/report \
  --private-key /srv/kuzet/secrets/report-role-private.pem \
  --public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem
uv run python scripts/pilot/acceptance_report.py verify \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 8h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --run-record /srv/kuzet/acceptance/8h/run-record.json \
  --run-attestation /srv/kuzet/acceptance/8h/target-run-attestation.json \
  --run-signature /srv/kuzet/acceptance/8h/target-run-attestation.sig \
  --journal-proof /srv/kuzet/acceptance/8h/target-journal-proof.jsonl \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --metadata /srv/kuzet/acceptance/8h/report/acceptance-verification.json \
  --public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem
```

The replay CLI invokes exactly one existing shared DeepStream entrypoint, with
no shell interpolation and bounded output/time. Its machine-token collector
binds `start`, periodic `sample`, all 16 `fault` phase commands, and `finalize`
to the exact site, manifest, launch attestation, 20 camera IDs, per-camera
analytic schedule, gate, canonical fault-schedule hash, and random collector
ID. The final record's `run_id` must equal that nonce, so stale evidence is
rejected. The authority persists every accepted request before finalization and
derives final sample and fault evidence from that journal. The CLI refuses an
early process exit, missing observations or fault acknowledgements, response
mismatch, unbounded response, forced kill, or non-target final record. Child
stdout/stderr are discarded; deployment-owned logs remain separately rotated.
At gate completion the CLI sends `SIGTERM`; the DeepStream entrypoint translates
it into a main-loop quit, drains/stops the runtime, and must exit with status
zero before the authority can finalize the record.
Fresh campaigns require four absent, distinct output paths: run record, V2
attestation, detached signature, and journal proof. If the runner crashes after
the controller durably commits a final V2 envelope, restart with the exact same
collector state and output arguments. The runner authenticates the stored
offline-root/policy binding, downloads the sealed proof, exact-compares any
already-published output, and completes publication without relaunching the
runtime. A partial campaign without a committed final remains fail-closed and
requires explicit operator invalidation; never edit the SQLite journal to force
a retry. The dedicated controller exposes `/api/internal/acceptance/start`,
`/sample`, `/fault/prepare`, `/fault/ack`, `/finalize`, and the sealed `/proof`
stream only at the canonical host-loopback origin. A portable Apple run uses
`--mode portable`, is marked `test_only`, and cannot satisfy this gate.

Expected artifacts: the canonical run record; the independently signed
target-run V2 attestation and its detached run signature; the bounded canonical
JSONL journal proof and collector journal with their start-time trust binding;
the report JSON, self-contained
escaped HTML, detached report signature, and verification metadata; runtime and
API logs; graph/config/model/engine/container hashes; resource samples;
fault/recovery traces; and the separate signed fire/weapon matrix.

8-hour verdict: **PENDING external NVIDIA/20-source execution**.

## Target-only 72-hour final soak

Use the same frozen inputs, a newly provisioned private controller proof root,
and new CLI-owned output paths:

```bash
export PILOT_ACCEPTANCE_PROOF_PATH=/srv/kuzet/acceptance-proofs/72h
test "$(stat -c %u:%g:%a "${PILOT_ACCEPTANCE_PROOF_PATH}")" = "10001:10001:700"
export PYTORCH_ENABLE_MPS_FALLBACK=1
uv run python scripts/pilot/replay_20.py \
  --mode target \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 72h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --site-config /srv/kuzet/reviewed/site.yaml \
  --site-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-manifest /srv/kuzet/reviewed/runtime-manifest.yaml \
  --runtime-manifest-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-sha256 REPLACE_WITH_64_HEX \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --runtime-image-id-sha256 REPLACE_WITH_64_HEX \
  --runtime-image-config-sha256 REPLACE_WITH_64_HEX \
  --runtime-code-sha256 REPLACE_WITH_64_HEX \
  --mount-contract /srv/kuzet/reviewed/runtime-mount-contract.yaml \
  --mount-contract-sha256 REPLACE_WITH_64_HEX \
  --container-engine /usr/bin/docker \
  --nvidia-ctk /usr/bin/nvidia-ctk \
  --control-network kuzet-controlled-pilot_control \
  --camera-network kuzet-camera-lan \
  --control-network-id REPLACE_WITH_64_HEX \
  --control-network-config-sha256 REPLACE_WITH_64_HEX \
  --camera-network-id REPLACE_WITH_64_HEX \
  --camera-network-config-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-executable /srv/kuzet/bin/acceptance-adapter \
  --acceptance-adapter-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-policy /srv/kuzet/reviewed/acceptance-adapter-policy.json \
  --acceptance-adapter-policy-sha256 REPLACE_WITH_64_HEX \
  --acceptance-adapter-work-root /srv/kuzet/acceptance/72h/adapter-work \
  --acceptance-observer-executable /srv/kuzet/bin/acceptance-observer \
  --acceptance-observer-sha256 REPLACE_WITH_64_HEX \
  --acceptance-observer-policy /srv/kuzet/reviewed/acceptance-observer-policy.json \
  --acceptance-observer-policy-sha256 REPLACE_WITH_64_HEX \
  --acceptance-observer-work-root /srv/kuzet/acceptance/72h/observer-work \
  --collector-state /srv/kuzet/acceptance/72h/state/collector.sqlite3 \
  --control-plane-url http://127.0.0.1:8765 \
  --machine-token-file /srv/kuzet/secrets/machine_token \
  --acceptance-controller-token-file /srv/kuzet/secrets/acceptance_controller_token \
  --collector-interval-seconds 60 \
  --duration-seconds 259200 \
  --out /srv/kuzet/acceptance/72h/run-record.json \
  --out-attestation /srv/kuzet/acceptance/72h/target-run-attestation.json \
  --out-signature /srv/kuzet/acceptance/72h/target-run-attestation.sig \
  --out-journal-proof /srv/kuzet/acceptance/72h/target-journal-proof.jsonl
uv run python scripts/pilot/acceptance_report.py generate \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 72h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --run-record /srv/kuzet/acceptance/72h/run-record.json \
  --run-attestation /srv/kuzet/acceptance/72h/target-run-attestation.json \
  --run-signature /srv/kuzet/acceptance/72h/target-run-attestation.sig \
  --journal-proof /srv/kuzet/acceptance/72h/target-journal-proof.jsonl \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --out-dir /srv/kuzet/acceptance/72h/report \
  --private-key /srv/kuzet/secrets/report-role-private.pem \
  --public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem
uv run python scripts/pilot/acceptance_report.py verify \
  --acceptance-site-id "$PILOT_SITE_ID" \
  --acceptance-campaign-id "$PILOT_ACCEPTANCE_CAMPAIGN_ID" \
  --acceptance-gate 72h \
  --acceptance-offline-root-spki-sha256 "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" \
  --acceptance-offline-root-public-key /srv/kuzet/reviewed/acceptance/offline-root-public.pem \
  --acceptance-trust-policy /srv/kuzet/reviewed/acceptance/trust-policy.json \
  --acceptance-trust-policy-signature /srv/kuzet/reviewed/acceptance/trust-policy.sig \
  --acceptance-manifest-role-public-key /srv/kuzet/reviewed/acceptance/manifest-role-public.pem \
  --acceptance-capacity-role-public-key /srv/kuzet/reviewed/acceptance/capacity-role-public.pem \
  --acceptance-run-role-public-key /srv/kuzet/reviewed/acceptance/run-role-public.pem \
  --acceptance-report-role-public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem \
  --acceptance-conditional-role-public-key /srv/kuzet/reviewed/acceptance/conditional-role-public.pem \
  --manifest /srv/kuzet/reviewed/acceptance/acceptance-manifest.json \
  --manifest-signature /srv/kuzet/reviewed/acceptance/acceptance-manifest.sig \
  --run-record /srv/kuzet/acceptance/72h/run-record.json \
  --run-attestation /srv/kuzet/acceptance/72h/target-run-attestation.json \
  --run-signature /srv/kuzet/acceptance/72h/target-run-attestation.sig \
  --journal-proof /srv/kuzet/acceptance/72h/target-journal-proof.jsonl \
  --measured-capacity-report /srv/kuzet/reviewed/measured-capacity.yaml \
  --measured-capacity-signature /srv/kuzet/reviewed/measured-capacity.sig \
  --metadata /srv/kuzet/acceptance/72h/report/acceptance-verification.json \
  --public-key /srv/kuzet/reviewed/acceptance/report-role-public.pem
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
