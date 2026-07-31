# NVIDIA target acceptance — pending external hardware

This repository does not establish that any RTX 4090/5090/L4 supports the
20-camera workload. The gate remains pending until the following commands run
on the reviewed Linux NVIDIA host with the exact signed 20-stream replay
corpus. Never substitute curated investor clips for this corpus.

The stopped-create sequence below is the raw single-epoch runtime launch
contract and preflight evidence; it is not an 8-hour or 72-hour gate by
itself. The production target runner owns the three ordered signed launch
profiles/nonces, append-only restart transition, fresh third epoch/channel,
capture, snapshot, and V3 proof flow. Its exact host commands are in
[`ready_to_start.md`](../../docs/pilot/ready_to_start.md). Both target gates are
**PENDING external NVIDIA/site execution — NOT RUN**.

Required fixtures:

- populated site configuration with exactly 20 credential references;
- populated runtime manifest and its SHA-256;
- signed measured-capacity report and its SHA-256;
- a reviewed `runtime-mount-contract.v1` and its SHA-256, listing direct
  read-only file mounts for all 20 `/run/secrets/<safe-name>` RTSP references,
  the machine token, runtime database URL, object-store access key,
  object-store secret key, reviewed inputs, model, engine, and `nvinfer`
  config plus writable evidence-spool, runtime-journal, and runtime-preview
  directories; all three writable entries must carry
  `storage_encryption_attested: true` and a finite
  `storage_quota_bytes`; every mount must use a source path disjoint from all
  other mount sources;
- rights-cleared model, TensorRT engine, and `nvinfer` configuration matching
  their manifest hashes;
- 20 real RTSP feeds or lawful timestamp-preserving replays matching the
  frozen workload;
- pre-created control, data, camera-LAN, and storage-egress networks with
  customer firewall allowlists;
- machine token, runtime database URL, and object-store credentials mounted as
  distinct regular, non-linked files; and
- pre-created host sources for the `/srv/kuzet/evidence-spool`,
  `/var/lib/kuzet/journal`, and `/var/lib/kuzet/previews` container targets,
  owned by UID/GID `10001:10001` with mode `0700`; the reviewed journal and
  preview sources must be quota-bounded, encryption-attested Kazakhstan
  storage.

Build and record the local image identity:

```bash
set -euo pipefail

export PILOT_RUNTIME_CODE_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_IMAGE=kuzet-pilot-runtime:review
docker build \
  --platform linux/amd64 \
  --file deploy/pilot/Dockerfile.runtime \
  --build-arg KUZET_RUNTIME_CODE_SHA256="$PILOT_RUNTIME_CODE_SHA256" \
  --tag "$PILOT_RUNTIME_IMAGE" \
  .
export PILOT_RUNTIME_IMAGE_ID="$(
  docker image inspect "$PILOT_RUNTIME_IMAGE" --format '{{.Id}}'
)"
case "$PILOT_RUNTIME_IMAGE_ID" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "captured runtime image ID is not immutable" >&2; exit 1 ;;
esac
docker image inspect "$PILOT_RUNTIME_IMAGE_ID" \
  --format '{{json .RepoDigests}} {{.Id}}'
```

Create the runtime stopped, attach the reviewed camera LAN, data, and
storage-egress networks, then start it. Obtain every network name from
`docker network ls`; do not guess it. These commands only define the pending
launch contract and do not establish target execution or acceptance.

```bash
set -euo pipefail

export PILOT_CONTROL_NETWORK=kuzet-controlled-pilot_control
export PILOT_DATA_NETWORK=kuzet-controlled-pilot_data
export PILOT_CAMERA_LAN_NETWORK=kuzet-camera-lan
export PILOT_STORAGE_EGRESS_NETWORK=kuzet-storage-egress
export PILOT_SITE_ID=REPLACE_WITH_AUTHORITATIVE_SITE_ID
export PILOT_SITE_CONFIG=/srv/kuzet/reviewed/site.yaml
export PILOT_RUNTIME_MANIFEST=/srv/kuzet/reviewed/runtime-manifest.yaml
export PILOT_CAPACITY_REPORT=/srv/kuzet/reviewed/measured-capacity.yaml
export PILOT_CAPACITY_SIGNATURE=/srv/kuzet/reviewed/measured-capacity.sig
export PILOT_CAPACITY_AUTHORITY_PUBLIC_KEY=/srv/kuzet/reviewed/capacity-authority.pem
export PILOT_MOUNT_CONTRACT=/srv/kuzet/reviewed/runtime-mount-contract.yaml
export PILOT_RUNTIME_DATABASE_URL_SECRET=/srv/kuzet/secrets/runtime_database_url
export PILOT_RUNTIME_OBJECT_STORE_ACCESS_KEY_SECRET=/srv/kuzet/secrets/runtime_object_store_access_key
export PILOT_RUNTIME_OBJECT_STORE_SECRET_KEY_SECRET=/srv/kuzet/secrets/runtime_object_store_secret_key
export PILOT_RUNTIME_JOURNAL_SOURCE=/srv/kuzet/runtime-journal
export PILOT_RUNTIME_PREVIEW_SOURCE=/srv/kuzet/runtime-preview
export PILOT_RUNTIME_OBJECT_STORE_REGION=REPLACE_WITH_REVIEWED_KZ_REGION
export PILOT_RUNTIME_MEMORY_LIMIT=REPLACE_WITH_MEASURED_MEMORY_LIMIT
export PILOT_RUNTIME_CPU_LIMIT=REPLACE_WITH_MEASURED_CPU_LIMIT
export PILOT_RUNTIME_SHM_LIMIT=REPLACE_WITH_MEASURED_SHM_LIMIT
export PILOT_RUNTIME_STOP_TIMEOUT_SECONDS=30
export PILOT_SITE_CONFIG_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_MANIFEST_SHA256=REPLACE_WITH_64_HEX
export PILOT_MEASURED_CAPACITY_SHA256=REPLACE_WITH_64_HEX
export PILOT_MOUNT_CONTRACT_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_IMAGE_CONFIG_SHA256=REPLACE_WITH_64_HEX
export PILOT_GPU_UUID=GPU-REPLACE_WITH_REVIEWED_UUID
export PILOT_RUNTIME_LAUNCH_NONCE=REPLACE_WITH_32_LOWER_HEX

# The validator reads only bounded regular files and emits one safe argv item
# per line. It hashes model/engine/config sources, verifies the captured image
# ID, requires exact target coverage and private runtime storage, and never
# resolves or prints RTSP or production credential values.
mapfile -t PILOT_RUNTIME_MOUNT_ARGV < <(
  uv run python scripts/pilot/validate_runtime_mounts.py \
    --site-config "$PILOT_SITE_CONFIG" \
    --site-config-sha256 "$PILOT_SITE_CONFIG_SHA256" \
    --runtime-manifest "$PILOT_RUNTIME_MANIFEST" \
    --runtime-manifest-sha256 "$PILOT_RUNTIME_MANIFEST_SHA256" \
    --measured-capacity-report "$PILOT_CAPACITY_REPORT" \
    --measured-capacity-sha256 "$PILOT_MEASURED_CAPACITY_SHA256" \
    --measured-capacity-signature "$PILOT_CAPACITY_SIGNATURE" \
    --capacity-authority-public-key "$PILOT_CAPACITY_AUTHORITY_PUBLIC_KEY" \
    --database-url-secret "$PILOT_RUNTIME_DATABASE_URL_SECRET" \
    --object-store-access-key-secret "$PILOT_RUNTIME_OBJECT_STORE_ACCESS_KEY_SECRET" \
    --object-store-secret-key-secret "$PILOT_RUNTIME_OBJECT_STORE_SECRET_KEY_SECRET" \
    --runtime-journal-source "$PILOT_RUNTIME_JOURNAL_SOURCE" \
    --runtime-preview-source "$PILOT_RUNTIME_PREVIEW_SOURCE" \
    --mount-contract "$PILOT_MOUNT_CONTRACT" \
    --mount-contract-sha256 "$PILOT_MOUNT_CONTRACT_SHA256" \
    --image-id "$PILOT_RUNTIME_IMAGE_ID"
)
test "${#PILOT_RUNTIME_MOUNT_ARGV[@]}" -eq 70

runtime_id=$(
  docker create \
    --name kuzet-pilot-runtime-acceptance \
    --gpus "device=$PILOT_GPU_UUID,\"capabilities=compute,utility,video\"" \
    --user 10001:10001 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --ipc private \
    --init \
    --stop-timeout "$PILOT_RUNTIME_STOP_TIMEOUT_SECONDS" \
    --pids-limit 512 \
    --memory "$PILOT_RUNTIME_MEMORY_LIMIT" \
    --cpus "$PILOT_RUNTIME_CPU_LIMIT" \
    --shm-size "$PILOT_RUNTIME_SHM_LIMIT" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=134217728,mode=1777 \
    --tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777 \
    --log-driver json-file \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    --network "$PILOT_CONTROL_NETWORK" \
    "${PILOT_RUNTIME_MOUNT_ARGV[@]}" \
    "$PILOT_RUNTIME_IMAGE_ID" \
    --site-id "$PILOT_SITE_ID" \
    --site-config /run/config/site.yaml \
    --site-config-sha256 "$PILOT_SITE_CONFIG_SHA256" \
    --runtime-manifest /run/config/runtime-manifest.yaml \
    --runtime-manifest-sha256 "$PILOT_RUNTIME_MANIFEST_SHA256" \
    --measured-capacity-report /run/config/measured-capacity.yaml \
    --measured-capacity-sha256 "$PILOT_MEASURED_CAPACITY_SHA256" \
    --measured-capacity-signature /run/config/measured-capacity.sig \
    --capacity-authority-public-key /run/config/capacity-authority.pem \
    --runtime-image-id-sha256 "${PILOT_RUNTIME_IMAGE_ID#sha256:}" \
    --runtime-image-config-sha256 "$PILOT_RUNTIME_IMAGE_CONFIG_SHA256" \
    --runtime-code-sha256 "$PILOT_RUNTIME_CODE_SHA256" \
    --mount-contract-sha256 "$PILOT_MOUNT_CONTRACT_SHA256" \
    --runtime-launch-nonce "$PILOT_RUNTIME_LAUNCH_NONCE" \
    --control-plane-url http://api:8000 \
    --machine-token-file /run/secrets/machine_token \
    --database-url-secret /run/secrets/runtime_database_url \
    --object-store-access-key-secret /run/secrets/runtime_object_store_access_key \
    --object-store-secret-key-secret /run/secrets/runtime_object_store_secret_key \
    --object-store-region "$PILOT_RUNTIME_OBJECT_STORE_REGION"
)
docker network connect "$PILOT_CAMERA_LAN_NETWORK" "$runtime_id"
docker network connect "$PILOT_DATA_NETWORK" "$runtime_id"
docker network connect "$PILOT_STORAGE_EGRESS_NETWORK" "$runtime_id"
docker start --attach "$runtime_id"
```

The process must refuse before GPU graph startup if a digest, model right,
target-site gate, measured workload binding, or capacity headroom check is
missing. Acceptance requires evidence that:

- all 20 sources remain supervised in one shared streammux/model/tracker graph;
- measured effective throughput is at least 125% of the frozen required
  throughput;
- scheduled sample drops stay below 1%;
- queue-age p95 is below 1 second and p99 below 2 seconds;
- peak GPU utilization is at most 75% and VRAM utilization at most 80%;
- reconnect, evidence, disk, and notification failure metrics are visible; and
- no continuous raw video is copied from the customer's NVR path.

After the TLS proxy starts, verify the public boundary from an approved host:

```bash
curl --fail --cacert /srv/kuzet/reviewed/pilot-ca.pem \
  "https://${PILOT_BIND_ADDRESS}:${PILOT_TLS_PORT:-8443}/login"
test "$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --cacert /srv/kuzet/reviewed/pilot-ca.pem \
    "https://${PILOT_BIND_ADDRESS}:${PILOT_TLS_PORT:-8443}/api/internal/telemetry"
)" = 404
```

Archive commands, manifests, image identities, `nvidia-smi`, TensorRT/driver
versions, raw Prometheus output, and the signed report. No CUDA, DeepStream,
TensorRT, exact-20, 8-hour, 72-hour, or GPU-capacity result has been produced
in the current cloud environment.
