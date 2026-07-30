# NVIDIA target acceptance — pending external hardware

This repository does not establish that any RTX 4090/5090/L4 supports the
20-camera workload. The gate remains pending until the following commands run
on the reviewed Linux NVIDIA host with the exact signed 20-stream replay
corpus. Never substitute curated investor clips for this corpus.

Required fixtures:

- populated site configuration with exactly 20 credential references;
- populated runtime manifest and its SHA-256;
- signed measured-capacity report and its SHA-256;
- a reviewed `runtime-mount-contract.v1` and its SHA-256, listing direct
  read-only file mounts for all 20 `/run/secrets/<safe-name>` RTSP references,
  the machine token, reviewed inputs, model, engine, and `nvinfer` config plus
  the one writable evidence-spool directory; every camera secret must use a
  unique host source path disjoint from token, reviewed-input, and artifact
  sources;
- rights-cleared model, TensorRT engine, and `nvinfer` configuration matching
  their manifest hashes;
- 20 real RTSP feeds or lawful timestamp-preserving replays matching the
  frozen workload;
- pre-created camera-LAN and storage-egress networks with customer firewall
  allowlists; and
- machine token mounted as a regular, non-linked file.

Build and record the local image identity:

```bash
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

Create the runtime stopped, attach the separately reviewed camera LAN, then
start it. The control network name is obtained from `docker network ls`; do not
guess it.

```bash
export PILOT_CONTROL_NETWORK=kuzet-controlled-pilot_control
export PILOT_CAMERA_LAN_NETWORK=kuzet-camera-lan
export PILOT_SITE_CONFIG=/srv/kuzet/reviewed/site.yaml
export PILOT_RUNTIME_MANIFEST=/srv/kuzet/reviewed/runtime-manifest.yaml
export PILOT_CAPACITY_REPORT=/srv/kuzet/reviewed/measured-capacity.yaml
export PILOT_CAPACITY_SIGNATURE=/srv/kuzet/reviewed/measured-capacity.sig
export PILOT_CAPACITY_AUTHORITY_PUBLIC_KEY=/srv/kuzet/reviewed/capacity-authority.pem
export PILOT_MOUNT_CONTRACT=/srv/kuzet/reviewed/runtime-mount-contract.yaml
export PILOT_SITE_CONFIG_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_MANIFEST_SHA256=REPLACE_WITH_64_HEX
export PILOT_MEASURED_CAPACITY_SHA256=REPLACE_WITH_64_HEX
export PILOT_MOUNT_CONTRACT_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_CODE_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_IMAGE_CONFIG_SHA256=REPLACE_WITH_64_HEX
export PILOT_GPU_UUID=GPU-REPLACE_WITH_REVIEWED_UUID
export PILOT_RUNTIME_LAUNCH_NONCE=REPLACE_WITH_32_LOWER_HEX

# The validator reads only bounded regular files and emits one safe argv item
# per line. It hashes model/engine/config sources, verifies the captured image
# ID, requires exact target coverage, and never resolves or prints RTSP values.
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
    --mount-contract "$PILOT_MOUNT_CONTRACT" \
    --mount-contract-sha256 "$PILOT_MOUNT_CONTRACT_SHA256" \
    --image-id "$PILOT_RUNTIME_IMAGE_ID"
)
test "${#PILOT_RUNTIME_MOUNT_ARGV[@]}" -eq 60

runtime_id=$(
  docker create \
    --name kuzet-pilot-runtime-acceptance \
    --gpus "device=$PILOT_GPU_UUID,capabilities=compute,utility,video" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 512 \
    --memory 16g \
    --cpus 8 \
    --network "$PILOT_CONTROL_NETWORK" \
    "${PILOT_RUNTIME_MOUNT_ARGV[@]}" \
    "$PILOT_RUNTIME_IMAGE_ID" \
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
    --machine-token-file /run/secrets/machine_token
)
docker network connect "$PILOT_CAMERA_LAN_NETWORK" "$runtime_id"
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
versions, raw Prometheus output, and the signed report. This gate is explicitly
pending in the Apple M2 environment.
