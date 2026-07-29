# NVIDIA target acceptance — pending external hardware

This repository does not establish that any RTX 4090/5090/L4 supports the
20-camera workload. The gate remains pending until the following commands run
on the reviewed Linux NVIDIA host with the exact signed 20-stream replay
corpus. Never substitute curated investor clips for this corpus.

Required fixtures:

- populated site configuration with exactly 20 credential references;
- populated runtime manifest and its SHA-256;
- signed measured-capacity report and its SHA-256;
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
  --tag "$PILOT_RUNTIME_IMAGE" \
  .
docker image inspect "$PILOT_RUNTIME_IMAGE" \
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
export PILOT_SITE_CONFIG_SHA256=REPLACE_WITH_64_HEX
export PILOT_RUNTIME_MANIFEST_SHA256=REPLACE_WITH_64_HEX
export PILOT_MEASURED_CAPACITY_SHA256=REPLACE_WITH_64_HEX

runtime_id=$(
  docker create \
    --name kuzet-pilot-runtime-acceptance \
    --gpus all \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 512 \
    --memory 16g \
    --cpus 8 \
    --network "$PILOT_CONTROL_NETWORK" \
    --mount type=bind,src="$PILOT_SITE_CONFIG",dst=/run/config/site.yaml,readonly \
    --mount type=bind,src="$PILOT_RUNTIME_MANIFEST",dst=/run/config/runtime-manifest.yaml,readonly \
    --mount type=bind,src="$PILOT_CAPACITY_REPORT",dst=/run/config/measured-capacity.yaml,readonly \
    --mount type=bind,src=/srv/kuzet/secrets/machine_token,dst=/run/secrets/machine_token,readonly \
    --mount type=bind,src=/srv/kuzet/evidence-spool,dst=/srv/kuzet/evidence-spool \
    "$PILOT_RUNTIME_IMAGE" \
    --site-config /run/config/site.yaml \
    --site-config-sha256 "$PILOT_SITE_CONFIG_SHA256" \
    --runtime-manifest /run/config/runtime-manifest.yaml \
    --runtime-manifest-sha256 "$PILOT_RUNTIME_MANIFEST_SHA256" \
    --measured-capacity-report /run/config/measured-capacity.yaml \
    --measured-capacity-sha256 "$PILOT_MEASURED_CAPACITY_SHA256" \
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
