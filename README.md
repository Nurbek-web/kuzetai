# Kuzet AI / ProtectorAI

Kuzet AI currently has two deliberately separate surfaces.

## Investor MVP

The existing Apple Silicon video pipeline and Gradio dashboard are a
hand-curated investor demonstration. They detect selected examples of fights,
weapons, fire/smoke, and restricted-zone activity. The investor reel and demo
remain available and are not evidence that the models generalize to a customer
site.

```bash
# Install uv first: https://astral.sh/uv
uv run python -m cli run-file --input path/to/video.mp4 --output out/annotated.mp4
uv run python -m cli serve
uv run python -m cli build-reel
```

## Controlled-pilot runtime

The additive runtime under `protector/pilot/` implements contracts and
orchestration for a shared, bounded multi-camera service. It is **not a validated 20-camera runtime**
and is not production-ready. A fresh Linux NVIDIA target, the exact 20 lawful
customer streams or frozen replay sources, and the documented 8-hour and
72-hour acceptance gates are still required.

Continuous raw video remains in the customer NVR or other customer-controlled
local path. Kuzet stores only bounded event evidence and metadata. Every alert
is a candidate until human confirmation; the system never automatically calls
police or fire services and never controls doors.

Start with the [pilot deployment runbook](docs/pilot/deployment_runbook.md), the
[Ready-to-Start gate](docs/pilot/ready_to_start.md), and the
[known limits](docs/pilot/known_limits.md). Operators also need the
[operator runbook](docs/pilot/operator_runbook.md), [incident response
runbook](docs/pilot/incident_response.md), [model
register](docs/pilot/model_register.md), and still-PENDING [handover
manifest](docs/pilot/handover_manifest.md).

The packaged acceptance controller and target runner now include the reviewed,
additive retained-runtime continuation contract: three ordered signed source
profiles and launch nonces, a fresh third runtime epoch/channel, and a durable
append-only execution-transition journal. The exact host-side 8-hour and
72-hour command contracts are documented, but both are **PENDING external
NVIDIA/site execution — NOT RUN**. No endurance, CUDA, DeepStream, TensorRT,
GPU-capacity, or exact-20 result is claimed.

Controlled-pilot status is **PENDING implementation review and external
execution**. The model-engine builder contract, bounded orphan-version
retention instrumentation, storage authority probes, target NVIDIA/site gates,
and the separate Compose runtime activation wrapper must all close before
activation. No full-suite pass is claimed for this revision.

## Investor-demo quickstart

```bash
export PYTORCH_ENABLE_MPS_FALLBACK=1
uv run pytest tests/ -q
uv run ruff check protector tests cli.py
```

## Investor-demo modules

- **Event Analysis** — fight / aggression detection (X-CLIP zero-shot + ViT)
- **Alarm Detection** — weapons (YOLO) + fire/smoke detection
- **Restricted Zone Control** — polygon-based intrusion and loitering detection
