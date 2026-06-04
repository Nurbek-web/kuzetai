from __future__ import annotations

import os

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

import numpy as np
import torch

from protector.config import DEVICE, XCLIP_SIZE

PROMPTS = [
    "people physically fighting",
    "a person hitting another person",
    "students walking calmly in a hallway",
    "people standing and talking",
    "children running and playing",
]
VIOLENT_INDICES = [0, 1]  # indices in PROMPTS that are "violent"


class XClipScorer:
    def __init__(self, device: str = DEVICE) -> None:
        from transformers import AutoModel, AutoProcessor

        self._device = device
        self._processor = AutoProcessor.from_pretrained("microsoft/xclip-base-patch32")
        self._model = AutoModel.from_pretrained(
            "microsoft/xclip-base-patch32",
            torch_dtype=torch.float16 if device in ("mps", "cuda") else torch.float32,
        ).to(device)
        self._model.eval()

    def score_clip(self, frames: list[np.ndarray]) -> dict[str, float]:
        """
        Score a list of frames (8 BGR frames, each HxWx3 uint8).
        Resizes each to XCLIP_SIZE x XCLIP_SIZE (224x224).
        Returns dict with 'violence_prob' (0-1), 'top_prompt', and per-prompt scores.
        """
        import cv2

        # Resize and convert BGR→RGB
        rgb_frames = [
            cv2.cvtColor(cv2.resize(f, (XCLIP_SIZE, XCLIP_SIZE)), cv2.COLOR_BGR2RGB)
            for f in frames
        ]
        # X-CLIP base-patch32 MIT module expects exactly 8 frames
        _n_frames = 8
        while len(rgb_frames) < _n_frames:
            rgb_frames.append(rgb_frames[-1])
        rgb_frames = rgb_frames[:_n_frames]

        inputs = self._processor(
            text=PROMPTS,
            videos=[rgb_frames],
            return_tensors="pt",
            padding=True,
        )
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = outputs.logits_per_video.softmax(dim=1).cpu().float().squeeze(0)

        scores = {p: float(probs[i]) for i, p in enumerate(PROMPTS)}
        violence_prob = sum(float(probs[i]) for i in VIOLENT_INDICES)
        top_prompt = PROMPTS[int(probs.argmax())]
        return {"violence_prob": violence_prob, "top_prompt": top_prompt, **scores}

    def release(self) -> None:
        del self._model, self._processor
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass
