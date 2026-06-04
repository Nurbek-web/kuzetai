from __future__ import annotations

import os

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

import numpy as np

from protector.config import DEVICE


class ViTViolenceClassifier:
    def __init__(self, device: str = DEVICE) -> None:
        import timm
        import torch
        from huggingface_hub import hf_hub_download

        self._device = device
        # Download timm-style weights from HuggingFace
        model_path = hf_hub_download(
            "jaranohaal/vit-base-violence-detection", "pytorch_model.bin"
        )
        state_dict = torch.load(model_path, map_location="cpu", weights_only=True)

        # Create timm vit_base_patch16_224 with 2 classes (NonViolence=0, Violence=1)
        self._model = timm.create_model(
            "vit_base_patch16_224", pretrained=False, num_classes=2
        )
        self._model.load_state_dict(state_dict, strict=True)
        self._model.to(device)
        self._model.eval()

        # Build the preprocessing transform from timm data config
        from timm.data import create_transform, resolve_data_config
        config = resolve_data_config({}, model=self._model)
        self._transform = create_transform(**config)

        # Label 1 = Violence
        self._violence_idx = 1

    def score_frames(self, frames: list[np.ndarray]) -> list[float]:
        """
        Score each frame independently.
        Returns list of float (0-1), one per frame, where 1.0 = fully violent.
        Expects BGR uint8 frames.
        """
        import cv2
        import torch
        from PIL import Image

        scores: list[float] = []
        for frame in frames:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb)
            tensor = self._transform(pil_img).unsqueeze(0).to(self._device)
            with torch.no_grad():
                logits = self._model(tensor)
                probs = logits.softmax(dim=-1).cpu().float().squeeze(0)
            violence_score = float(probs[self._violence_idx])
            scores.append(violence_score)
        return scores

    def score_clip_median(self, frames: list[np.ndarray]) -> float:
        """Returns median violence score over all frames. Uses ~8 sampled frames."""
        import random

        sample = random.sample(frames, min(8, len(frames))) if len(frames) > 8 else frames
        scores = self.score_frames(sample)
        return float(np.median(scores))

    def release(self) -> None:
        del self._model, self._transform
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass
