"""Pure native source-profile evidence tracking for the fixed 20-camera pilot."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import subprocess
import tempfile
import weakref
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from threading import RLock
from typing import ClassVar, Literal, Protocol

from protector.pilot.trusted_artifacts import (
    canonical_ed25519_public_key_pem,
    ed25519_public_key_spki_sha256,
    trusted_openssl_executable,
    verify_ed25519_payload,
)

_CAMERA_COUNT = 20
_KEY_BYTES = 32
_PREWARM_NS = 60_000_000_000
_IDENTITY_DOMAIN = b"kuzet-ai/native-source-identity/v1\x00"
_EXPECTATION_DOMAIN = b"kuzet-ai/native-source-profile-expectation/v1\x00"
_MAX_URL_BYTES = 16_384
_MAX_DELTA_CAPACITY = 1_000_000
_CALLBACK_ISSUER = object()
_INT64_MAX = 2**63 - 1
_SOURCE_PROOF_SCHEMA = "kuzet.native-source-profile-proof.v1"
_SOURCE_MILESTONE_SCHEMA = "kuzet.native-source-profile-milestone.v1"
_SOURCE_PROOF_DOMAIN = b"kuzet-ai/native-source-profile-proof/v1\x00"
_SOURCE_MILESTONE_AUTH_DOMAIN = b"kuzet-ai/native-source-profile-milestone-authentication/v1\x00"
_SOURCE_MILESTONE_HEAD_DOMAIN = b"kuzet-ai/native-source-profile-milestone-head/v1\x00"
_SOURCE_MILESTONE_TERMINAL_DOMAIN = b"kuzet-ai/native-source-profile-milestone-terminal/v1\x00"
_ED25519_PKCS8_SEED_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_MAX_PROOF_MILESTONES = _CAMERA_COUNT * 11
_DELTA_EVENTS = frozenset(
    {
        "callback_closed",
        "epoch_started",
        "failure",
        "native_probe_failure",
        "observation",
        "rtp_caps",
        "source_bound",
    }
)


def _validate_identifier(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 128
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a non-empty bounded identifier")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{label} must be a non-empty bounded identifier") from None


def _validate_int(
    value: int,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = _INT64_MAX,
) -> None:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside its allowed integer bounds")


def _increment_int64(value: int, label: str) -> int:
    _validate_int(value, label)
    if value == _INT64_MAX:
        raise OverflowError(f"{label} exhausted its signed 64-bit range")
    return value + 1


def _checked_int64_add(left: int, right: int, label: str) -> int:
    _validate_int(left, label)
    _validate_int(right, label)
    if left > _INT64_MAX - right:
        raise ValueError(f"{label} is not reachable in signed 64-bit arithmetic")
    return left + right


def _checked_int64_multiply(left: int, right: int, label: str) -> int:
    _validate_int(left, label)
    _validate_int(right, label)
    if left and right > _INT64_MAX // left:
        raise ValueError(f"{label} is not reachable in signed 64-bit arithmetic")
    return left * right


class _SecretMaterial:
    __slots__ = ("_key", "_resolved_url")

    def __init__(
        self,
        resolved_url: object,
        commitment_key: object,
    ) -> None:
        self._resolved_url = resolved_url
        self._key = commitment_key

    def __repr__(self) -> str:
        return "_SecretMaterial(<redacted>)"

    def clear(self) -> None:
        self._resolved_url = ""
        self._key = b""

    def take(self) -> tuple[object, object]:
        resolved_url = self._resolved_url
        commitment_key = self._key
        self.clear()
        return resolved_url, commitment_key


class _ProofSeedMaterial:
    __slots__ = ("_seed",)

    def __init__(self, seed: object) -> None:
        self._seed = seed

    def __repr__(self) -> str:
        return "_ProofSeedMaterial(<redacted>)"

    def take(self) -> object:
        seed = self._seed
        self._seed = b""
        return seed


class _MilestoneKeyMaterial:
    __slots__ = ("_key",)

    def __init__(self, key: object) -> None:
        self._key = key

    def __repr__(self) -> str:
        return "_MilestoneKeyMaterial(<redacted>)"

    def clear(self) -> None:
        self._key = b""

    def take(self) -> object:
        key = self._key
        self.clear()
        return key


class _MilestoneAuthenticator:
    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        self._key = key

    def __repr__(self) -> str:
        return "_MilestoneAuthenticator(<redacted>)"

    def digest_hex(self, payload: bytes) -> str:
        return hmac.digest(self._key, payload, "sha256").hex()


def _take_milestone_authenticator_key(material: _MilestoneKeyMaterial) -> bytes:
    raw_key = material.take()
    owned_key = b""
    try:
        if type(raw_key) is bytes:
            owned_key = raw_key
        elif type(raw_key) is bytearray:
            owned_key = bytes(raw_key)
        if len(owned_key) != _KEY_BYTES:
            raise ValueError("source profile milestone authenticator key must be exactly 32-byte")
        raw_key = b""
        return owned_key
    except Exception:
        raw_key = b""
        owned_key = b""
        raise


class SourceProfileProofSigner(Protocol):
    """Dedicated signing capability; source URL commitment material is never accepted."""

    @property
    def key_id(self) -> str: ...

    @property
    def public_key(self) -> bytes: ...

    def sign(self, payload: bytes) -> bytes: ...


def _write_private_proof_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class Ed25519SourceProfileProofSigner:
    """In-memory seed-backed Ed25519 signer used only for final proof envelopes."""

    __slots__ = ("_key_id", "_public_key", "_signing_seed")

    def __init__(
        self,
        *,
        key_id: str,
        signing_seed: bytes | bytearray,
    ) -> None:
        seed_material = _ProofSeedMaterial(signing_seed)
        signing_seed = b""
        raw_seed = seed_material.take()
        owned_seed = b""
        try:
            _validate_identifier(key_id, "source profile proof key_id")
            if type(raw_seed) is bytes:
                owned_seed = raw_seed
            elif type(raw_seed) is bytearray:
                owned_seed = bytes(raw_seed)
            if len(owned_seed) != 32:
                raise ValueError("source profile proof signing seed must be exactly 32-byte")
            object.__setattr__(self, "_key_id", key_id)
            object.__setattr__(self, "_signing_seed", owned_seed)
            raw_seed = b""
            owned_seed = b""
            object.__setattr__(self, "_public_key", self._derive_public_key())
        except Exception:
            raw_seed = b""
            owned_seed = b""
            raise

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("source profile proof signers are immutable")

    def __repr__(self) -> str:
        return f"Ed25519SourceProfileProofSigner(key_id={self._key_id!r}, signing_seed=<redacted>)"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> bytes:
        return bytes(self._public_key)

    def _derive_public_key(self) -> bytes:
        private_key_der = _ED25519_PKCS8_SEED_PREFIX + self._signing_seed
        public_key = b""
        failed = False
        try:
            with tempfile.TemporaryDirectory(prefix="kuzet-source-proof-key-") as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                private_key_path = root / "private.der"
                _write_private_proof_file(private_key_path, private_key_der)
                private_key_der = b""
                result = subprocess.run(
                    (
                        trusted_openssl_executable(),
                        "pkey",
                        "-inform",
                        "DER",
                        "-in",
                        str(private_key_path),
                        "-pubout",
                    ),
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode:
                    failed = True
                else:
                    public_key = canonical_ed25519_public_key_pem(result.stdout)
        except Exception:
            failed = True
        finally:
            private_key_der = b""
        if failed or not public_key:
            public_key = b""
            raise ValueError("source profile proof public key derivation failed") from None
        return public_key

    def sign(self, payload: bytes) -> bytes:
        if type(payload) is not bytes or not 1 <= len(payload) <= 16 * 1024 * 1024:
            raise ValueError("source profile proof signing payload is invalid")
        private_key_der = _ED25519_PKCS8_SEED_PREFIX + self._signing_seed
        signature = b""
        failed = False
        try:
            with tempfile.TemporaryDirectory(prefix="kuzet-source-proof-signing-") as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                private_key_path = root / "private.der"
                payload_path = root / "payload"
                signature_path = root / "signature"
                _write_private_proof_file(private_key_path, private_key_der)
                private_key_der = b""
                _write_private_proof_file(payload_path, payload)
                result = subprocess.run(
                    (
                        trusted_openssl_executable(),
                        "pkeyutl",
                        "-sign",
                        "-rawin",
                        "-inkey",
                        str(private_key_path),
                        "-keyform",
                        "DER",
                        "-in",
                        str(payload_path),
                        "-out",
                        str(signature_path),
                    ),
                    check=False,
                    capture_output=True,
                    timeout=30,
                )
                if result.returncode:
                    failed = True
                else:
                    signature = signature_path.read_bytes()
        except Exception:
            failed = True
        finally:
            private_key_der = b""
        if failed or len(signature) != 64:
            signature = b""
            raise ValueError("source profile proof signing failed") from None
        return signature


def _canonical_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _take_validated_secret_material(
    secrets: _SecretMaterial,
) -> tuple[object, bytes]:
    resolved_url, raw_key = secrets.take()
    commitment_key = b""
    invalid_key = False
    conversion_failed = False
    try:
        if type(raw_key) is bytes:
            commitment_key = raw_key
        elif type(raw_key) is bytearray:
            commitment_key = bytes(raw_key)
        else:
            invalid_key = True
        if len(commitment_key) != _KEY_BYTES:
            invalid_key = True
    except Exception:
        conversion_failed = True
    raw_key = b""
    if invalid_key or conversion_failed:
        resolved_url = ""
        commitment_key = b""
        raise ValueError("source profile commitment key must be exactly 32-byte") from None
    return resolved_url, commitment_key


def _identity_payload(
    *,
    site_id: str,
    camera_id: str,
    source_index: int,
    resolved_url: str,
) -> bytes:
    encoded_url: bytes | None = None
    canonical: bytes | None = None
    payload = b""
    canonical_payload: dict[str, object] = {}
    failed = False
    try:
        if type(resolved_url) is not str or not resolved_url or "\x00" in resolved_url:
            failed = True
        else:
            encoded_url = resolved_url.encode("utf-8")
            if len(encoded_url) > _MAX_URL_BYTES:
                failed = True
        if not failed:
            canonical_payload = {
                "camera_id": camera_id,
                "resolved_url": resolved_url,
                "site_id": site_id,
                "source_index": source_index,
            }
            canonical = json.dumps(
                canonical_payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            payload = _IDENTITY_DOMAIN + canonical
    except Exception:
        failed = True
    finally:
        resolved_url = ""
        encoded_url = None
        canonical = None
        canonical_payload.clear()
        canonical_payload = {}
    if failed or not payload:
        payload = b""
        raise ValueError("resolved source identity is invalid") from None
    return payload


def _compute_commitment_from_secrets(
    *,
    site_id: str,
    camera_id: str,
    source_index: int,
    secrets: _SecretMaterial,
) -> str:
    resolved_url, commitment_key = _take_validated_secret_material(secrets)
    payload = b""
    commitment: str | None = None
    failed = False
    try:
        payload = _identity_payload(
            site_id=site_id,
            camera_id=camera_id,
            source_index=source_index,
            resolved_url=resolved_url,  # type: ignore[arg-type]
        )
        commitment = hmac.digest(
            commitment_key,
            payload,
            "sha256",
        ).hex()
    except Exception:
        failed = True
    resolved_url = ""
    commitment_key = b""
    payload = b""
    if failed or commitment is None:
        raise ValueError("source identity commitment could not be computed") from None
    return commitment


def compute_source_identity_commitment(
    *,
    site_id: str,
    camera_id: str,
    source_index: int,
    resolved_url: str,
    commitment_key: bytes | bytearray,
) -> str:
    """Commit to a resolved source without retaining or returning its URL or key."""
    secrets = _SecretMaterial(resolved_url, commitment_key)
    resolved_url = ""
    commitment_key = b""
    try:
        _validate_identifier(site_id, "site_id")
        _validate_identifier(camera_id, "camera_id")
        _validate_int(
            source_index,
            "source_index",
            maximum=_CAMERA_COUNT - 1,
        )
    except Exception:
        secrets.clear()
        raise
    return _compute_commitment_from_secrets(
        site_id=site_id,
        camera_id=camera_id,
        source_index=source_index,
        secrets=secrets,
    )


def _validate_digest(value: str, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _expectation_payload(
    site_id: str,
    expectation: SourceProfileExpectation,
) -> bytes:
    return _EXPECTATION_DOMAIN + _canonical_bytes(
        {
            "bitrate_kbps_max": expectation.bitrate_kbps_max,
            "bitrate_kbps_min": expectation.bitrate_kbps_min,
            "camera_id": expectation.camera_id,
            "codec": expectation.codec,
            "fps_max": expectation.fps_max,
            "fps_min": expectation.fps_min,
            "height": expectation.height,
            "max_timestamp_gap_ns": expectation.max_timestamp_gap_ns,
            "max_timestamp_skew_ns": expectation.max_timestamp_skew_ns,
            "site_id": site_id,
            "source_identity_commitment": expectation.source_identity_commitment,
            "source_index": expectation.source_index,
            "stale_after_ns": expectation.stale_after_ns,
            "width": expectation.width,
        }
    )


@dataclass(frozen=True, slots=True)
class SourceProfileExpectation:
    """Signed public expectation; the credential-bearing source is only committed."""

    camera_id: str
    source_index: int
    source_identity_commitment: str
    codec: Literal["h264", "h265"]
    width: int
    height: int
    fps_min: float
    fps_max: float
    bitrate_kbps_min: int
    bitrate_kbps_max: int
    max_timestamp_gap_ns: int
    max_timestamp_skew_ns: int
    stale_after_ns: int
    signature: str

    def __post_init__(self) -> None:
        _validate_identifier(self.camera_id, "camera_id")
        _validate_int(self.source_index, "source_index", maximum=_CAMERA_COUNT - 1)
        _validate_digest(self.source_identity_commitment, "source identity commitment")
        if type(self.codec) is not str or self.codec not in {"h264", "h265"}:
            raise ValueError("codec must be h264 or h265")
        _validate_int(self.width, "width", minimum=320, maximum=16_384)
        _validate_int(self.height, "height", minimum=240, maximum=8_640)
        if (
            type(self.fps_min) not in {int, float}
            or type(self.fps_max) not in {int, float}
            or not math.isfinite(self.fps_min)
            or not math.isfinite(self.fps_max)
            or not 1.0 <= self.fps_min <= self.fps_max <= 240
        ):
            raise ValueError("FPS bounds must be finite, positive, and ordered")
        _validate_int(
            self.bitrate_kbps_min,
            "minimum bitrate",
            minimum=1,
            maximum=1_000_000,
        )
        _validate_int(
            self.bitrate_kbps_max,
            "maximum bitrate",
            minimum=self.bitrate_kbps_min,
            maximum=1_000_000,
        )
        _validate_int(
            self.max_timestamp_gap_ns,
            "timestamp gap",
            minimum=1,
            maximum=120_000_000_000,
        )
        _validate_int(
            self.max_timestamp_skew_ns,
            "timestamp skew",
            minimum=0,
            maximum=60_000_000_000,
        )
        _validate_int(
            self.stale_after_ns,
            "stale source bound",
            minimum=1,
            maximum=300_000_000_000,
        )
        _validate_digest(self.signature, "source profile signature")

    @classmethod
    def signed(
        cls,
        *,
        site_id: str,
        camera_id: str,
        source_index: int,
        resolved_url: str,
        commitment_key: bytes | bytearray,
        codec: Literal["h264", "h265"],
        width: int,
        height: int,
        fps_min: float,
        fps_max: float,
        bitrate_kbps_min: int,
        bitrate_kbps_max: int,
        max_timestamp_gap_ns: int,
        max_timestamp_skew_ns: int,
        stale_after_ns: int,
    ) -> SourceProfileExpectation:
        """Resolve, commit, and sign without placing the URL/key on the result."""
        secrets = _SecretMaterial(resolved_url, commitment_key)
        resolved_url = ""
        commitment_key = b""
        try:
            _validate_identifier(site_id, "site_id")
            template = cls(
                camera_id=camera_id,
                source_index=source_index,
                source_identity_commitment="0" * 64,
                codec=codec,
                width=width,
                height=height,
                fps_min=fps_min,
                fps_max=fps_max,
                bitrate_kbps_min=bitrate_kbps_min,
                bitrate_kbps_max=bitrate_kbps_max,
                max_timestamp_gap_ns=max_timestamp_gap_ns,
                max_timestamp_skew_ns=max_timestamp_skew_ns,
                stale_after_ns=stale_after_ns,
                signature="0" * 64,
            )
            return _sign_expectation_from_secrets(
                cls=cls,
                site_id=site_id,
                template=template,
                secrets=secrets,
            )
        except Exception:
            secrets.clear()
            raise

    def to_dict(self) -> dict[str, object]:
        return {
            "camera_id": self.camera_id,
            "source_index": self.source_index,
            "source_identity_commitment": self.source_identity_commitment,
            "codec": self.codec,
            "width": self.width,
            "height": self.height,
            "fps_min": self.fps_min,
            "fps_max": self.fps_max,
            "bitrate_kbps_min": self.bitrate_kbps_min,
            "bitrate_kbps_max": self.bitrate_kbps_max,
            "max_timestamp_gap_ns": self.max_timestamp_gap_ns,
            "max_timestamp_skew_ns": self.max_timestamp_skew_ns,
            "stale_after_ns": self.stale_after_ns,
            "signature": self.signature,
        }


def _sign_expectation_from_secrets(
    *,
    cls: type[SourceProfileExpectation],
    site_id: str,
    template: SourceProfileExpectation,
    secrets: _SecretMaterial,
) -> SourceProfileExpectation:
    resolved_url, commitment_key = _take_validated_secret_material(secrets)
    identity_payload = b""
    expectation_payload = b""
    signed: SourceProfileExpectation | None = None
    failed = False
    try:
        identity_payload = _identity_payload(
            site_id=site_id,
            camera_id=template.camera_id,
            source_index=template.source_index,
            resolved_url=resolved_url,  # type: ignore[arg-type]
        )
        commitment = hmac.digest(
            commitment_key,
            identity_payload,
            "sha256",
        ).hex()
        unsigned = cls(
            camera_id=template.camera_id,
            source_index=template.source_index,
            source_identity_commitment=commitment,
            codec=template.codec,
            width=template.width,
            height=template.height,
            fps_min=template.fps_min,
            fps_max=template.fps_max,
            bitrate_kbps_min=template.bitrate_kbps_min,
            bitrate_kbps_max=template.bitrate_kbps_max,
            max_timestamp_gap_ns=template.max_timestamp_gap_ns,
            max_timestamp_skew_ns=template.max_timestamp_skew_ns,
            stale_after_ns=template.stale_after_ns,
            signature="0" * 64,
        )
        expectation_payload = _expectation_payload(site_id, unsigned)
        signature = hmac.digest(
            commitment_key,
            expectation_payload,
            "sha256",
        ).hex()
        signed = cls(
            camera_id=unsigned.camera_id,
            source_index=unsigned.source_index,
            source_identity_commitment=unsigned.source_identity_commitment,
            codec=unsigned.codec,
            width=unsigned.width,
            height=unsigned.height,
            fps_min=unsigned.fps_min,
            fps_max=unsigned.fps_max,
            bitrate_kbps_min=unsigned.bitrate_kbps_min,
            bitrate_kbps_max=unsigned.bitrate_kbps_max,
            max_timestamp_gap_ns=unsigned.max_timestamp_gap_ns,
            max_timestamp_skew_ns=unsigned.max_timestamp_skew_ns,
            stale_after_ns=unsigned.stale_after_ns,
            signature=signature,
        )
    except Exception:
        failed = True
    resolved_url = ""
    commitment_key = b""
    identity_payload = b""
    expectation_payload = b""
    if failed or signed is None:
        raise ValueError("source profile expectation could not be signed") from None
    return signed


def _verify_expectation_signatures_from_secrets(
    *,
    site_id: str,
    expectations: tuple[SourceProfileExpectation, ...],
    secrets: _SecretMaterial,
    milestone_authenticator_key: bytes,
) -> None:
    _resolved_url, commitment_key = _take_validated_secret_material(secrets)
    expectation_payload = b""
    signature_invalid = False
    key_reused = False
    failed = False
    try:
        key_reused = hmac.compare_digest(
            commitment_key,
            milestone_authenticator_key,
        )
        for expectation in expectations:
            expectation_payload = _expectation_payload(site_id, expectation)
            expected_signature = hmac.digest(
                commitment_key,
                expectation_payload,
                "sha256",
            ).hex()
            expectation_payload = b""
            if not hmac.compare_digest(
                expectation.signature,
                expected_signature,
            ):
                signature_invalid = True
                break
    except Exception:
        failed = True
    _resolved_url = ""
    commitment_key = b""
    milestone_authenticator_key = b""
    expectation_payload = b""
    if failed:
        raise ValueError("source profile expectation signatures could not be verified") from None
    if signature_invalid:
        raise ValueError("source profile expectation signature is invalid") from None
    if key_reused:
        raise ValueError(
            "source profile milestone authenticator key must differ from the source commitment key"
        ) from None


@dataclass(frozen=True, slots=True)
class NativeSourceCaps:
    codec: Literal["h264", "h265"]
    width: int
    height: int
    fps: float
    bitrate_kbps: int

    def __post_init__(self) -> None:
        if type(self.codec) is not str or self.codec not in {"h264", "h265"}:
            raise ValueError("native CAPS codec must be h264 or h265")
        _validate_int(self.width, "native CAPS width", minimum=1, maximum=16_384)
        _validate_int(self.height, "native CAPS height", minimum=1, maximum=8_640)
        if (
            type(self.fps) not in {int, float}
            or not math.isfinite(self.fps)
            or not 1.0 <= self.fps <= 240
        ):
            raise ValueError("native CAPS FPS must be finite and positive")
        _validate_int(
            self.bitrate_kbps,
            "native CAPS bitrate",
            minimum=1,
            maximum=1_000_000,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "codec": self.codec,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "bitrate_kbps": self.bitrate_kbps,
        }


@dataclass(frozen=True, slots=True)
class NativeSourceObservation:
    """One complete observation assembled from native RTP/parser/decoder callbacks."""

    caps: NativeSourceCaps
    parser_bytes: int
    decoded_frames: int
    source_ntp_ns: int
    source_timestamp_ns: int
    observed_monotonic_ns: int

    def __post_init__(self) -> None:
        if type(self.caps) is not NativeSourceCaps:
            raise ValueError("native observation requires validated CAPS")
        _validate_int(self.parser_bytes, "parser byte counter", minimum=1)
        _validate_int(self.decoded_frames, "decoded frame counter", minimum=1)
        _validate_int(self.source_ntp_ns, "source NTP counter", minimum=1)
        _validate_int(self.source_timestamp_ns, "source timestamp counter", minimum=1)
        _validate_int(self.observed_monotonic_ns, "observation time")
        object.__setattr__(self, "caps", _clone_caps(self.caps))

    def to_dict(self) -> dict[str, object]:
        return {
            "caps": self.caps.to_dict(),
            "parser_bytes": self.parser_bytes,
            "decoded_frames": self.decoded_frames,
            "source_ntp_ns": self.source_ntp_ns,
            "source_timestamp_ns": self.source_timestamp_ns,
            "observed_monotonic_ns": self.observed_monotonic_ns,
        }


_FAILURE_CODE_VALUES = frozenset(
    {
        "bounded_buffer_overflow",
        "counter_regression",
        "excessive_gap",
        "excessive_skew",
        "host_monotonic_regression",
        "invalid_callback_provenance",
        "profile_mismatch",
        "stale_source",
        "timestamp_regression",
        "timestamp_replay",
    }
)
_MAX_SOURCE_FAILURES = len(_FAILURE_CODE_VALUES)
_MAX_PROFILE_FAILURES = _CAMERA_COUNT * _MAX_SOURCE_FAILURES
_CALLBACK_REQUIRED_FAILURE_VALUES = frozenset(
    {
        "counter_regression",
        "excessive_gap",
        "excessive_skew",
        "host_monotonic_regression",
        "invalid_callback_provenance",
        "profile_mismatch",
        "timestamp_regression",
        "timestamp_replay",
    }
)
_STRICT_CALLBACK_EVENT_FAILURE_VALUES = _CALLBACK_REQUIRED_FAILURE_VALUES - {"profile_mismatch"}
_PRIOR_CAPS_FAILURE_VALUES = frozenset(
    {
        "counter_regression",
        "timestamp_regression",
        "timestamp_replay",
    }
)
_PRIOR_OBSERVATION_FAILURE_VALUES = frozenset({"excessive_skew"})
_NATIVE_PROBE_FAILURE_VALUES = frozenset(
    {
        "bounded_buffer_overflow",
        "counter_regression",
        "invalid_callback_provenance",
    }
)


def _failure_code_value_for_public_name(name: str) -> str | None:
    if name == "PROFILE_MISMATCH":
        return "profile_mismatch"
    if name == "TIMESTAMP_REGRESSION":
        return "timestamp_regression"
    if name == "TIMESTAMP_REPLAY":
        return "timestamp_replay"
    if name == "EXCESSIVE_GAP":
        return "excessive_gap"
    if name == "EXCESSIVE_SKEW":
        return "excessive_skew"
    if name == "STALE_SOURCE":
        return "stale_source"
    if name == "COUNTER_REGRESSION":
        return "counter_regression"
    if name == "HOST_MONOTONIC_REGRESSION":
        return "host_monotonic_regression"
    if name == "BUFFER_OVERFLOW":
        return "bounded_buffer_overflow"
    if name == "INVALID_CALLBACK_PROVENANCE":
        return "invalid_callback_provenance"
    return None


def _canonical_failure_code(value: str) -> SourceProfileFailureCode:
    if type(value) is not str or value not in _FAILURE_CODE_VALUES:
        raise ValueError("failure code is not part of the source-profile vocabulary")
    return str.__new__(SourceProfileFailureCode, value)


class _SourceProfileFailureCodeMeta(type):
    def __getattribute__(cls, name: str) -> object:
        value = _failure_code_value_for_public_name(name)
        if value is not None:
            return _canonical_failure_code(value)
        return super().__getattribute__(name)

    def __setattr__(cls, name: str, value: object) -> None:
        if _failure_code_value_for_public_name(name) is not None:
            raise AttributeError("source profile failure code constants are immutable")
        super().__setattr__(name, value)

    def __delattr__(cls, name: str) -> None:
        if _failure_code_value_for_public_name(name) is not None:
            raise AttributeError("source profile failure code constants are immutable")
        super().__delattr__(name)


class SourceProfileFailureCode(str, metaclass=_SourceProfileFailureCodeMeta):
    """Immutable string-like failure code without mutable Enum singleton state."""

    __slots__ = ()

    PROFILE_MISMATCH: ClassVar[SourceProfileFailureCode]
    TIMESTAMP_REGRESSION: ClassVar[SourceProfileFailureCode]
    TIMESTAMP_REPLAY: ClassVar[SourceProfileFailureCode]
    EXCESSIVE_GAP: ClassVar[SourceProfileFailureCode]
    EXCESSIVE_SKEW: ClassVar[SourceProfileFailureCode]
    STALE_SOURCE: ClassVar[SourceProfileFailureCode]
    COUNTER_REGRESSION: ClassVar[SourceProfileFailureCode]
    HOST_MONOTONIC_REGRESSION: ClassVar[SourceProfileFailureCode]
    BUFFER_OVERFLOW: ClassVar[SourceProfileFailureCode]
    INVALID_CALLBACK_PROVENANCE: ClassVar[SourceProfileFailureCode]

    def __new__(cls, value: str) -> SourceProfileFailureCode:
        if (
            cls is not SourceProfileFailureCode
            or type(value) is not str
            or value not in _FAILURE_CODE_VALUES
        ):
            raise ValueError("failure code is not part of the source-profile vocabulary")
        return _canonical_failure_code(value)

    @property
    def value(self) -> str:
        return str(self)


@dataclass(frozen=True, slots=True)
class SourceProfileFailure:
    camera_id: str
    code: SourceProfileFailureCode
    epoch: int
    first_generation: int

    def __post_init__(self) -> None:
        _validate_identifier(self.camera_id, "failure camera_id")
        if type(self.code) is not SourceProfileFailureCode:
            raise ValueError("failure code must be SourceProfileFailureCode")
        _validate_int(self.epoch, "failure epoch", minimum=1)
        _validate_int(
            self.first_generation,
            "failure first generation",
            minimum=1,
        )
        if self.epoch >= self.first_generation:
            raise ValueError("failure first generation must follow its epoch start event")
        object.__setattr__(
            self,
            "code",
            _canonical_failure_code(self.code.value),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "camera_id": self.camera_id,
            "code": self.code.value,
            "epoch": self.epoch,
            "first_generation": self.first_generation,
        }


@dataclass(frozen=True, slots=True)
class SourceProfileMilestoneReceiptV1:
    schema: Literal["kuzet.native-source-profile-milestone.v1"]
    sequence: int
    site_id: str
    epoch: int
    epoch_started_generation: int
    authenticator_key_id: str
    camera_id: str
    source_index: int
    source_identity_commitment: str
    kind: Literal["prewarm_completed", "failure"]
    failure_code: SourceProfileFailureCode | None
    event_generation: int
    event_monotonic_ns: int
    parser_bytes: int | None
    decoded_frames: int | None
    source_ntp_ns: int | None
    source_timestamp_ns: int | None
    baseline_duration_ns: int | None
    prior_head: str
    head: str
    authentication_tag: str

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != _SOURCE_MILESTONE_SCHEMA:
            raise ValueError("source profile milestone schema is invalid")
        _validate_int(
            self.sequence,
            "source profile milestone sequence",
            minimum=1,
            maximum=_MAX_PROOF_MILESTONES,
        )
        _validate_identifier(self.site_id, "source profile milestone site_id")
        _validate_int(self.epoch, "source profile milestone epoch", minimum=1)
        _validate_int(
            self.epoch_started_generation,
            "source profile milestone epoch start generation",
            minimum=1,
        )
        _validate_identifier(
            self.authenticator_key_id,
            "source profile milestone authenticator key_id",
        )
        _validate_identifier(self.camera_id, "source profile milestone camera_id")
        _validate_int(
            self.source_index,
            "source profile milestone source index",
            maximum=_CAMERA_COUNT - 1,
        )
        _validate_digest(
            self.source_identity_commitment,
            "source profile milestone identity commitment",
        )
        if type(self.kind) is not str or self.kind not in {
            "prewarm_completed",
            "failure",
        }:
            raise ValueError("source profile milestone kind is invalid")
        _validate_int(
            self.event_generation,
            "source profile milestone event generation",
            minimum=1,
        )
        if not self.epoch_started_generation < self.event_generation:
            raise ValueError("source profile milestone must follow its epoch start")
        _validate_int(
            self.event_monotonic_ns,
            "source profile milestone event time",
        )
        _validate_digest(self.prior_head, "source profile milestone prior head")
        _validate_digest(self.head, "source profile milestone head")
        _validate_digest(
            self.authentication_tag,
            "source profile milestone authentication tag",
        )
        counters = (
            self.parser_bytes,
            self.decoded_frames,
            self.source_ntp_ns,
            self.source_timestamp_ns,
            self.baseline_duration_ns,
        )
        if self.kind == "failure":
            if type(self.failure_code) is not SourceProfileFailureCode:
                raise ValueError("failure milestone requires a canonical failure code")
            if any(value is not None for value in counters):
                raise ValueError("failure milestone cannot contain crossing counters")
            failure_code = _canonical_failure_code(self.failure_code.value)
            object.__setattr__(self, "failure_code", failure_code)
        else:
            if self.failure_code is not None:
                raise ValueError("prewarm milestone cannot contain a failure code")
            for value, label in zip(
                counters,
                (
                    "parser bytes",
                    "decoded frames",
                    "source NTP",
                    "source timestamp",
                    "baseline duration",
                ),
                strict=True,
            ):
                if value is None:
                    raise ValueError(f"prewarm milestone requires {label}")
                _validate_int(
                    value,
                    f"source profile milestone {label}",
                    minimum=1,
                )
            assert self.baseline_duration_ns is not None
            if self.baseline_duration_ns < _PREWARM_NS:
                raise ValueError("prewarm milestone baseline is below 60 seconds")
        expected_head = hashlib.sha256(
            _SOURCE_MILESTONE_HEAD_DOMAIN + _canonical_bytes(_milestone_receipt_unsigned_dict(self))
        ).hexdigest()
        if not hmac.compare_digest(self.head, expected_head):
            raise ValueError("source profile milestone head is invalid")

    def to_dict(self) -> dict[str, object]:
        payload = _milestone_receipt_unsigned_dict(self)
        payload["head"] = self.head
        payload["authentication_tag"] = self.authentication_tag
        return payload


def _milestone_receipt_unsigned_dict(
    receipt: SourceProfileMilestoneReceiptV1,
) -> dict[str, object]:
    return {
        "schema": receipt.schema,
        "sequence": receipt.sequence,
        "site_id": receipt.site_id,
        "epoch": receipt.epoch,
        "epoch_started_generation": receipt.epoch_started_generation,
        "authenticator_key_id": receipt.authenticator_key_id,
        "camera_id": receipt.camera_id,
        "source_index": receipt.source_index,
        "source_identity_commitment": receipt.source_identity_commitment,
        "kind": receipt.kind,
        "failure_code": (None if receipt.failure_code is None else receipt.failure_code.value),
        "event_generation": receipt.event_generation,
        "event_monotonic_ns": receipt.event_monotonic_ns,
        "parser_bytes": receipt.parser_bytes,
        "decoded_frames": receipt.decoded_frames,
        "source_ntp_ns": receipt.source_ntp_ns,
        "source_timestamp_ns": receipt.source_timestamp_ns,
        "baseline_duration_ns": receipt.baseline_duration_ns,
        "prior_head": receipt.prior_head,
    }


def _milestone_authentication_payload(
    receipt: SourceProfileMilestoneReceiptV1,
) -> bytes:
    payload = _milestone_receipt_unsigned_dict(receipt)
    payload["head"] = receipt.head
    return _SOURCE_MILESTONE_AUTH_DOMAIN + _canonical_bytes(payload)


def _milestone_terminal_payload(
    *,
    site_id: str,
    authenticator_key_id: str,
    epoch: int,
    epoch_started_generation: int,
    source_identity_commitments: tuple[str, ...],
    receipt_count: int,
    final_head: str,
) -> bytes:
    return _SOURCE_MILESTONE_TERMINAL_DOMAIN + _canonical_bytes(
        {
            "authenticator_key_id": authenticator_key_id,
            "epoch": epoch,
            "epoch_started_generation": epoch_started_generation,
            "final_head": final_head,
            "receipt_count": receipt_count,
            "site_id": site_id,
            "source_identity_commitments": list(source_identity_commitments),
        }
    )


@dataclass(frozen=True, slots=True)
class _SourceProfileMilestone:
    camera_id: str
    source_index: int
    source_identity_commitment: str
    kind: Literal["prewarm_completed", "failure"]
    failure_code: SourceProfileFailureCode | None
    event_generation: int
    event_monotonic_ns: int
    parser_bytes: int | None = None
    decoded_frames: int | None = None
    source_ntp_ns: int | None = None
    source_timestamp_ns: int | None = None
    baseline_duration_ns: int | None = None


@dataclass(frozen=True, slots=True)
class _PreparedMilestoneBatch:
    expected_count: int
    expected_prior_head: str
    receipts: tuple[SourceProfileMilestoneReceiptV1, ...]
    terminal_authentication_tag: str


@dataclass(frozen=True, slots=True)
class NativeSourceStateSnapshot:
    camera_id: str
    source_index: int
    bound: bool
    identity_verified: bool
    callback_generation: int
    observation: NativeSourceObservation | None
    baseline_duration_ns: int
    continuous_observations: int
    maximum_observed_gap_ns: int
    continuity_gap_bound_ns: int
    stale_after_ns: int
    prewarm_completed_monotonic_ns: int | None
    failures: tuple[SourceProfileFailure, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.camera_id, "snapshot camera_id")
        _validate_int(
            self.source_index,
            "snapshot source index",
            maximum=_CAMERA_COUNT - 1,
        )
        _validate_int(
            self.callback_generation,
            "snapshot callback generation",
        )
        _validate_int(
            self.baseline_duration_ns,
            "snapshot baseline duration",
        )
        _validate_int(
            self.continuous_observations,
            "snapshot continuous observations",
        )
        _validate_int(
            self.maximum_observed_gap_ns,
            "snapshot maximum observed gap",
        )
        _validate_int(
            self.continuity_gap_bound_ns,
            "snapshot continuity gap bound",
            minimum=1,
            maximum=1_000_000_000,
        )
        _validate_int(
            self.stale_after_ns,
            "snapshot stale source bound",
            minimum=1,
            maximum=300_000_000_000,
        )
        if self.prewarm_completed_monotonic_ns is not None:
            _validate_int(
                self.prewarm_completed_monotonic_ns,
                "snapshot prewarm completion time",
            )
        if type(self.bound) is not bool:
            raise ValueError("snapshot bound must be bool")
        if type(self.identity_verified) is not bool:
            raise ValueError("snapshot identity_verified must be bool")
        if self.bound != bool(self.callback_generation % 2):
            raise ValueError("snapshot callback generation does not match bound state")
        if self.bound and self.callback_generation == _INT64_MAX:
            raise ValueError("snapshot callback generation cannot guarantee a later close")
        if self.callback_generation == 0 and self.identity_verified:
            raise ValueError("unbound initial snapshot cannot have verified identity")
        if self.maximum_observed_gap_ns > self.continuity_gap_bound_ns:
            raise ValueError("snapshot maximum gap exceeds its signed continuity bound")
        if self.observation is not None and type(self.observation) is not NativeSourceObservation:
            raise ValueError("snapshot observation must be NativeSourceObservation or None")
        if type(self.failures) is not tuple:
            raise ValueError("snapshot failures must be a tuple")
        if len(self.failures) > _MAX_SOURCE_FAILURES:
            raise ValueError("snapshot failures exceed the bounded failure vocabulary")
        if any(type(failure) is not SourceProfileFailure for failure in self.failures):
            raise ValueError("snapshot failures must contain SourceProfileFailure records")
        failures = tuple(_clone_failure(failure) for failure in self.failures)
        if any(failure.camera_id != self.camera_id for failure in failures):
            raise ValueError("snapshot failures must belong to their source")
        failure_codes = tuple(failure.code.value for failure in failures)
        if failure_codes != tuple(sorted(set(failure_codes))):
            raise ValueError("snapshot failures must be unique and ordered")
        if (
            self.callback_generation > 0
            and not self.identity_verified
            and "profile_mismatch" not in failure_codes
        ):
            raise ValueError("unverified callback history requires profile_mismatch")
        if self.callback_generation == 0 and any(
            failure_code in _CALLBACK_REQUIRED_FAILURE_VALUES for failure_code in failure_codes
        ):
            raise ValueError("never-bound snapshot cannot contain callback failures")
        if self.callback_generation == 0 and "bounded_buffer_overflow" in failure_codes:
            overflow = next(
                failure for failure in failures if failure.code.value == "bounded_buffer_overflow"
            )
            stale = next(
                (failure for failure in failures if failure.code.value == "stale_source"),
                None,
            )
            if stale is None or stale.first_generation != overflow.first_generation:
                raise ValueError("never-bound overflow requires a co-emitted stale failure")
        for failure in failures:
            requires_callback_event = (
                failure.code.value in _STRICT_CALLBACK_EVENT_FAILURE_VALUES
                or (
                    failure.code.value == "profile_mismatch"
                    and self.identity_verified
                    and self.callback_generation <= 2
                )
            )
            if requires_callback_event:
                generation_offset = (
                    4
                    if failure.code.value in _PRIOR_OBSERVATION_FAILURE_VALUES
                    else (3 if failure.code.value in _PRIOR_CAPS_FAILURE_VALUES else 2)
                )
                earliest_callback_failure_generation = _checked_int64_add(
                    failure.epoch,
                    generation_offset,
                    "snapshot callback failure chronology",
                )
                if failure.first_generation < earliest_callback_failure_generation:
                    raise ValueError(
                        "snapshot callback failure predates a reachable callback event"
                    )
        if self.observation is None:
            if (
                self.baseline_duration_ns != 0
                or self.continuous_observations != 0
                or self.maximum_observed_gap_ns != 0
                or self.prewarm_completed_monotonic_ns is not None
            ):
                raise ValueError("snapshot without observation cannot retain evidence counters")
            observation = None
        else:
            if not self.identity_verified or self.continuous_observations < 1:
                raise ValueError("snapshot observation requires verified continuous evidence")
            if self.continuous_observations == 1 and (
                self.baseline_duration_ns != 0 or self.maximum_observed_gap_ns != 0
            ):
                raise ValueError("first observation cannot claim an elapsed baseline or gap")
            if self.continuous_observations > 1 and (
                self.baseline_duration_ns == 0 or self.maximum_observed_gap_ns == 0
            ):
                raise ValueError("multiple observations require an elapsed baseline and gap")
            observation = _clone_observation(self.observation)
            if any(
                terminal_counter < self.continuous_observations
                for terminal_counter in (
                    observation.parser_bytes,
                    observation.decoded_frames,
                    observation.source_ntp_ns,
                    observation.source_timestamp_ns,
                )
            ):
                raise ValueError(
                    "snapshot terminal counters cannot reach its continuous observation count"
                )
            if self.continuous_observations > 1:
                observation_steps = self.continuous_observations - 1
                minimum_reachable_baseline_ns = _checked_int64_multiply(
                    1,
                    observation_steps,
                    "snapshot baseline arithmetic",
                )
                maximum_reachable_baseline_ns = _checked_int64_multiply(
                    self.maximum_observed_gap_ns,
                    observation_steps,
                    "snapshot baseline arithmetic",
                )
                if not (
                    minimum_reachable_baseline_ns
                    <= self.baseline_duration_ns
                    <= maximum_reachable_baseline_ns
                ):
                    raise ValueError(
                        "snapshot baseline is not reachable from its observation count and gap"
                    )
            if any(
                terminal_clock < self.baseline_duration_ns
                for terminal_clock in (
                    observation.observed_monotonic_ns,
                    observation.source_ntp_ns,
                    observation.source_timestamp_ns,
                )
            ):
                raise ValueError("snapshot terminal clocks cannot precede its retained baseline")
            prewarm_complete = self.baseline_duration_ns >= _PREWARM_NS
            if prewarm_complete != (self.prewarm_completed_monotonic_ns is not None):
                raise ValueError(
                    "snapshot prewarm completion must exactly match retained baseline evidence"
                )
            if (
                self.prewarm_completed_monotonic_ns is not None
                and self.prewarm_completed_monotonic_ns > observation.observed_monotonic_ns
            ):
                raise ValueError("snapshot prewarm completion exceeds its current observation")
            if self.prewarm_completed_monotonic_ns is not None:
                if (
                    self.baseline_duration_ns == _PREWARM_NS
                    and self.prewarm_completed_monotonic_ns != observation.observed_monotonic_ns
                ):
                    raise ValueError("snapshot exact-threshold prewarm completion must be current")
                maximum_post_completion_elapsed_ns = _checked_int64_multiply(
                    self.maximum_observed_gap_ns,
                    self.continuous_observations - 2,
                    "snapshot prewarm completion observation span",
                )
                if (
                    observation.observed_monotonic_ns - self.prewarm_completed_monotonic_ns
                    > maximum_post_completion_elapsed_ns
                ):
                    raise ValueError("snapshot prewarm completion predates reachable observations")
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "failures", failures)

    def to_dict(self) -> dict[str, object]:
        return {
            "camera_id": self.camera_id,
            "source_index": self.source_index,
            "bound": self.bound,
            "identity_verified": self.identity_verified,
            "callback_generation": self.callback_generation,
            "observation": None if self.observation is None else self.observation.to_dict(),
            "baseline_duration_ns": self.baseline_duration_ns,
            "continuous_observations": self.continuous_observations,
            "maximum_observed_gap_ns": self.maximum_observed_gap_ns,
            "continuity_gap_bound_ns": self.continuity_gap_bound_ns,
            "stale_after_ns": self.stale_after_ns,
            "prewarm_completed_monotonic_ns": self.prewarm_completed_monotonic_ns,
            "failures": [failure.to_dict() for failure in self.failures],
        }


@dataclass(frozen=True, slots=True)
class NativeSourceProfileSnapshot:
    epoch: int
    generation: int
    epoch_started_generation: int
    ready: bool
    epoch_started_monotonic_ns: int
    ready_at_monotonic_ns: int | None
    sources: tuple[NativeSourceStateSnapshot, ...]
    failures: tuple[SourceProfileFailure, ...]

    def __post_init__(self) -> None:
        _validate_int(self.epoch, "snapshot epoch", minimum=1)
        _validate_int(self.generation, "snapshot generation", minimum=1)
        _validate_int(
            self.epoch_started_generation,
            "snapshot epoch start generation",
            minimum=1,
        )
        if not self.epoch <= self.epoch_started_generation <= self.generation:
            raise ValueError("snapshot epoch start generation must fall within epoch history")
        _validate_int(
            self.epoch_started_monotonic_ns,
            "snapshot epoch start",
        )
        if self.ready_at_monotonic_ns is not None:
            _validate_int(
                self.ready_at_monotonic_ns,
                "snapshot ready time",
            )
        if type(self.ready) is not bool:
            raise ValueError("snapshot ready must be bool")
        if self.ready != (self.ready_at_monotonic_ns is not None):
            raise ValueError("snapshot ready flag and ready time must agree")
        if (
            self.ready_at_monotonic_ns is not None
            and self.ready_at_monotonic_ns < self.epoch_started_monotonic_ns
        ):
            raise ValueError("snapshot ready time predates its epoch")
        if type(self.sources) is not tuple:
            raise ValueError("snapshot sources must be a tuple")
        if len(self.sources) != _CAMERA_COUNT:
            raise ValueError("snapshot requires exactly 20 sources")
        if any(type(source) is not NativeSourceStateSnapshot for source in self.sources):
            raise ValueError("snapshot sources must contain source state records")
        sources = tuple(_clone_source_snapshot(source) for source in self.sources)
        if tuple(source.source_index for source in sources) != tuple(range(_CAMERA_COUNT)):
            raise ValueError("snapshot sources must be in canonical source-index order")
        camera_ids = tuple(source.camera_id for source in sources)
        if len(set(camera_ids)) != _CAMERA_COUNT:
            raise ValueError("snapshot source camera IDs must be unique")
        if type(self.failures) is not tuple:
            raise ValueError("snapshot failures must be a tuple")
        if len(self.failures) > _MAX_PROFILE_FAILURES:
            raise ValueError("snapshot failures exceed the bounded failure vocabulary")
        if any(type(failure) is not SourceProfileFailure for failure in self.failures):
            raise ValueError("snapshot failures must contain failure records")
        failures = tuple(_clone_failure(failure) for failure in self.failures)
        source_failures = tuple(failure for source in sources for failure in source.failures)
        if failures != source_failures:
            raise ValueError("snapshot failures must match ordered source failures")
        if any(
            failure.epoch != self.epoch
            or not (self.epoch_started_generation < failure.first_generation <= self.generation)
            for failure in failures
        ):
            raise ValueError("snapshot failure epoch/generation is inconsistent")
        for source in sources:
            for failure in source.failures:
                requires_callback_event = (
                    failure.code.value in _STRICT_CALLBACK_EVENT_FAILURE_VALUES
                    or (
                        failure.code.value == "profile_mismatch"
                        and source.identity_verified
                        and source.callback_generation <= 2
                    )
                )
                if not requires_callback_event:
                    continue
                generation_offset = (
                    4
                    if failure.code.value in _PRIOR_OBSERVATION_FAILURE_VALUES
                    else (3 if failure.code.value in _PRIOR_CAPS_FAILURE_VALUES else 2)
                )
                earliest_callback_failure_generation = _checked_int64_add(
                    self.epoch_started_generation,
                    generation_offset,
                    "snapshot callback failure chronology",
                )
                if failure.first_generation < earliest_callback_failure_generation:
                    raise ValueError("snapshot callback failure predates its epoch provenance")
        minimum_generation = self.epoch_started_generation
        for source in sources:
            minimum_generation = _checked_int64_add(
                minimum_generation,
                source.callback_generation,
                "snapshot generation history",
            )
            if source.observation is not None:
                minimum_generation = _checked_int64_add(
                    minimum_generation,
                    1,
                    "snapshot generation history",
                )
                minimum_generation = _checked_int64_add(
                    minimum_generation,
                    source.continuous_observations,
                    "snapshot generation history",
                )
        provable_failure_generations = {
            failure.first_generation
            for source in sources
            for failure in source.failures
            if failure.code.value != "bounded_buffer_overflow"
            and (
                failure.code.value != "profile_mismatch"
                or (source.identity_verified and source.callback_generation <= 2)
            )
        }
        minimum_generation = _checked_int64_add(
            minimum_generation,
            len(provable_failure_generations),
            "snapshot generation history",
        )
        if self.generation < minimum_generation:
            raise ValueError("snapshot generation is below its reachable history")
        bound_source_count = sum(source.bound for source in sources)
        if self.generation > _INT64_MAX - bound_source_count:
            raise ValueError("snapshot generation cannot guarantee every bound callback close")
        for source in sources:
            if source.observation is None:
                continue
            earliest_reachable_terminal_ns = _checked_int64_add(
                self.epoch_started_monotonic_ns,
                source.baseline_duration_ns,
                "snapshot source timeline",
            )
            if source.observation.observed_monotonic_ns < earliest_reachable_terminal_ns:
                raise ValueError("snapshot source timeline predates its epoch and baseline")
            if source.prewarm_completed_monotonic_ns is not None:
                earliest_prewarm_completion_ns = _checked_int64_add(
                    self.epoch_started_monotonic_ns,
                    _PREWARM_NS,
                    "snapshot prewarm completion timeline",
                )
                if source.prewarm_completed_monotonic_ns < earliest_prewarm_completion_ns:
                    raise ValueError(
                        "snapshot source prewarm completion predates its epoch baseline"
                    )
        complete = not failures and all(
            source.bound
            and source.identity_verified
            and source.observation is not None
            and source.baseline_duration_ns >= _PREWARM_NS
            and source.prewarm_completed_monotonic_ns is not None
            and source.continuous_observations >= 2
            and source.maximum_observed_gap_ns <= source.continuity_gap_bound_ns
            and not source.failures
            for source in sources
        )
        if self.ready != complete:
            raise ValueError("snapshot ready state must exactly match complete source evidence")
        if self.ready:
            assert self.ready_at_monotonic_ns is not None
            earliest_ready_ns = _checked_int64_add(
                self.epoch_started_monotonic_ns,
                _PREWARM_NS,
                "snapshot 60-second readiness timeline",
            )
            if self.ready_at_monotonic_ns < earliest_ready_ns:
                raise ValueError("snapshot ready time precedes its 60-second prewarm")
            first_all_source_completion_ns = max(
                source.prewarm_completed_monotonic_ns
                for source in sources
                if source.prewarm_completed_monotonic_ns is not None
            )
            if self.ready_at_monotonic_ns != first_all_source_completion_ns:
                raise ValueError(
                    "snapshot ready time must equal first all-source prewarm completion"
                )
            maximum_observed_monotonic_ns = max(
                source.observation.observed_monotonic_ns
                for source in sources
                if source.observation is not None
            )
            if self.ready_at_monotonic_ns > maximum_observed_monotonic_ns:
                raise ValueError("snapshot ready time exceeds its current source observations")
            if any(
                maximum_observed_monotonic_ns - source.observation.observed_monotonic_ns
                > source.stale_after_ns
                for source in sources
                if source.observation is not None
            ):
                raise ValueError("snapshot ready sources exceed a signed stale source bound")
        object.__setattr__(self, "sources", sources)
        object.__setattr__(self, "failures", failures)

    def to_dict(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "generation": self.generation,
            "epoch_started_generation": self.epoch_started_generation,
            "ready": self.ready,
            "epoch_started_monotonic_ns": self.epoch_started_monotonic_ns,
            "ready_at_monotonic_ns": self.ready_at_monotonic_ns,
            "sources": [source.to_dict() for source in self.sources],
            "failures": [failure.to_dict() for failure in self.failures],
        }


def _clone_profile_snapshot(
    snapshot: NativeSourceProfileSnapshot,
) -> NativeSourceProfileSnapshot:
    if type(snapshot) is not NativeSourceProfileSnapshot:
        raise ValueError("proof snapshot must be an exact NativeSourceProfileSnapshot")
    return NativeSourceProfileSnapshot(
        epoch=snapshot.epoch,
        generation=snapshot.generation,
        epoch_started_generation=snapshot.epoch_started_generation,
        ready=snapshot.ready,
        epoch_started_monotonic_ns=snapshot.epoch_started_monotonic_ns,
        ready_at_monotonic_ns=snapshot.ready_at_monotonic_ns,
        sources=snapshot.sources,
        failures=snapshot.failures,
    )


def _clone_milestone_receipt(
    receipt: SourceProfileMilestoneReceiptV1,
) -> SourceProfileMilestoneReceiptV1:
    if type(receipt) is not SourceProfileMilestoneReceiptV1:
        raise ValueError("proof receipts must contain exact milestone records")
    return SourceProfileMilestoneReceiptV1(
        schema=receipt.schema,
        sequence=receipt.sequence,
        site_id=receipt.site_id,
        epoch=receipt.epoch,
        epoch_started_generation=receipt.epoch_started_generation,
        authenticator_key_id=receipt.authenticator_key_id,
        camera_id=receipt.camera_id,
        source_index=receipt.source_index,
        source_identity_commitment=receipt.source_identity_commitment,
        kind=receipt.kind,
        failure_code=receipt.failure_code,
        event_generation=receipt.event_generation,
        event_monotonic_ns=receipt.event_monotonic_ns,
        parser_bytes=receipt.parser_bytes,
        decoded_frames=receipt.decoded_frames,
        source_ntp_ns=receipt.source_ntp_ns,
        source_timestamp_ns=receipt.source_timestamp_ns,
        baseline_duration_ns=receipt.baseline_duration_ns,
        prior_head=receipt.prior_head,
        head=receipt.head,
        authentication_tag=receipt.authentication_tag,
    )


@dataclass(frozen=True, slots=True)
class NativeSourceProfileProofEnvelopeV1:
    schema: Literal["kuzet.native-source-profile-proof.v1"]
    site_id: str
    key_id: str
    public_key_sha256: str
    milestone_authenticator_key_id: str
    milestone_authentication_tag: str
    epoch: int
    epoch_started_generation: int
    generation: int
    source_identity_commitments: tuple[str, ...]
    snapshot_sha256: str
    snapshot: NativeSourceProfileSnapshot
    receipts: tuple[SourceProfileMilestoneReceiptV1, ...]
    final_head: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != _SOURCE_PROOF_SCHEMA:
            raise ValueError("source profile proof schema is invalid")
        _validate_identifier(self.site_id, "source profile proof site_id")
        _validate_identifier(self.key_id, "source profile proof key_id")
        _validate_digest(self.public_key_sha256, "source profile proof public key digest")
        _validate_identifier(
            self.milestone_authenticator_key_id,
            "source profile proof milestone authenticator key_id",
        )
        _validate_digest(
            self.milestone_authentication_tag,
            "source profile proof milestone authentication tag",
        )
        _validate_int(self.epoch, "source profile proof epoch", minimum=1)
        _validate_int(
            self.epoch_started_generation,
            "source profile proof epoch start generation",
            minimum=1,
        )
        _validate_int(self.generation, "source profile proof generation", minimum=1)
        if (
            type(self.source_identity_commitments) is not tuple
            or len(self.source_identity_commitments) != _CAMERA_COUNT
        ):
            raise ValueError("source profile proof requires 20 canonical source identities")
        for commitment in self.source_identity_commitments:
            _validate_digest(commitment, "source profile proof source identity")
        _validate_digest(self.snapshot_sha256, "source profile proof snapshot digest")
        _validate_digest(self.final_head, "source profile proof final milestone head")
        if (
            type(self.signature) is not str
            or len(self.signature) != 128
            or any(character not in "0123456789abcdef" for character in self.signature)
        ):
            raise ValueError("source profile proof signature must be canonical Ed25519 hex")
        snapshot = _clone_profile_snapshot(self.snapshot)
        if (
            self.epoch != snapshot.epoch
            or self.epoch_started_generation != snapshot.epoch_started_generation
            or self.generation != snapshot.generation
        ):
            raise ValueError("source profile proof chronology differs from its snapshot")
        expected_snapshot_sha256 = hashlib.sha256(_canonical_bytes(snapshot.to_dict())).hexdigest()
        if not hmac.compare_digest(self.snapshot_sha256, expected_snapshot_sha256):
            raise ValueError("source profile proof snapshot digest is invalid")
        if type(self.receipts) is not tuple or len(self.receipts) > _MAX_PROOF_MILESTONES:
            raise ValueError("source profile proof receipts are not a bounded tuple")
        receipts = tuple(_clone_milestone_receipt(receipt) for receipt in self.receipts)
        expected_prior_head = "0" * 64
        previous_generation = self.epoch_started_generation
        for sequence, receipt in enumerate(receipts, start=1):
            if receipt.sequence != sequence:
                raise ValueError("source profile proof receipt sequence is not canonical")
            if receipt.site_id != self.site_id or receipt.epoch != self.epoch:
                raise ValueError("source profile proof receipt belongs to another scope")
            if receipt.authenticator_key_id != self.milestone_authenticator_key_id:
                raise ValueError("source profile proof receipt authenticator is inconsistent")
            if receipt.epoch_started_generation != self.epoch_started_generation:
                raise ValueError("source profile proof receipt epoch start is inconsistent")
            if receipt.event_generation < previous_generation:
                raise ValueError("source profile proof receipt generation regressed")
            if receipt.event_generation > self.generation:
                raise ValueError("source profile proof receipt exceeds snapshot generation")
            if receipt.prior_head != expected_prior_head:
                raise ValueError("source profile proof receipt chain is broken")
            previous_generation = receipt.event_generation
            expected_prior_head = receipt.head
        if self.final_head != expected_prior_head:
            raise ValueError("source profile proof final milestone head is invalid")
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "receipts", receipts)

    def to_dict(self) -> dict[str, object]:
        payload = _proof_envelope_unsigned_dict(self)
        payload["signature"] = self.signature
        return payload


def _proof_envelope_unsigned_dict(
    envelope: NativeSourceProfileProofEnvelopeV1,
) -> dict[str, object]:
    return {
        "schema": envelope.schema,
        "site_id": envelope.site_id,
        "key_id": envelope.key_id,
        "public_key_sha256": envelope.public_key_sha256,
        "milestone_authenticator_key_id": envelope.milestone_authenticator_key_id,
        "milestone_authentication_tag": envelope.milestone_authentication_tag,
        "epoch": envelope.epoch,
        "epoch_started_generation": envelope.epoch_started_generation,
        "generation": envelope.generation,
        "source_identity_commitments": list(envelope.source_identity_commitments),
        "snapshot_sha256": envelope.snapshot_sha256,
        "snapshot": envelope.snapshot.to_dict(),
        "receipts": [receipt.to_dict() for receipt in envelope.receipts],
        "final_head": envelope.final_head,
    }


def _proof_signing_payload(envelope: NativeSourceProfileProofEnvelopeV1) -> bytes:
    return _SOURCE_PROOF_DOMAIN + _canonical_bytes(_proof_envelope_unsigned_dict(envelope))


def _validate_authoritative_milestone_bindings(
    envelope: NativeSourceProfileProofEnvelopeV1,
) -> None:
    snapshot = envelope.snapshot
    sources_by_camera = {source.camera_id: source for source in snapshot.sources}
    completion_receipts: dict[str, SourceProfileMilestoneReceiptV1] = {}
    failure_receipts: dict[
        tuple[str, str],
        SourceProfileMilestoneReceiptV1,
    ] = {}
    for receipt in envelope.receipts:
        source = sources_by_camera.get(receipt.camera_id)
        if (
            source is None
            or source.source_index != receipt.source_index
            or envelope.source_identity_commitments[receipt.source_index]
            != receipt.source_identity_commitment
        ):
            raise ValueError("source profile proof receipt identity is inconsistent")
        if receipt.kind == "prewarm_completed":
            if receipt.camera_id in completion_receipts:
                raise ValueError("source profile proof has duplicate prewarm receipts")
            completion_receipts[receipt.camera_id] = receipt
            if (
                source.prewarm_completed_monotonic_ns != receipt.event_monotonic_ns
                or source.observation is None
                or receipt.parser_bytes is None
                or receipt.decoded_frames is None
                or receipt.source_ntp_ns is None
                or receipt.source_timestamp_ns is None
                or receipt.baseline_duration_ns is None
                or receipt.parser_bytes > source.observation.parser_bytes
                or receipt.decoded_frames > source.observation.decoded_frames
                or receipt.source_ntp_ns > source.observation.source_ntp_ns
                or receipt.source_timestamp_ns > source.observation.source_timestamp_ns
                or receipt.baseline_duration_ns > source.baseline_duration_ns
            ):
                raise ValueError("source profile proof prewarm receipt differs from snapshot")
        else:
            assert receipt.failure_code is not None
            key = (receipt.camera_id, receipt.failure_code.value)
            if key in failure_receipts:
                raise ValueError("source profile proof has duplicate failure receipts")
            failure_receipts[key] = receipt

    expected_completions = {
        source.camera_id: source.prewarm_completed_monotonic_ns
        for source in snapshot.sources
        if source.prewarm_completed_monotonic_ns is not None
    }
    if set(completion_receipts) != set(expected_completions):
        raise ValueError("source profile proof prewarm receipts are incomplete")
    expected_failures = {
        (failure.camera_id, failure.code.value): failure for failure in snapshot.failures
    }
    if set(failure_receipts) != set(expected_failures):
        raise ValueError("source profile proof failure receipts are incomplete")
    for key, failure in expected_failures.items():
        receipt = failure_receipts[key]
        if receipt.event_generation != failure.first_generation or receipt.epoch != failure.epoch:
            raise ValueError("source profile proof failure receipt differs from snapshot")
    if snapshot.ready:
        if len(completion_receipts) != _CAMERA_COUNT:
            raise ValueError("ready source profile proof lacks 20 prewarm receipts")
        authoritative_ready_at = max(
            receipt.event_monotonic_ns for receipt in completion_receipts.values()
        )
        if snapshot.ready_at_monotonic_ns != authoritative_ready_at:
            raise ValueError("source profile proof ready time is not authoritative")


def _verify_milestone_authentication_from_material(
    envelope: NativeSourceProfileProofEnvelopeV1,
    material: _MilestoneKeyMaterial,
) -> None:
    authenticator_key = _take_milestone_authenticator_key(material)
    authentication_invalid = False
    verification_failed = False
    try:
        for receipt in envelope.receipts:
            expected_tag = hmac.digest(
                authenticator_key,
                _milestone_authentication_payload(receipt),
                "sha256",
            ).hex()
            if not hmac.compare_digest(receipt.authentication_tag, expected_tag):
                authentication_invalid = True
                break
        if not authentication_invalid:
            expected_terminal_tag = hmac.digest(
                authenticator_key,
                _milestone_terminal_payload(
                    site_id=envelope.site_id,
                    authenticator_key_id=(envelope.milestone_authenticator_key_id),
                    epoch=envelope.epoch,
                    epoch_started_generation=envelope.epoch_started_generation,
                    source_identity_commitments=(envelope.source_identity_commitments),
                    receipt_count=len(envelope.receipts),
                    final_head=envelope.final_head,
                ),
                "sha256",
            ).hex()
            if not hmac.compare_digest(
                envelope.milestone_authentication_tag,
                expected_terminal_tag,
            ):
                authentication_invalid = True
    except Exception:
        verification_failed = True
    finally:
        authenticator_key = b""
    if verification_failed:
        raise ValueError("source profile milestone authentication could not be verified") from None
    if authentication_invalid:
        raise ValueError("source profile milestone authentication is invalid")


def _verify_source_profile_proof_from_material(
    envelope: NativeSourceProfileProofEnvelopeV1,
    *,
    expected_key_id: str,
    trusted_public_key: bytes,
    expected_milestone_authenticator_key_id: str,
    milestone_key_material: _MilestoneKeyMaterial,
    expected_site_id: str,
    expected_source_identity_commitments: tuple[str, ...],
    expected_epoch: int,
    expected_epoch_started_generation: int,
) -> NativeSourceProfileSnapshot:
    if type(envelope) is not NativeSourceProfileProofEnvelopeV1:
        raise ValueError("source profile proof envelope type is invalid")
    _validate_identifier(expected_key_id, "expected source profile proof key_id")
    _validate_identifier(
        expected_milestone_authenticator_key_id,
        "expected source profile milestone authenticator key_id",
    )
    _validate_identifier(expected_site_id, "expected source profile proof site_id")
    _validate_int(expected_epoch, "expected source profile proof epoch", minimum=1)
    _validate_int(
        expected_epoch_started_generation,
        "expected source profile proof epoch start generation",
        minimum=1,
    )
    if (
        type(expected_source_identity_commitments) is not tuple
        or len(expected_source_identity_commitments) != _CAMERA_COUNT
    ):
        raise ValueError("expected source profile identities must be an exact 20-item tuple")
    for commitment in expected_source_identity_commitments:
        _validate_digest(commitment, "expected source profile identity")
    if type(trusted_public_key) is not bytes:
        raise ValueError("trusted source profile proof public key must be bytes")
    trusted_key = canonical_ed25519_public_key_pem(trusted_public_key)
    trusted_fingerprint = ed25519_public_key_spki_sha256(trusted_key)
    owned = NativeSourceProfileProofEnvelopeV1(
        schema=envelope.schema,
        site_id=envelope.site_id,
        key_id=envelope.key_id,
        public_key_sha256=envelope.public_key_sha256,
        milestone_authenticator_key_id=envelope.milestone_authenticator_key_id,
        milestone_authentication_tag=envelope.milestone_authentication_tag,
        epoch=envelope.epoch,
        epoch_started_generation=envelope.epoch_started_generation,
        generation=envelope.generation,
        source_identity_commitments=envelope.source_identity_commitments,
        snapshot_sha256=envelope.snapshot_sha256,
        snapshot=envelope.snapshot,
        receipts=envelope.receipts,
        final_head=envelope.final_head,
        signature=envelope.signature,
    )
    if owned.key_id != expected_key_id:
        milestone_key_material.clear()
        raise ValueError("source profile proof key_id is not trusted")
    if owned.milestone_authenticator_key_id != expected_milestone_authenticator_key_id:
        milestone_key_material.clear()
        raise ValueError("source profile proof milestone authenticator key_id is not trusted")
    if owned.site_id != expected_site_id:
        milestone_key_material.clear()
        raise ValueError("source profile proof site_id is not trusted")
    if owned.source_identity_commitments != expected_source_identity_commitments:
        milestone_key_material.clear()
        raise ValueError("source profile proof source identities are not trusted")
    if (
        owned.epoch != expected_epoch
        or owned.epoch_started_generation != expected_epoch_started_generation
    ):
        milestone_key_material.clear()
        raise ValueError("source profile proof epoch chronology is not trusted")
    if not hmac.compare_digest(owned.public_key_sha256, trusted_fingerprint):
        milestone_key_material.clear()
        raise ValueError("source profile proof public key fingerprint is not trusted")
    _verify_milestone_authentication_from_material(
        owned,
        milestone_key_material,
    )
    try:
        signature = bytes.fromhex(owned.signature)
    except ValueError:
        raise ValueError("source profile proof signature is invalid") from None
    verify_ed25519_payload(
        payload=_proof_signing_payload(owned),
        signature=signature,
        trusted_public_key=trusted_key,
        label="source profile proof",
    )
    _validate_authoritative_milestone_bindings(owned)
    return _clone_profile_snapshot(owned.snapshot)


def verify_source_profile_proof(
    envelope: NativeSourceProfileProofEnvelopeV1,
    *,
    expected_key_id: str,
    trusted_public_key: bytes,
    expected_milestone_authenticator_key_id: str,
    trusted_milestone_authenticator_key: bytes | bytearray,
    expected_site_id: str,
    expected_source_identity_commitments: tuple[str, ...],
    expected_epoch: int,
    expected_epoch_started_generation: int,
) -> NativeSourceProfileSnapshot:
    """Verify one proof envelope and return a detached authoritative snapshot."""

    milestone_key_material = _MilestoneKeyMaterial(trusted_milestone_authenticator_key)
    trusted_milestone_authenticator_key = b""
    try:
        return _verify_source_profile_proof_from_material(
            envelope,
            expected_key_id=expected_key_id,
            trusted_public_key=trusted_public_key,
            expected_milestone_authenticator_key_id=(expected_milestone_authenticator_key_id),
            milestone_key_material=milestone_key_material,
            expected_site_id=expected_site_id,
            expected_source_identity_commitments=(expected_source_identity_commitments),
            expected_epoch=expected_epoch,
            expected_epoch_started_generation=(expected_epoch_started_generation),
        )
    finally:
        milestone_key_material.clear()


@dataclass(frozen=True, slots=True)
class NativeSourceProfileDelta:
    epoch: int
    generation: int
    event: str
    camera_id: str | None
    ready: bool
    failures: tuple[SourceProfileFailureCode, ...]
    parser_bytes: int | None = None
    decoded_frames: int | None = None
    source_ntp_ns: int | None = None
    source_timestamp_ns: int | None = None

    def __post_init__(self) -> None:
        _validate_int(self.epoch, "delta epoch", minimum=1)
        _validate_int(self.generation, "delta generation", minimum=1)
        if self.epoch > self.generation:
            raise ValueError("delta epoch cannot exceed generation")
        if type(self.event) is not str or self.event not in _DELTA_EVENTS:
            raise ValueError("delta event is not part of the source-profile vocabulary")
        if type(self.ready) is not bool:
            raise ValueError("delta ready must be bool")
        if self.camera_id is not None:
            _validate_identifier(self.camera_id, "delta camera_id")
        if type(self.failures) is not tuple:
            raise ValueError("delta failures must be a tuple")
        if len(self.failures) > _MAX_SOURCE_FAILURES:
            raise ValueError("delta failures exceed the bounded failure vocabulary")
        if any(type(failure) is not SourceProfileFailureCode for failure in self.failures):
            raise ValueError("delta failures must contain failure codes")
        failures = tuple(_canonical_failure_code(failure.value) for failure in self.failures)
        failure_values = tuple(failure.value for failure in failures)
        if failure_values != tuple(sorted(set(failure_values))):
            raise ValueError("delta failures must be unique and ordered")
        for value, label in (
            (self.parser_bytes, "delta parser byte counter"),
            (self.decoded_frames, "delta decoded frame counter"),
            (self.source_ntp_ns, "delta source NTP counter"),
            (self.source_timestamp_ns, "delta source timestamp counter"),
        ):
            if value is not None:
                _validate_int(value, label, minimum=1)
        counters = (
            self.parser_bytes,
            self.decoded_frames,
            self.source_ntp_ns,
            self.source_timestamp_ns,
        )
        if self.event == "epoch_started":
            if (
                self.camera_id is not None
                or self.ready
                or self.failures
                or any(value is not None for value in counters)
            ):
                raise ValueError("epoch-start delta contains source evidence")
        elif self.camera_id is None:
            raise ValueError("source delta requires camera_id")
        if self.event == "observation":
            if any(value is None for value in counters):
                raise ValueError("observation delta requires complete counters")
        elif any(value is not None for value in counters):
            raise ValueError("non-observation delta cannot contain counters")
        if self.event == "failure" and (not self.failures or self.ready):
            raise ValueError("failure delta requires failures and cannot be ready")
        if self.event in {"source_bound", "callback_closed"} and self.ready:
            raise ValueError(f"{self.event} delta cannot be ready")
        if self.ready and self.failures:
            raise ValueError("ready delta cannot contain failures")
        object.__setattr__(self, "failures", failures)

    def to_dict(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "generation": self.generation,
            "event": self.event,
            "camera_id": self.camera_id,
            "ready": self.ready,
            "failures": [failure.value for failure in self.failures],
            "parser_bytes": self.parser_bytes,
            "decoded_frames": self.decoded_frames,
            "source_ntp_ns": self.source_ntp_ns,
            "source_timestamp_ns": self.source_timestamp_ns,
        }


def _clone_expectation(
    expectation: SourceProfileExpectation,
) -> SourceProfileExpectation:
    if type(expectation) is not SourceProfileExpectation:
        raise ValueError("expectations must contain exact SourceProfileExpectation records")
    return SourceProfileExpectation(
        camera_id=expectation.camera_id,
        source_index=expectation.source_index,
        source_identity_commitment=expectation.source_identity_commitment,
        codec=expectation.codec,
        width=expectation.width,
        height=expectation.height,
        fps_min=expectation.fps_min,
        fps_max=expectation.fps_max,
        bitrate_kbps_min=expectation.bitrate_kbps_min,
        bitrate_kbps_max=expectation.bitrate_kbps_max,
        max_timestamp_gap_ns=expectation.max_timestamp_gap_ns,
        max_timestamp_skew_ns=expectation.max_timestamp_skew_ns,
        stale_after_ns=expectation.stale_after_ns,
        signature=expectation.signature,
    )


def _clone_caps(caps: NativeSourceCaps) -> NativeSourceCaps:
    if type(caps) is not NativeSourceCaps:
        raise ValueError("native CAPS must be an exact NativeSourceCaps record")
    return NativeSourceCaps(
        codec=caps.codec,
        width=caps.width,
        height=caps.height,
        fps=caps.fps,
        bitrate_kbps=caps.bitrate_kbps,
    )


def _clone_observation(
    observation: NativeSourceObservation,
) -> NativeSourceObservation:
    if type(observation) is not NativeSourceObservation:
        raise ValueError("observation must be an exact NativeSourceObservation record")
    return NativeSourceObservation(
        caps=observation.caps,
        parser_bytes=observation.parser_bytes,
        decoded_frames=observation.decoded_frames,
        source_ntp_ns=observation.source_ntp_ns,
        source_timestamp_ns=observation.source_timestamp_ns,
        observed_monotonic_ns=observation.observed_monotonic_ns,
    )


def _clone_failure(failure: SourceProfileFailure) -> SourceProfileFailure:
    if type(failure) is not SourceProfileFailure:
        raise ValueError("failure must be an exact SourceProfileFailure record")
    return SourceProfileFailure(
        camera_id=failure.camera_id,
        code=failure.code,
        epoch=failure.epoch,
        first_generation=failure.first_generation,
    )


def _clone_source_snapshot(
    source: NativeSourceStateSnapshot,
) -> NativeSourceStateSnapshot:
    if type(source) is not NativeSourceStateSnapshot:
        raise ValueError("source must be an exact NativeSourceStateSnapshot record")
    return NativeSourceStateSnapshot(
        camera_id=source.camera_id,
        source_index=source.source_index,
        bound=source.bound,
        identity_verified=source.identity_verified,
        callback_generation=source.callback_generation,
        observation=source.observation,
        baseline_duration_ns=source.baseline_duration_ns,
        continuous_observations=source.continuous_observations,
        maximum_observed_gap_ns=source.maximum_observed_gap_ns,
        continuity_gap_bound_ns=source.continuity_gap_bound_ns,
        stale_after_ns=source.stale_after_ns,
        prewarm_completed_monotonic_ns=source.prewarm_completed_monotonic_ns,
        failures=source.failures,
    )


def _clone_delta(delta: NativeSourceProfileDelta) -> NativeSourceProfileDelta:
    if type(delta) is not NativeSourceProfileDelta:
        raise ValueError("delta must be an exact NativeSourceProfileDelta record")
    return NativeSourceProfileDelta(
        epoch=delta.epoch,
        generation=delta.generation,
        event=delta.event,
        camera_id=delta.camera_id,
        ready=delta.ready,
        failures=delta.failures,
        parser_bytes=delta.parser_bytes,
        decoded_frames=delta.decoded_frames,
        source_ntp_ns=delta.source_ntp_ns,
        source_timestamp_ns=delta.source_timestamp_ns,
    )


@dataclass(slots=True)
class _SourceState:
    expectation: SourceProfileExpectation
    bound: bool = False
    identity_verified: bool = False
    callback_generation: int = 0
    callback_handle_ref: weakref.ReferenceType[NativeSourceCallbacks] | None = None
    callback_close_token: object | None = None
    monotonic_high_water_ns: int | None = None
    bound_monotonic_ns: int | None = None
    caps: NativeSourceCaps | None = None
    caps_monotonic_ns: int | None = None
    pending_parser: tuple[int, int, int] | None = None
    last_parser_bytes: int | None = None
    last_source_timestamp_ns: int | None = None
    observation: NativeSourceObservation | None = None
    baseline_monotonic_ns: int | None = None
    baseline_source_ntp_ns: int | None = None
    baseline_source_timestamp_ns: int | None = None
    baseline_duration_ns: int = 0
    continuous_observations: int = 0
    maximum_observed_gap_ns: int = 0
    prewarm_completed_monotonic_ns: int | None = None
    failures: dict[SourceProfileFailureCode, SourceProfileFailure] | None = None

    def __post_init__(self) -> None:
        self.failures = {}


def _clone_internal_source_state(state: _SourceState) -> _SourceState:
    cloned = _SourceState(expectation=state.expectation)
    cloned.bound = state.bound
    cloned.identity_verified = state.identity_verified
    cloned.callback_generation = state.callback_generation
    cloned.callback_handle_ref = state.callback_handle_ref
    cloned.callback_close_token = state.callback_close_token
    cloned.monotonic_high_water_ns = state.monotonic_high_water_ns
    cloned.bound_monotonic_ns = state.bound_monotonic_ns
    cloned.caps = state.caps
    cloned.caps_monotonic_ns = state.caps_monotonic_ns
    cloned.pending_parser = state.pending_parser
    cloned.last_parser_bytes = state.last_parser_bytes
    cloned.last_source_timestamp_ns = state.last_source_timestamp_ns
    cloned.observation = state.observation
    cloned.baseline_monotonic_ns = state.baseline_monotonic_ns
    cloned.baseline_source_ntp_ns = state.baseline_source_ntp_ns
    cloned.baseline_source_timestamp_ns = state.baseline_source_timestamp_ns
    cloned.baseline_duration_ns = state.baseline_duration_ns
    cloned.continuous_observations = state.continuous_observations
    cloned.maximum_observed_gap_ns = state.maximum_observed_gap_ns
    cloned.prewarm_completed_monotonic_ns = state.prewarm_completed_monotonic_ns
    cloned.failures = dict(state.failures or {})
    return cloned


@dataclass(slots=True)
class _IngestionSavepoint:
    generation: int
    ready_at_monotonic_ns: int | None
    monotonic_high_water_ns: int
    stale_check_high_water_ns: int
    close_reservations: int
    states: dict[str, _SourceState]
    milestone_count: int
    milestone_authentication_tag: str
    removed_deltas: list[NativeSourceProfileDelta]


def _atomic_ingestion(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            with self._ingestion_transaction():
                return method(self, *args, **kwargs)

    return wrapped


class NativeSourceCallbacks:
    """Generation-owned capability passed only to native graph callbacks."""

    __slots__ = (
        "__weakref__",
        "_callback_generation",
        "_epoch",
        "_tracker_ref",
        "camera_id",
    )

    def __init__(
        self,
        tracker: NativeSourceProfileTracker,
        *,
        camera_id: str,
        epoch: int,
        callback_generation: int,
        _issuer: object | None = None,
        _close_token: object | None = None,
    ) -> None:
        if _issuer is not _CALLBACK_ISSUER or _close_token is None:
            raise TypeError("source callback handles are issued only by the tracker")
        tracker_reference = weakref.ref(tracker)
        object.__setattr__(self, "_tracker_ref", tracker_reference)
        object.__setattr__(self, "camera_id", camera_id)
        object.__setattr__(self, "_epoch", epoch)
        object.__setattr__(self, "_callback_generation", callback_generation)
        weakref.finalize(
            self,
            _finalize_source_callback,
            tracker_reference,
            _close_token,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("source callback handles are immutable")

    def __repr__(self) -> str:
        return (
            "NativeSourceCallbacks("
            f"camera_id={self.camera_id!r}, epoch={self._epoch}, "
            f"callback_generation={self._callback_generation})"
        )

    def on_rtp_caps(
        self,
        caps: NativeSourceCaps,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        tracker = self._tracker_ref()
        return (
            False
            if tracker is None
            else tracker._on_rtp_caps(  # noqa: SLF001
                self,
                caps,
                observed_monotonic_ns,
            )
        )

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        tracker = self._tracker_ref()
        return (
            False
            if tracker is None
            else tracker._on_parser_counter(  # noqa: SLF001
                self,
                parser_bytes,
                source_timestamp_ns,
                observed_monotonic_ns,
            )
        )

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        tracker = self._tracker_ref()
        return (
            False
            if tracker is None
            else tracker._on_decoded_frame(  # noqa: SLF001
                self,
                decoded_frames,
                source_ntp_ns,
                observed_monotonic_ns,
            )
        )

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        tracker = self._tracker_ref()
        return (
            False
            if tracker is None
            else tracker._on_native_probe_failure(  # noqa: SLF001
                self,
                code,
                observed_monotonic_ns,
            )
        )

    def close(self) -> None:
        tracker = self._tracker_ref()
        if tracker is not None:
            tracker._close_live_callback(self)  # noqa: SLF001


def _finalize_source_callback(
    tracker_reference: weakref.ReferenceType[NativeSourceProfileTracker],
    close_token: object,
) -> None:
    tracker = tracker_reference()
    if tracker is not None:
        tracker._close_callback_lease(close_token)  # noqa: SLF001


class NativeSourceProfileTracker:
    """Locked, bounded native evidence tracker for one exact 20-source site."""

    def __init__(
        self,
        *,
        site_id: str,
        expectations: tuple[SourceProfileExpectation, ...] | list[SourceProfileExpectation],
        commitment_key: bytes | bytearray,
        milestone_authenticator_key_id: str,
        milestone_authenticator_key: bytes | bytearray,
        delta_capacity: int = 100_000,
        epoch_started_monotonic_ns: int = 0,
        proof_signer: SourceProfileProofSigner | None = None,
    ) -> None:
        secrets = _SecretMaterial("", commitment_key)
        commitment_key = b""
        milestone_key_material = _MilestoneKeyMaterial(milestone_authenticator_key)
        milestone_authenticator_key = b""
        owned_milestone_key = b""
        proof_key_id: str | None = None
        proof_public_key: bytes | None = None
        proof_public_key_sha256: str | None = None
        try:
            _validate_identifier(site_id, "site_id")
            _validate_identifier(
                milestone_authenticator_key_id,
                "source profile milestone authenticator key_id",
            )
            owned_milestone_key = _take_milestone_authenticator_key(milestone_key_material)
            _validate_int(
                delta_capacity,
                "delta capacity",
                minimum=1,
                maximum=_MAX_DELTA_CAPACITY,
            )
            _validate_int(epoch_started_monotonic_ns, "epoch start")
            if type(expectations) not in (tuple, list):
                raise ValueError(
                    "source profile expectations require an exact built-in tuple or list"
                )
            if len(expectations) != _CAMERA_COUNT:
                raise ValueError("source profile tracker requires exactly 20 expectations")
            owned_expectations = tuple(
                _clone_expectation(expectation) for expectation in expectations
            )
            camera_ids = tuple(expectation.camera_id for expectation in owned_expectations)
            if len(set(camera_ids)) != _CAMERA_COUNT:
                raise ValueError("source profile camera IDs must be unique")
            if tuple(expectation.source_index for expectation in owned_expectations) != tuple(
                range(_CAMERA_COUNT)
            ):
                raise ValueError("source profile source indices must be ordered from 0 through 19")
            _verify_expectation_signatures_from_secrets(
                site_id=site_id,
                expectations=owned_expectations,
                secrets=secrets,
                milestone_authenticator_key=owned_milestone_key,
            )
            if proof_signer is not None:
                proof_key_id = proof_signer.key_id
                _validate_identifier(proof_key_id, "source profile proof key_id")
                if type(proof_signer.public_key) is not bytes:
                    raise ValueError("source profile proof signer public key must be bytes")
                proof_public_key = canonical_ed25519_public_key_pem(proof_signer.public_key)
                proof_public_key_sha256 = ed25519_public_key_spki_sha256(proof_public_key)
                if not callable(proof_signer.sign):
                    raise ValueError("source profile proof signer must provide sign")
        except Exception:
            secrets.clear()
            milestone_key_material.clear()
            owned_milestone_key = b""
            raise

        self._lock = RLock()
        self._site_id = site_id
        self._expectations = owned_expectations
        self._delta_capacity = delta_capacity
        self._deltas: deque[NativeSourceProfileDelta] = deque()
        self._proof_signer = proof_signer
        self._proof_key_id = proof_key_id
        self._proof_public_key = proof_public_key
        self._proof_public_key_sha256 = proof_public_key_sha256
        self._milestone_authenticator_key_id = milestone_authenticator_key_id
        self._milestone_authenticator = _MilestoneAuthenticator(owned_milestone_key)
        owned_milestone_key = b""
        self._milestone_receipts: list[SourceProfileMilestoneReceiptV1] = []
        self._milestone_authentication_tag = "0" * 64
        self._ingestion_savepoint: _IngestionSavepoint | None = None
        self._close_reservations = 0
        self._epoch = 1
        self._generation = 0
        self._epoch_started_generation = 0
        self._epoch_started_monotonic_ns = epoch_started_monotonic_ns
        self._monotonic_high_water_ns = epoch_started_monotonic_ns
        self._stale_check_high_water_ns = epoch_started_monotonic_ns
        self._ready_at_monotonic_ns: int | None = None
        self._states = {
            expectation.camera_id: _SourceState(expectation=expectation)
            for expectation in owned_expectations
        }
        self._append_event("epoch_started", None)
        self._epoch_started_generation = self._generation
        self._milestone_authentication_tag = self._compute_terminal_authentication_tag(
            receipt_count=0,
            final_head="0" * 64,
            epoch=self._epoch,
            epoch_started_generation=self._epoch_started_generation,
        )

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @contextmanager
    def _ingestion_transaction(self):
        active = self._ingestion_savepoint
        if active is not None:
            yield
            return
        savepoint = _IngestionSavepoint(
            generation=self._generation,
            ready_at_monotonic_ns=self._ready_at_monotonic_ns,
            monotonic_high_water_ns=self._monotonic_high_water_ns,
            stale_check_high_water_ns=self._stale_check_high_water_ns,
            close_reservations=self._close_reservations,
            states={
                camera_id: _clone_internal_source_state(state)
                for camera_id, state in self._states.items()
            },
            milestone_count=len(self._milestone_receipts),
            milestone_authentication_tag=self._milestone_authentication_tag,
            removed_deltas=[],
        )
        self._ingestion_savepoint = savepoint
        try:
            yield
        except BaseException:
            while self._deltas and self._deltas[-1].generation > savepoint.generation:
                self._deltas.pop()
            for delta in reversed(savepoint.removed_deltas):
                self._deltas.appendleft(delta)
            self._generation = savepoint.generation
            self._ready_at_monotonic_ns = savepoint.ready_at_monotonic_ns
            self._monotonic_high_water_ns = savepoint.monotonic_high_water_ns
            self._stale_check_high_water_ns = savepoint.stale_check_high_water_ns
            self._close_reservations = savepoint.close_reservations
            self._states = savepoint.states
            del self._milestone_receipts[savepoint.milestone_count :]
            self._milestone_authentication_tag = savepoint.milestone_authentication_tag
            raise
        finally:
            self._ingestion_savepoint = None

    def _popleft_delta(self) -> NativeSourceProfileDelta:
        delta = self._deltas.popleft()
        savepoint = self._ingestion_savepoint
        if savepoint is not None and delta.generation <= savepoint.generation:
            savepoint.removed_deltas.append(delta)
        return delta

    def _require_event_capacity(
        self,
        event_count: int = 1,
        *,
        close_reservation_delta: int = 0,
    ) -> None:
        _validate_int(event_count, "event reservation count")
        if type(close_reservation_delta) is not int:
            raise ValueError("close reservation delta must be an integer")
        projected_close_reservations = self._close_reservations + close_reservation_delta
        if not 0 <= projected_close_reservations <= _CAMERA_COUNT:
            raise ValueError("close reservation count is outside its allowed bounds")
        if event_count + projected_close_reservations > _INT64_MAX - self._generation:
            raise OverflowError("tracker generation exhausted its signed 64-bit range")

    def _state_for(self, camera_id: str) -> _SourceState:
        try:
            return self._states[camera_id]
        except KeyError as exc:
            raise ValueError("camera_id is not part of the signed source profile") from exc

    def _owned_state(
        self,
        callback: NativeSourceCallbacks,
        *,
        require_verified_identity: bool = True,
    ) -> _SourceState | None:
        for state in self._states.values():
            if (
                state.bound
                and state.callback_handle_ref is not None
                and state.callback_handle_ref() is callback
                and (not require_verified_identity or state.identity_verified)
            ):
                return state
        return None

    def _add_failures(
        self,
        state: _SourceState,
        codes: set[SourceProfileFailureCode],
        *,
        generation: int,
    ) -> tuple[SourceProfileFailure, ...]:
        assert state.failures is not None
        added: list[SourceProfileFailure] = []
        for code in sorted(codes, key=lambda failure_code: failure_code.value):
            if code not in state.failures:
                failure = SourceProfileFailure(
                    camera_id=state.expectation.camera_id,
                    code=code,
                    epoch=self._epoch,
                    first_generation=generation,
                )
                state.failures[code] = failure
                added.append(failure)
        if codes:
            self._ready_at_monotonic_ns = None
        return tuple(added)

    def _compute_terminal_authentication_tag(
        self,
        *,
        receipt_count: int,
        final_head: str,
        epoch: int,
        epoch_started_generation: int,
    ) -> str:
        return self._milestone_authenticator.digest_hex(
            _milestone_terminal_payload(
                site_id=self._site_id,
                authenticator_key_id=self._milestone_authenticator_key_id,
                epoch=epoch,
                epoch_started_generation=epoch_started_generation,
                source_identity_commitments=tuple(
                    expectation.source_identity_commitment for expectation in self._expectations
                ),
                receipt_count=receipt_count,
                final_head=final_head,
            )
        )

    def _prepare_milestones(
        self,
        milestones: tuple[_SourceProfileMilestone, ...],
    ) -> _PreparedMilestoneBatch:
        expected_count = len(self._milestone_receipts)
        if expected_count + len(milestones) > _MAX_PROOF_MILESTONES:
            raise RuntimeError("source profile milestone bound was exhausted")
        expected_prior_head = (
            "0" * 64 if not self._milestone_receipts else self._milestone_receipts[-1].head
        )
        seen = {
            (
                receipt.camera_id,
                receipt.kind,
                None if receipt.failure_code is None else receipt.failure_code.value,
            )
            for receipt in self._milestone_receipts
        }
        receipts: list[SourceProfileMilestoneReceiptV1] = []
        prior_head = expected_prior_head
        for offset, milestone in enumerate(milestones, start=1):
            duplicate_key = (
                milestone.camera_id,
                milestone.kind,
                None if milestone.failure_code is None else milestone.failure_code.value,
            )
            if duplicate_key in seen:
                raise RuntimeError("source profile milestone was already recorded")
            seen.add(duplicate_key)
            sequence = expected_count + offset
            unsigned = {
                "schema": _SOURCE_MILESTONE_SCHEMA,
                "sequence": sequence,
                "site_id": self._site_id,
                "epoch": self._epoch,
                "epoch_started_generation": (self._epoch_started_generation),
                "authenticator_key_id": self._milestone_authenticator_key_id,
                "camera_id": milestone.camera_id,
                "source_index": milestone.source_index,
                "source_identity_commitment": (milestone.source_identity_commitment),
                "kind": milestone.kind,
                "failure_code": (
                    None if milestone.failure_code is None else milestone.failure_code.value
                ),
                "event_generation": milestone.event_generation,
                "event_monotonic_ns": milestone.event_monotonic_ns,
                "parser_bytes": milestone.parser_bytes,
                "decoded_frames": milestone.decoded_frames,
                "source_ntp_ns": milestone.source_ntp_ns,
                "source_timestamp_ns": milestone.source_timestamp_ns,
                "baseline_duration_ns": milestone.baseline_duration_ns,
                "prior_head": prior_head,
            }
            head = hashlib.sha256(
                _SOURCE_MILESTONE_HEAD_DOMAIN + _canonical_bytes(unsigned)
            ).hexdigest()
            authenticated = dict(unsigned)
            authenticated["head"] = head
            authentication_tag = self._milestone_authenticator.digest_hex(
                _SOURCE_MILESTONE_AUTH_DOMAIN + _canonical_bytes(authenticated)
            )
            receipt = SourceProfileMilestoneReceiptV1(
                schema=_SOURCE_MILESTONE_SCHEMA,
                sequence=sequence,
                site_id=self._site_id,
                epoch=self._epoch,
                epoch_started_generation=self._epoch_started_generation,
                authenticator_key_id=self._milestone_authenticator_key_id,
                camera_id=milestone.camera_id,
                source_index=milestone.source_index,
                source_identity_commitment=(milestone.source_identity_commitment),
                kind=milestone.kind,
                failure_code=milestone.failure_code,
                event_generation=milestone.event_generation,
                event_monotonic_ns=milestone.event_monotonic_ns,
                parser_bytes=milestone.parser_bytes,
                decoded_frames=milestone.decoded_frames,
                source_ntp_ns=milestone.source_ntp_ns,
                source_timestamp_ns=milestone.source_timestamp_ns,
                baseline_duration_ns=milestone.baseline_duration_ns,
                prior_head=prior_head,
                head=head,
                authentication_tag=authentication_tag,
            )
            receipts.append(receipt)
            prior_head = head
        terminal_tag = self._compute_terminal_authentication_tag(
            receipt_count=expected_count + len(receipts),
            final_head=prior_head,
            epoch=self._epoch,
            epoch_started_generation=self._epoch_started_generation,
        )
        return _PreparedMilestoneBatch(
            expected_count=expected_count,
            expected_prior_head=expected_prior_head,
            receipts=tuple(receipts),
            terminal_authentication_tag=terminal_tag,
        )

    def _commit_milestones(
        self,
        prepared: _PreparedMilestoneBatch,
    ) -> None:
        current_prior_head = (
            "0" * 64 if not self._milestone_receipts else self._milestone_receipts[-1].head
        )
        if (
            len(self._milestone_receipts) != prepared.expected_count
            or current_prior_head != prepared.expected_prior_head
        ):
            raise RuntimeError("source profile milestone chain changed before commit")
        self._milestone_receipts.extend(prepared.receipts)
        self._milestone_authentication_tag = prepared.terminal_authentication_tag

    def _record_failure_milestones(
        self,
        state: _SourceState,
        failures: tuple[SourceProfileFailure, ...],
        *,
        event_monotonic_ns: int,
    ) -> None:
        if not failures:
            return
        prepared = self._prepare_milestones(
            tuple(
                _SourceProfileMilestone(
                    camera_id=state.expectation.camera_id,
                    source_index=state.expectation.source_index,
                    source_identity_commitment=(state.expectation.source_identity_commitment),
                    kind="failure",
                    failure_code=failure.code,
                    event_generation=failure.first_generation,
                    event_monotonic_ns=event_monotonic_ns,
                )
                for failure in failures
            )
        )
        self._commit_milestones(prepared)

    def _record_prewarm_milestone(
        self,
        state: _SourceState,
        observation: NativeSourceObservation,
        *,
        event_generation: int,
    ) -> None:
        prepared = self._prepare_milestones(
            (
                _SourceProfileMilestone(
                    camera_id=state.expectation.camera_id,
                    source_index=state.expectation.source_index,
                    source_identity_commitment=(state.expectation.source_identity_commitment),
                    kind="prewarm_completed",
                    failure_code=None,
                    event_generation=event_generation,
                    event_monotonic_ns=observation.observed_monotonic_ns,
                    parser_bytes=observation.parser_bytes,
                    decoded_frames=observation.decoded_frames,
                    source_ntp_ns=observation.source_ntp_ns,
                    source_timestamp_ns=observation.source_timestamp_ns,
                    baseline_duration_ns=state.baseline_duration_ns,
                ),
            )
        )
        self._commit_milestones(prepared)

    def _append_event(
        self,
        event: str,
        state: _SourceState | None,
        observation: NativeSourceObservation | None = None,
        *,
        event_monotonic_ns: int | None = None,
    ) -> int:
        self._require_event_capacity()
        self._generation = _increment_int64(self._generation, "tracker generation")
        overflow_failures: tuple[SourceProfileFailure, ...] = ()
        if len(self._deltas) >= self._delta_capacity:
            self._popleft_delta()
            if state is not None:
                overflow_failures = self._add_failures(
                    state,
                    {_canonical_failure_code("bounded_buffer_overflow")},
                    generation=self._generation,
                )
        failures = (
            ()
            if state is None or state.failures is None
            else tuple(sorted(state.failures, key=lambda code: code.value))
        )
        self._deltas.append(
            NativeSourceProfileDelta(
                epoch=self._epoch,
                generation=self._generation,
                event=event,
                camera_id=None if state is None else state.expectation.camera_id,
                ready=self._ready_at_monotonic_ns is not None,
                failures=failures,
                parser_bytes=None if observation is None else observation.parser_bytes,
                decoded_frames=None if observation is None else observation.decoded_frames,
                source_ntp_ns=None if observation is None else observation.source_ntp_ns,
                source_timestamp_ns=(
                    None if observation is None else observation.source_timestamp_ns
                ),
            )
        )
        if state is not None and overflow_failures:
            milestone_time = (
                self._monotonic_high_water_ns if event_monotonic_ns is None else event_monotonic_ns
            )
            self._record_failure_milestones(
                state,
                overflow_failures,
                event_monotonic_ns=milestone_time,
            )
        return self._generation

    def _fail(
        self,
        state: _SourceState,
        codes: set[SourceProfileFailureCode],
        *,
        event_monotonic_ns: int,
    ) -> bool:
        new_codes = (
            codes
            if state.failures is None
            else {code for code in codes if code not in state.failures}
        )
        if new_codes:
            self._require_event_capacity()
            added = self._add_failures(
                state,
                new_codes,
                generation=_increment_int64(
                    self._generation,
                    "tracker generation",
                ),
            )
            self._append_event(
                "failure",
                state,
                event_monotonic_ns=event_monotonic_ns,
            )
            self._record_failure_milestones(
                state,
                added,
                event_monotonic_ns=event_monotonic_ns,
            )
        return False

    def _validate_callback_time(
        self,
        state: _SourceState,
        observed_monotonic_ns: int,
    ) -> bool:
        previous = (
            self._epoch_started_monotonic_ns
            if state.monotonic_high_water_ns is None
            else state.monotonic_high_water_ns
        )
        if observed_monotonic_ns < previous:
            return self._fail(
                state,
                {_canonical_failure_code("host_monotonic_regression")},
                event_monotonic_ns=observed_monotonic_ns,
            )
        if observed_monotonic_ns - previous > state.expectation.stale_after_ns:
            return self._fail(
                state,
                {_canonical_failure_code("excessive_gap")},
                event_monotonic_ns=observed_monotonic_ns,
            )
        return True

    def _commit_callback_time(
        self,
        state: _SourceState,
        observed_monotonic_ns: int,
        *,
        following_event_count: int = 0,
        stale_now_monotonic_ns: int | None = None,
        pending_observation: NativeSourceObservation | None = None,
    ) -> None:
        stale_now = (
            observed_monotonic_ns if stale_now_monotonic_ns is None else stale_now_monotonic_ns
        )
        self._require_event_capacity(
            self._new_stale_failure_count(
                stale_now,
                pending_state=state if pending_observation is not None else None,
                pending_observation=pending_observation,
            )
            + following_event_count
        )
        state.monotonic_high_water_ns = observed_monotonic_ns
        self._monotonic_high_water_ns = max(
            self._monotonic_high_water_ns,
            observed_monotonic_ns,
        )
        self._mark_stale_sources(
            stale_now,
            pending_state=state if pending_observation is not None else None,
            pending_observation=pending_observation,
        )

    def bind_source(
        self,
        *,
        camera_id: str,
        resolved_url: str,
        commitment_key: bytes | bytearray,
        bound_monotonic_ns: int,
    ) -> NativeSourceCallbacks:
        """Bind one resolved source and return its generation-owned callback capability."""
        secrets = _SecretMaterial(resolved_url, commitment_key)
        resolved_url = ""
        commitment_key = b""
        try:
            return self._bind_source_from_secrets(
                camera_id=camera_id,
                secrets=secrets,
                bound_monotonic_ns=bound_monotonic_ns,
            )
        except Exception:
            secrets.clear()
            raise

    @_atomic_ingestion
    def _bind_source_from_secrets(
        self,
        *,
        camera_id: str,
        secrets: _SecretMaterial,
        bound_monotonic_ns: int,
    ) -> NativeSourceCallbacks:
        _validate_int(bound_monotonic_ns, "callback bind time")
        with self._lock:
            state = self._state_for(camera_id)
            if bound_monotonic_ns < self._epoch_started_monotonic_ns:
                raise ValueError("callback bind time predates the current epoch")
            if state.bound:
                raise RuntimeError("source callback already existed in this epoch")
            previous_bind_time = (
                self._epoch_started_monotonic_ns
                if state.monotonic_high_water_ns is None
                else state.monotonic_high_water_ns
            )
            if bound_monotonic_ns < previous_bind_time:
                raise ValueError("callback bind time regressed for its source")
            if bound_monotonic_ns - previous_bind_time > state.expectation.stale_after_ns:
                raise ValueError("callback bind time exceeds the signed source gap")
            observed_commitment = _compute_commitment_from_secrets(
                site_id=self._site_id,
                camera_id=camera_id,
                source_index=state.expectation.source_index,
                secrets=secrets,
            )
            identity_verified = hmac.compare_digest(
                observed_commitment,
                state.expectation.source_identity_commitment,
            )
            callback_generation = _increment_int64(
                state.callback_generation,
                "callback generation",
            )
            if callback_generation == _INT64_MAX:
                raise OverflowError("callback generation cannot guarantee a later close")
            self._require_event_capacity(
                close_reservation_delta=1,
            )
            close_token = object()
            callback = NativeSourceCallbacks(
                self,
                camera_id=camera_id,
                epoch=self._epoch,
                callback_generation=callback_generation,
                _issuer=_CALLBACK_ISSUER,
                _close_token=close_token,
            )
            callback_reference = weakref.ref(callback)
            candidate = _SourceState(expectation=state.expectation)
            candidate.bound = True
            candidate.identity_verified = identity_verified
            candidate.callback_generation = callback_generation
            candidate.callback_handle_ref = callback_reference
            candidate.callback_close_token = close_token
            candidate.monotonic_high_water_ns = (
                bound_monotonic_ns if identity_verified else state.monotonic_high_water_ns
            )
            candidate.bound_monotonic_ns = bound_monotonic_ns
            candidate.failures = dict(state.failures or {})

            next_generation = _increment_int64(
                self._generation,
                "tracker generation",
            )
            new_failure_codes: set[SourceProfileFailureCode] = set()
            if not identity_verified:
                new_failure_codes.add(_canonical_failure_code("profile_mismatch"))
            if len(self._deltas) >= self._delta_capacity:
                new_failure_codes.add(_canonical_failure_code("bounded_buffer_overflow"))
            assert candidate.failures is not None
            added_failures: list[SourceProfileFailure] = []
            for code in sorted(new_failure_codes, key=lambda failure_code: failure_code.value):
                if code not in candidate.failures:
                    failure = SourceProfileFailure(
                        camera_id=camera_id,
                        code=code,
                        epoch=self._epoch,
                        first_generation=next_generation,
                    )
                    candidate.failures[code] = failure
                    added_failures.append(failure)

            self._require_event_capacity()
            event = NativeSourceProfileDelta(
                epoch=self._epoch,
                generation=next_generation,
                event="source_bound",
                camera_id=camera_id,
                ready=False,
                failures=tuple(
                    sorted(
                        candidate.failures,
                        key=lambda failure_code: failure_code.value,
                    )
                ),
            )

            self._deltas.append(event)
            if len(self._deltas) > self._delta_capacity:
                self._popleft_delta()
            self._states[camera_id] = candidate
            self._generation = next_generation
            self._close_reservations += 1
            self._ready_at_monotonic_ns = None
            if identity_verified:
                self._monotonic_high_water_ns = max(
                    self._monotonic_high_water_ns,
                    bound_monotonic_ns,
                )
            self._record_failure_milestones(
                candidate,
                tuple(added_failures),
                event_monotonic_ns=bound_monotonic_ns,
            )
            return callback

    def _close_owned_state(self, state: _SourceState) -> None:
        callback_generation = _increment_int64(
            state.callback_generation,
            "callback generation",
        )
        self._require_event_capacity(
            close_reservation_delta=-1,
        )
        state.bound = False
        state.callback_handle_ref = None
        state.callback_close_token = None
        state.callback_generation = callback_generation
        self._ready_at_monotonic_ns = None
        self._close_reservations -= 1
        self._append_event(
            "callback_closed",
            state,
            event_monotonic_ns=self._monotonic_high_water_ns,
        )

    @_atomic_ingestion
    def _close_live_callback(self, callback: NativeSourceCallbacks) -> None:
        with self._lock:
            state = self._owned_state(
                callback,
                require_verified_identity=False,
            )
            if state is None:
                return
            self._close_owned_state(state)

    @_atomic_ingestion
    def _close_callback_lease(self, close_token: object) -> None:
        with self._lock:
            state = next(
                (
                    candidate
                    for candidate in self._states.values()
                    if candidate.bound and candidate.callback_close_token is close_token
                ),
                None,
            )
            if state is not None:
                self._close_owned_state(state)

    @staticmethod
    def _caps_match(
        expectation: SourceProfileExpectation,
        caps: NativeSourceCaps,
    ) -> bool:
        return (
            caps.codec == expectation.codec
            and caps.width == expectation.width
            and caps.height == expectation.height
            and expectation.fps_min <= caps.fps <= expectation.fps_max
            and expectation.bitrate_kbps_min <= caps.bitrate_kbps <= expectation.bitrate_kbps_max
        )

    @staticmethod
    def _continuity_gap_bound_ns(expectation: SourceProfileExpectation) -> int:
        two_slowest_frame_periods = math.ceil(2_000_000_000 / expectation.fps_min)
        return min(
            expectation.max_timestamp_gap_ns,
            1_000_000_000,
            two_slowest_frame_periods,
        )

    @_atomic_ingestion
    def _on_rtp_caps(
        self,
        callback: NativeSourceCallbacks,
        caps: NativeSourceCaps,
        observed_monotonic_ns: int,
    ) -> bool:
        if type(caps) is not NativeSourceCaps:
            raise TypeError("native RTP callback requires NativeSourceCaps")
        _validate_int(observed_monotonic_ns, "RTP CAPS callback time")
        with self._lock:
            state = self._owned_state(callback)
            if state is None:
                return False
            owned_caps = _clone_caps(caps)
            if not self._validate_callback_time(state, observed_monotonic_ns):
                return False
            if state.bound_monotonic_ns is None or not self._caps_match(
                state.expectation, owned_caps
            ):
                return self._fail(
                    state,
                    {_canonical_failure_code("profile_mismatch")},
                    event_monotonic_ns=observed_monotonic_ns,
                )
            self._commit_callback_time(
                state,
                observed_monotonic_ns,
                following_event_count=1,
            )
            state.caps = owned_caps
            state.caps_monotonic_ns = observed_monotonic_ns
            self._append_event(
                "rtp_caps",
                state,
                event_monotonic_ns=observed_monotonic_ns,
            )
            return True

    @_atomic_ingestion
    def _on_native_probe_failure(
        self,
        callback: NativeSourceCallbacks,
        code: SourceProfileFailureCode,
        observed_monotonic_ns: int,
    ) -> bool:
        if (
            type(code) is not SourceProfileFailureCode
            or code.value not in _NATIVE_PROBE_FAILURE_VALUES
        ):
            raise ValueError("native probe failure code is not authoritative")
        _validate_int(observed_monotonic_ns, "native probe failure callback time")
        with self._lock:
            state = self._owned_state(callback)
            if state is None:
                return False
            self._append_event(
                "native_probe_failure",
                state,
                event_monotonic_ns=observed_monotonic_ns,
            )
            return self._fail(
                state,
                {_canonical_failure_code(code.value)},
                event_monotonic_ns=observed_monotonic_ns,
            )

    @_atomic_ingestion
    def _on_parser_counter(
        self,
        callback: NativeSourceCallbacks,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int(parser_bytes, "parser byte counter", minimum=1)
        _validate_int(source_timestamp_ns, "source timestamp counter", minimum=1)
        _validate_int(observed_monotonic_ns, "parser callback time")
        with self._lock:
            state = self._owned_state(callback)
            if state is None:
                return False
            if not self._validate_callback_time(state, observed_monotonic_ns):
                return False
            if state.caps is None or state.caps_monotonic_ns is None:
                return self._fail(
                    state,
                    {_canonical_failure_code("invalid_callback_provenance")},
                    event_monotonic_ns=observed_monotonic_ns,
                )
            failures: set[SourceProfileFailureCode] = set()
            if observed_monotonic_ns < state.caps_monotonic_ns or (
                state.pending_parser is not None and observed_monotonic_ns < state.pending_parser[2]
            ):
                failures.add(_canonical_failure_code("counter_regression"))
            if state.last_parser_bytes is not None and parser_bytes <= state.last_parser_bytes:
                failures.add(_canonical_failure_code("counter_regression"))
            if state.last_source_timestamp_ns is not None:
                if source_timestamp_ns < state.last_source_timestamp_ns:
                    failures.add(_canonical_failure_code("timestamp_regression"))
                elif source_timestamp_ns == state.last_source_timestamp_ns:
                    failures.add(_canonical_failure_code("timestamp_replay"))
            if failures:
                return self._fail(
                    state,
                    failures,
                    event_monotonic_ns=observed_monotonic_ns,
                )
            self._commit_callback_time(state, observed_monotonic_ns)
            state.pending_parser = (
                parser_bytes,
                source_timestamp_ns,
                observed_monotonic_ns,
            )
            state.last_parser_bytes = parser_bytes
            state.last_source_timestamp_ns = source_timestamp_ns
            return True

    @_atomic_ingestion
    def _on_decoded_frame(
        self,
        callback: NativeSourceCallbacks,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int(decoded_frames, "decoded frame counter", minimum=1)
        _validate_int(source_ntp_ns, "source NTP counter", minimum=1)
        _validate_int(observed_monotonic_ns, "decoder callback time")
        with self._lock:
            state = self._owned_state(callback)
            if state is None:
                return False
            if not self._validate_callback_time(state, observed_monotonic_ns):
                return False
            if state.caps is None or state.pending_parser is None:
                return self._fail(
                    state,
                    {_canonical_failure_code("invalid_callback_provenance")},
                    event_monotonic_ns=observed_monotonic_ns,
                )
            parser_bytes, source_timestamp_ns, parser_monotonic_ns = state.pending_parser
            previous = state.observation
            failures: set[SourceProfileFailureCode] = set()
            if observed_monotonic_ns < parser_monotonic_ns:
                failures.add(_canonical_failure_code("invalid_callback_provenance"))
            if previous is not None:
                monotonic_delta = observed_monotonic_ns - previous.observed_monotonic_ns
                source_ntp_delta = source_ntp_ns - previous.source_ntp_ns
                source_timestamp_delta = source_timestamp_ns - previous.source_timestamp_ns
                if decoded_frames <= previous.decoded_frames or monotonic_delta <= 0:
                    failures.add(_canonical_failure_code("counter_regression"))
                if source_ntp_delta < 0:
                    failures.add(_canonical_failure_code("timestamp_regression"))
                elif source_ntp_delta == 0:
                    failures.add(_canonical_failure_code("timestamp_replay"))
                if monotonic_delta > self._continuity_gap_bound_ns(state.expectation):
                    failures.add(_canonical_failure_code("excessive_gap"))
                if (
                    abs(source_ntp_delta - monotonic_delta)
                    > state.expectation.max_timestamp_skew_ns
                    or abs(source_timestamp_delta - monotonic_delta)
                    > state.expectation.max_timestamp_skew_ns
                ):
                    failures.add(_canonical_failure_code("excessive_skew"))
            if failures:
                return self._fail(
                    state,
                    failures,
                    event_monotonic_ns=observed_monotonic_ns,
                )

            observation = NativeSourceObservation(
                caps=state.caps,
                parser_bytes=parser_bytes,
                decoded_frames=decoded_frames,
                source_ntp_ns=source_ntp_ns,
                source_timestamp_ns=source_timestamp_ns,
                observed_monotonic_ns=observed_monotonic_ns,
            )
            continuous_observations = _increment_int64(
                state.continuous_observations,
                "continuous observation counter",
            )
            self._commit_callback_time(
                state,
                observed_monotonic_ns,
                following_event_count=1,
                stale_now_monotonic_ns=self._maximum_current_observation_time(
                    pending_state=state,
                    pending_observation=observation,
                ),
                pending_observation=observation,
            )
            state.pending_parser = None
            state.observation = observation
            state.continuous_observations = continuous_observations
            if state.baseline_monotonic_ns is None:
                state.baseline_monotonic_ns = observed_monotonic_ns
                state.baseline_source_ntp_ns = source_ntp_ns
                state.baseline_source_timestamp_ns = source_timestamp_ns
            assert state.baseline_source_ntp_ns is not None
            assert state.baseline_source_timestamp_ns is not None
            if previous is not None:
                state.maximum_observed_gap_ns = max(
                    state.maximum_observed_gap_ns,
                    observed_monotonic_ns - previous.observed_monotonic_ns,
                )
            state.baseline_duration_ns = min(
                observed_monotonic_ns - state.baseline_monotonic_ns,
                source_ntp_ns - state.baseline_source_ntp_ns,
                source_timestamp_ns - state.baseline_source_timestamp_ns,
            )
            completed_prewarm = (
                state.prewarm_completed_monotonic_ns is None
                and state.baseline_duration_ns >= _PREWARM_NS
            )
            if completed_prewarm:
                state.prewarm_completed_monotonic_ns = observed_monotonic_ns
            self._refresh_readiness()
            event_generation = self._append_event(
                "observation",
                state,
                observation,
                event_monotonic_ns=observed_monotonic_ns,
            )
            if completed_prewarm:
                self._record_prewarm_milestone(
                    state,
                    observation,
                    event_generation=event_generation,
                )
            return True

    def _maximum_current_observation_time(
        self,
        *,
        pending_state: _SourceState | None = None,
        pending_observation: NativeSourceObservation | None = None,
    ) -> int:
        observation_times: list[int] = []
        for state in self._states.values():
            observation = (
                pending_observation
                if state is pending_state and pending_observation is not None
                else state.observation
            )
            if observation is not None:
                observation_times.append(observation.observed_monotonic_ns)
        return max(
            observation_times,
            default=self._epoch_started_monotonic_ns,
        )

    def _refresh_readiness(self) -> None:
        self._mark_stale_sources(self._maximum_current_observation_time())
        if self._ready_at_monotonic_ns is not None:
            return
        if all(
            state.bound
            and state.identity_verified
            and state.observation is not None
            and state.baseline_duration_ns >= _PREWARM_NS
            and state.prewarm_completed_monotonic_ns is not None
            and state.continuous_observations >= 2
            and state.maximum_observed_gap_ns <= self._continuity_gap_bound_ns(state.expectation)
            and not state.failures
            for state in self._states.values()
        ):
            self._ready_at_monotonic_ns = max(
                state.prewarm_completed_monotonic_ns
                for state in self._states.values()
                if state.prewarm_completed_monotonic_ns is not None
            )

    @staticmethod
    def _is_newly_stale(
        state: _SourceState,
        now_monotonic_ns: int,
        epoch_started_monotonic_ns: int,
        *,
        pending_state: _SourceState | None = None,
        pending_observation: NativeSourceObservation | None = None,
    ) -> bool:
        failures = state.failures or {}
        if _canonical_failure_code("stale_source") in failures:
            return False
        observation = (
            pending_observation
            if state is pending_state and pending_observation is not None
            else state.observation
        )
        reference = (
            observation.observed_monotonic_ns
            if observation is not None
            else (
                state.bound_monotonic_ns
                if state.bound_monotonic_ns is not None
                else epoch_started_monotonic_ns
            )
        )
        return now_monotonic_ns - reference > state.expectation.stale_after_ns

    def _new_stale_failure_count(
        self,
        now_monotonic_ns: int,
        *,
        pending_state: _SourceState | None = None,
        pending_observation: NativeSourceObservation | None = None,
    ) -> int:
        return sum(
            self._is_newly_stale(
                state,
                now_monotonic_ns,
                self._epoch_started_monotonic_ns,
                pending_state=pending_state,
                pending_observation=pending_observation,
            )
            for state in self._states.values()
        )

    def _mark_stale_sources(
        self,
        now_monotonic_ns: int,
        *,
        pending_state: _SourceState | None = None,
        pending_observation: NativeSourceObservation | None = None,
    ) -> None:
        self._require_event_capacity(
            self._new_stale_failure_count(
                now_monotonic_ns,
                pending_state=pending_state,
                pending_observation=pending_observation,
            )
        )
        for state in self._states.values():
            observation = (
                pending_observation
                if state is pending_state and pending_observation is not None
                else state.observation
            )
            reference = (
                observation.observed_monotonic_ns
                if observation is not None
                else (
                    state.bound_monotonic_ns
                    if state.bound_monotonic_ns is not None
                    else self._epoch_started_monotonic_ns
                )
            )
            if now_monotonic_ns - reference > state.expectation.stale_after_ns:
                self._fail(
                    state,
                    {_canonical_failure_code("stale_source")},
                    event_monotonic_ns=now_monotonic_ns,
                )

    @_atomic_ingestion
    def check_stale(self, *, now_monotonic_ns: int) -> NativeSourceProfileSnapshot:
        _validate_int(now_monotonic_ns, "stale check time")
        with self._lock:
            if now_monotonic_ns < self._stale_check_high_water_ns:
                raise ValueError("stale check time regressed behind its monotonic high-water")
            self._require_event_capacity(self._new_stale_failure_count(now_monotonic_ns))
            self._stale_check_high_water_ns = now_monotonic_ns
            self._monotonic_high_water_ns = max(
                self._monotonic_high_water_ns,
                now_monotonic_ns,
            )
            self._mark_stale_sources(now_monotonic_ns)
            return self._snapshot_unlocked()

    def ready_for_gate(self, *, gate_started_monotonic_ns: int) -> bool:
        snapshot = self.check_stale(now_monotonic_ns=gate_started_monotonic_ns)
        return (
            snapshot.ready
            and snapshot.ready_at_monotonic_ns is not None
            and snapshot.ready_at_monotonic_ns < gate_started_monotonic_ns
        )

    def restart_epoch(self, *, started_monotonic_ns: int) -> NativeSourceProfileSnapshot:
        _validate_int(started_monotonic_ns, "epoch start")
        with self._lock:
            if started_monotonic_ns <= self._monotonic_high_water_ns:
                raise ValueError("new epoch must start after monotonic high-water")
            epoch = _increment_int64(self._epoch, "source profile epoch")
            self._require_event_capacity(
                close_reservation_delta=-self._close_reservations,
            )
            epoch_started_generation = _increment_int64(
                self._generation,
                "tracker generation",
            )
            milestone_authentication_tag = self._compute_terminal_authentication_tag(
                receipt_count=0,
                final_head="0" * 64,
                epoch=epoch,
                epoch_started_generation=epoch_started_generation,
            )
            self._epoch = epoch
            self._epoch_started_monotonic_ns = started_monotonic_ns
            self._monotonic_high_water_ns = started_monotonic_ns
            self._stale_check_high_water_ns = started_monotonic_ns
            self._ready_at_monotonic_ns = None
            self._states = {
                expectation.camera_id: _SourceState(expectation=expectation)
                for expectation in self._expectations
            }
            self._milestone_receipts = []
            self._close_reservations = 0
            self._deltas.clear()
            self._append_event("epoch_started", None)
            self._epoch_started_generation = self._generation
            if self._epoch_started_generation != epoch_started_generation:
                raise RuntimeError("source profile restart generation changed before commit")
            self._milestone_authentication_tag = milestone_authentication_tag
            return self._snapshot_unlocked()

    def acknowledge_deltas(self, *, through_generation: int) -> None:
        _validate_int(through_generation, "acknowledged generation")
        with self._lock:
            while self._deltas and self._deltas[0].generation <= through_generation:
                self._deltas.popleft()

    def deltas_since(self, generation: int) -> tuple[NativeSourceProfileDelta, ...]:
        _validate_int(generation, "delta generation")
        with self._lock:
            return tuple(
                _clone_delta(delta) for delta in self._deltas if delta.generation > generation
            )

    def _milestone_receipts_unlocked(
        self,
    ) -> tuple[SourceProfileMilestoneReceiptV1, ...]:
        return tuple(_clone_milestone_receipt(receipt) for receipt in self._milestone_receipts)

    def authoritative_proof(self) -> NativeSourceProfileProofEnvelopeV1:
        """Sign one detached proof of exact tracker-owned epoch milestones."""

        with self._lock:
            if (
                self._proof_signer is None
                or self._proof_key_id is None
                or self._proof_public_key is None
                or self._proof_public_key_sha256 is None
            ):
                raise RuntimeError("source profile authoritative proof signer is not configured")
            proof_signer = self._proof_signer
            proof_key_id = self._proof_key_id
            proof_public_key_sha256 = self._proof_public_key_sha256
            site_id = self._site_id
            milestone_authenticator_key_id = self._milestone_authenticator_key_id
            milestone_authentication_tag = self._milestone_authentication_tag
            snapshot = self._snapshot_unlocked()
            receipts = self._milestone_receipts_unlocked()
            final_head = receipts[-1].head if receipts else "0" * 64
            snapshot_sha256 = hashlib.sha256(_canonical_bytes(snapshot.to_dict())).hexdigest()
            unsigned = NativeSourceProfileProofEnvelopeV1(
                schema=_SOURCE_PROOF_SCHEMA,
                site_id=site_id,
                key_id=proof_key_id,
                public_key_sha256=proof_public_key_sha256,
                milestone_authenticator_key_id=(milestone_authenticator_key_id),
                milestone_authentication_tag=(milestone_authentication_tag),
                epoch=snapshot.epoch,
                epoch_started_generation=snapshot.epoch_started_generation,
                generation=snapshot.generation,
                source_identity_commitments=tuple(
                    expectation.source_identity_commitment for expectation in self._expectations
                ),
                snapshot_sha256=snapshot_sha256,
                snapshot=snapshot,
                receipts=receipts,
                final_head=final_head,
                signature="0" * 128,
            )
        signature = proof_signer.sign(_proof_signing_payload(unsigned))
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("source profile proof signer returned an invalid signature")
        envelope = NativeSourceProfileProofEnvelopeV1(
            schema=unsigned.schema,
            site_id=unsigned.site_id,
            key_id=unsigned.key_id,
            public_key_sha256=unsigned.public_key_sha256,
            milestone_authenticator_key_id=(unsigned.milestone_authenticator_key_id),
            milestone_authentication_tag=(unsigned.milestone_authentication_tag),
            epoch=unsigned.epoch,
            epoch_started_generation=unsigned.epoch_started_generation,
            generation=unsigned.generation,
            source_identity_commitments=unsigned.source_identity_commitments,
            snapshot_sha256=unsigned.snapshot_sha256,
            snapshot=unsigned.snapshot,
            receipts=unsigned.receipts,
            final_head=unsigned.final_head,
            signature=signature.hex(),
        )
        return envelope

    def _snapshot_unlocked(self) -> NativeSourceProfileSnapshot:
        sources = tuple(
            NativeSourceStateSnapshot(
                camera_id=expectation.camera_id,
                source_index=expectation.source_index,
                bound=self._states[expectation.camera_id].bound,
                identity_verified=self._states[expectation.camera_id].identity_verified,
                callback_generation=self._states[expectation.camera_id].callback_generation,
                observation=self._states[expectation.camera_id].observation,
                baseline_duration_ns=self._states[expectation.camera_id].baseline_duration_ns,
                continuous_observations=self._states[expectation.camera_id].continuous_observations,
                maximum_observed_gap_ns=self._states[expectation.camera_id].maximum_observed_gap_ns,
                continuity_gap_bound_ns=self._continuity_gap_bound_ns(expectation),
                stale_after_ns=expectation.stale_after_ns,
                prewarm_completed_monotonic_ns=self._states[
                    expectation.camera_id
                ].prewarm_completed_monotonic_ns,
                failures=tuple(
                    sorted(
                        (self._states[expectation.camera_id].failures or {}).values(),
                        key=lambda failure: failure.code.value,
                    )
                ),
            )
            for expectation in self._expectations
        )
        failures = tuple(failure for source in sources for failure in source.failures)
        return NativeSourceProfileSnapshot(
            epoch=self._epoch,
            generation=self._generation,
            epoch_started_generation=self._epoch_started_generation,
            ready=self._ready_at_monotonic_ns is not None and not failures,
            epoch_started_monotonic_ns=self._epoch_started_monotonic_ns,
            ready_at_monotonic_ns=self._ready_at_monotonic_ns,
            sources=sources,
            failures=failures,
        )

    def snapshot(self) -> NativeSourceProfileSnapshot:
        with self._lock:
            return self._snapshot_unlocked()


__all__ = [
    "Ed25519SourceProfileProofSigner",
    "NativeSourceCallbacks",
    "NativeSourceCaps",
    "NativeSourceObservation",
    "NativeSourceProfileDelta",
    "NativeSourceProfileProofEnvelopeV1",
    "NativeSourceProfileSnapshot",
    "NativeSourceProfileTracker",
    "NativeSourceStateSnapshot",
    "SourceProfileMilestoneReceiptV1",
    "SourceProfileExpectation",
    "SourceProfileFailure",
    "SourceProfileFailureCode",
    "SourceProfileProofSigner",
    "compute_source_identity_commitment",
    "verify_source_profile_proof",
]
