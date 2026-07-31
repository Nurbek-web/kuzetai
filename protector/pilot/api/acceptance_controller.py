"""Loopback-only acceptance authority process, independent of the pilot API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import StreamingResponse

from protector.pilot.acceptance import MAX_ACCEPTANCE_ENVELOPE_BYTES
from protector.pilot.acceptance_authority import (
    AcceptanceAuthority,
    AcceptanceAuthorityTrustContextV2,
    AcceptanceFaultAckRequestV2,
    AcceptanceFaultAckResponseV2,
    AcceptanceFaultPrepareRequestV2,
    AcceptanceFaultPrepareResponseV2,
    AcceptanceFinalizeRequestV2,
    AcceptanceProofRequestV2,
    AcceptanceRunSigner,
    AcceptanceSampleRequestV2,
    AcceptanceSampleResponseV2,
    AcceptanceStartRequestV2,
    AcceptanceStartResponseV2,
    SQLiteAcceptanceAuthorityJournal,
    TargetAcceptanceAdapter,
    build_authority_trust_context,
    read_host_boot_id,
)
from protector.pilot.acceptance_authority_v3 import (
    AcceptanceAuthorityStateStoreV3,
    AcceptanceAuthorityV3,
)
from protector.pilot.acceptance_capture_v3 import (
    ProtectedAcceptanceCaptureRepositoryV3,
)
from protector.pilot.acceptance_controller_v3 import (
    AcceptanceControllerResultV3,
    CollectorBoundAcceptanceControllerV3,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    AcceptanceProofStore,
)
from protector.pilot.acceptance_proof_v3 import AcceptanceProofStoreV3
from protector.pilot.acceptance_snapshot import (
    AcceptanceAuthoritySnapshotStoreV3,
)
from protector.pilot.acceptance_trust import (
    AcceptanceRolePublicKeyPathsV2,
    verify_acceptance_trust_chain,
)
from protector.pilot.api.app import (
    MAX_REQUEST_BODY_BYTES,
    ProcessSingletonLock,
    RequestBodyLimitMiddleware,
)
from protector.pilot.trusted_artifacts import (
    capture_regular_bounded,
    trusted_openssl_executable,
)

_TOKEN_PATH = Path("/run/secrets/acceptance_controller_token")
_MAX_TOKEN_BYTES = 16 * 1024
_MAX_FINAL_REQUEST_BODY_BYTES = MAX_ACCEPTANCE_ENVELOPE_BYTES
_RUN_SIGNING_KEY_PATH = Path("/run/keys/acceptance/run-private.pem")
_PROOF_ROOT_PATH = Path("/var/lib/kuzet/acceptance-proofs")
_OFFLINE_ROOT_PUBLIC_KEY_PATH = Path("/run/config/acceptance/offline-root-public.pem")
_TRUST_POLICY_PATH = Path("/run/config/acceptance/trust-policy.json")
_TRUST_POLICY_SIGNATURE_PATH = Path("/run/config/acceptance/trust-policy.sig")
_ACCEPTANCE_MANIFEST_PATH = Path("/run/config/acceptance/acceptance-manifest.json")
_ACCEPTANCE_MANIFEST_SIGNATURE_PATH = Path("/run/config/acceptance/acceptance-manifest.sig")
_ROLE_PUBLIC_KEY_PATHS = AcceptanceRolePublicKeyPathsV2(
    manifest=Path("/run/config/acceptance/manifest-role-public.pem"),
    capacity=Path("/run/config/acceptance/capacity-role-public.pem"),
    run=Path("/run/config/acceptance/run-role-public.pem"),
    report=Path("/run/config/acceptance/report-role-public.pem"),
    conditional=Path("/run/config/acceptance/conditional-role-public.pem"),
)
_PROTECTED_NAMESPACE_OWNER_UID = 0
_PROTECTED_NAMESPACE_RUNTIME_UID = 10_001
_PROTECTED_NAMESPACE_RUNTIME_GID = 10_001
_ED25519_PRIVATE_KEY_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_ED25519_PRIVATE_KEY_PEM = re.compile(
    rb"-----BEGIN PRIVATE KEY-----\n"
    rb"([A-Za-z0-9+/]{64})\n"
    rb"-----END PRIVATE KEY-----\n"
)


class AcceptanceRequestBodyLimitMiddleware(RequestBodyLimitMiddleware):
    """Keep small control messages tight while allowing one bounded final record."""

    def __init__(
        self,
        app: Any,
        *,
        max_body_bytes: int,
        max_final_body_bytes: int,
    ) -> None:
        super().__init__(app, max_body_bytes=max_body_bytes)
        if max_final_body_bytes < max_body_bytes:
            raise ValueError("final acceptance body limit cannot be smaller")
        self.max_final_body_bytes = max_final_body_bytes

    def _limit_for_scope(self, scope: dict[str, Any]) -> int:
        if scope.get("path") == "/api/internal/acceptance/finalize":
            return self.max_final_body_bytes
        return self.max_body_bytes


class OpenSSLAcceptanceRunSigner:
    """Ed25519 signer whose private key exists only in the controller."""

    def __init__(
        self,
        private_key_path: Path,
        *,
        expected_public_key_spki_sha256: str,
        expected_uid: int = _PROTECTED_NAMESPACE_RUNTIME_UID,
        expected_gid: int = _PROTECTED_NAMESPACE_RUNTIME_UID,
    ) -> None:
        if len(expected_public_key_spki_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_public_key_spki_sha256
        ):
            raise ValueError("run authority public key fingerprint is invalid")
        captured = capture_regular_bounded(
            private_key_path,
            max_bytes=64 * 1024,
            label="run authority private key",
        )
        metadata = captured.metadata
        if (
            expected_uid < 0
            or expected_gid < 0
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise ValueError("run authority private key metadata is invalid")
        match = _ED25519_PRIVATE_KEY_PEM.fullmatch(captured.payload)
        if match is None:
            raise ValueError("run authority private key must be one canonical PKCS#8 key")
        try:
            private_der = base64.b64decode(match.group(1), validate=True)
        except ValueError:
            raise ValueError("run authority private key must be one canonical PKCS#8 key") from None
        if len(private_der) != 48 or not private_der.startswith(_ED25519_PRIVATE_KEY_DER_PREFIX):
            raise ValueError("run authority private key must be Ed25519 PKCS#8")
        self._private_key = captured.payload
        with tempfile.TemporaryDirectory(prefix="kuzet-run-signer-") as temporary:
            key_path = Path(temporary) / "private.pem"
            key_path.write_bytes(self._private_key)
            key_path.chmod(0o600)
            result = subprocess.run(
                (
                    trusted_openssl_executable(),
                    "pkey",
                    "-in",
                    str(key_path),
                    "-pubout",
                    "-outform",
                    "DER",
                ),
                check=False,
                capture_output=True,
                timeout=10,
            )
        if (
            result.returncode
            or len(result.stdout) != 44
            or not result.stdout.startswith(bytes.fromhex("302a300506032b6570032100"))
        ):
            raise ValueError("run authority private key must be Ed25519")
        fingerprint = hashlib.sha256(result.stdout).hexdigest()
        if fingerprint != expected_public_key_spki_sha256:
            raise ValueError("run authority private key differs from pinned public key")
        self._public_key_spki_sha256 = fingerprint

    @property
    def public_key_spki_sha256(self) -> str:
        return self._public_key_spki_sha256

    def sign(self, payload: bytes) -> bytes:
        if not 1 <= len(payload) <= 64 * 1024 * 1024:
            raise ValueError("run authority payload is unbounded")
        with tempfile.TemporaryDirectory(prefix="kuzet-run-signature-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            key_path = root / "private.pem"
            payload_path = root / "record.json"
            signature_path = root / "record.sig"
            key_path.write_bytes(self._private_key)
            key_path.chmod(0o600)
            payload_path.write_bytes(payload)
            payload_path.chmod(0o600)
            result = subprocess.run(
                (
                    trusted_openssl_executable(),
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(key_path),
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
                raise RuntimeError("run authority signing failed")
            signature = signature_path.read_bytes()
        if len(signature) != 64:
            raise RuntimeError("run authority signature is invalid")
        return signature


def _compose_acceptance_authority(
    *,
    journal_path: Path,
    journal_namespace_owner_uid: int | None,
    adapter: TargetAcceptanceAdapter | None,
    signer: AcceptanceRunSigner | None,
    proof_store: AcceptanceProofStore | None,
    trust_context: AcceptanceAuthorityTrustContextV2 | None,
    wall_clock: Callable[[], datetime],
    monotonic_clock: Callable[[], float],
    host_boot_id_provider: Callable[[], str],
) -> AcceptanceAuthority:
    return AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(
            journal_path,
            protected_namespace_owner_uid=journal_namespace_owner_uid,
        ),
        adapter=adapter,
        signer=signer,
        proof_store=proof_store,
        trust_context=trust_context,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
        host_boot_id_provider=host_boot_id_provider,
    )


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def build_production_acceptance_authority() -> AcceptanceAuthority:
    """Build one fixed-path, offline-root-bound target authority."""
    if os.geteuid() != _PROTECTED_NAMESPACE_RUNTIME_UID:
        raise RuntimeError("acceptance controller must run as the provisioned runtime UID")
    allowed_acceptance_environment = {
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        "PILOT_ACCEPTANCE_GATE",
        "PILOT_ACCEPTANCE_JOURNAL_PATH",
        "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256",
        "PILOT_ACCEPTANCE_PROOF_DIR",
        "PILOT_ACCEPTANCE_SNAPSHOT_DIR",
        "PILOT_ACCEPTANCE_CHANNEL_DIR",
        "PILOT_ACCEPTANCE_CAPTURE_DIR",
    }
    forbidden = tuple(
        name
        for name in os.environ
        if name.startswith("PILOT_ACCEPTANCE_") and name not in allowed_acceptance_environment
    )
    if forbidden:
        raise RuntimeError("acceptance controller environment contains an unsupported override")
    configured_path = os.environ.get(
        "PILOT_ACCEPTANCE_JOURNAL_PATH",
        "",
    ).strip()
    if not configured_path:
        raise RuntimeError("PILOT_ACCEPTANCE_JOURNAL_PATH is required")
    journal_path = Path(configured_path)
    if not journal_path.is_absolute():
        raise RuntimeError("acceptance journal path must be absolute")
    configured_gate = _required_environment("PILOT_ACCEPTANCE_GATE")
    if configured_gate not in {"8h", "72h"}:
        raise RuntimeError("PILOT_ACCEPTANCE_GATE must be 8h or 72h")
    try:
        trust = verify_acceptance_trust_chain(
            expected_offline_root_spki_sha256=_required_environment(
                "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256"
            ),
            root_public_key_path=_OFFLINE_ROOT_PUBLIC_KEY_PATH,
            policy_path=_TRUST_POLICY_PATH,
            policy_signature_path=_TRUST_POLICY_SIGNATURE_PATH,
            role_public_key_paths=_ROLE_PUBLIC_KEY_PATHS,
            manifest_path=_ACCEPTANCE_MANIFEST_PATH,
            manifest_signature_path=(_ACCEPTANCE_MANIFEST_SIGNATURE_PATH),
        )
        trust_context = build_authority_trust_context(
            trust=trust,
            configured_site_id=_required_environment("PILOT_SITE_ID"),
            configured_campaign_id=_required_environment("PILOT_ACCEPTANCE_CAMPAIGN_ID"),
            configured_gate=configured_gate,  # type: ignore[arg-type]
        )
    except ValueError as exc:
        raise RuntimeError("acceptance offline-root trust is unavailable") from exc
    try:
        signer = OpenSSLAcceptanceRunSigner(
            _RUN_SIGNING_KEY_PATH,
            expected_public_key_spki_sha256=(trust.policy.roles.run_spki_sha256),
            expected_uid=_PROTECTED_NAMESPACE_RUNTIME_UID,
            expected_gid=_PROTECTED_NAMESPACE_RUNTIME_GID,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("acceptance run authority signer is unavailable") from exc
    proof_root = Path(
        os.environ.get(
            "PILOT_ACCEPTANCE_PROOF_DIR",
            str(_PROOF_ROOT_PATH),
        )
    )
    try:
        proof_store = AcceptanceProofStore(proof_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("acceptance journal proof store is unavailable") from exc
    return _compose_acceptance_authority(
        journal_path=journal_path,
        journal_namespace_owner_uid=_PROTECTED_NAMESPACE_OWNER_UID,
        adapter=None,
        signer=signer,
        proof_store=proof_store,
        trust_context=trust_context,
        wall_clock=lambda: datetime.now(UTC),
        monotonic_clock=time.monotonic,
        host_boot_id_provider=read_host_boot_id,
    )


def _read_controller_token(path: Path = _TOKEN_PATH) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 16 <= metadata.st_size <= _MAX_TOKEN_BYTES:
            raise RuntimeError("acceptance controller token is unavailable")
        payload = os.read(descriptor, _MAX_TOKEN_BYTES + 1)
        if len(payload) != metadata.st_size:
            raise RuntimeError("acceptance controller token changed while reading")
        token = payload.decode("utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("acceptance controller token is unavailable") from exc
    finally:
        os.close(descriptor)
    if len(token) < 16:
        raise RuntimeError("acceptance controller token is unavailable")
    return token


def create_acceptance_controller_app(
    *,
    authority: Any,
    v3_authority: Any | None = None,
    controller_token: str,
    runtime_lock_path: str | Path = "/tmp/kuzet-acceptance-controller.lock",
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
    max_final_request_body_bytes: int = _MAX_FINAL_REQUEST_BODY_BYTES,
    v3_authorization_guard: Callable[[], None] | None = None,
) -> FastAPI:
    """Create the small authenticated controller surface."""
    if (
        authority is None
        or (
            v3_authority is not None
            and (
                not callable(
                    getattr(v3_authority, "finalize_collector", None)
                )
                or not callable(
                    getattr(v3_authority, "readiness_probe", None)
                )
            )
        )
        or (
            v3_authorization_guard is not None
            and not callable(v3_authorization_guard)
        )
        or len(controller_token) < 16
    ):
        raise ValueError("acceptance controller requires authority and token")
    singleton = ProcessSingletonLock(runtime_lock_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        singleton.acquire()
        try:
            yield
        finally:
            singleton.release()

    app = FastAPI(
        title="Kuzet AI Acceptance Controller",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        AcceptanceRequestBodyLimitMiddleware,
        max_body_bytes=max_request_body_bytes,
        max_final_body_bytes=max_final_request_body_bytes,
    )

    def require_controller(
        authorization: Annotated[
            str | None,
            Header(alias="Authorization"),
        ] = None,
    ) -> None:
        scheme, separator, credential = (authorization or "").partition(" ")
        if (
            separator != " "
            or scheme.casefold() != "bearer"
            or not credential
            or not hmac.compare_digest(credential, controller_token)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="acceptance controller authentication required",
            )

    def call(method: str, payload: dict[str, object]) -> dict[str, object]:
        try:
            result = getattr(authority, method)(payload)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_acceptance_evidence",
                    "message": "acceptance evidence is invalid",
                },
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "acceptance_state_conflict",
                    "message": "acceptance state conflict",
                },
            ) from exc
        if not isinstance(result, dict):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="acceptance authority unavailable",
            )
        return result

    @app.post(
        "/api/internal/acceptance/start",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceStartResponseV2,
    )
    def start(payload: AcceptanceStartRequestV2) -> dict[str, object]:
        return call("start", payload.model_dump(mode="json"))

    @app.post(
        "/api/internal/acceptance/sample",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceSampleResponseV2,
    )
    def sample(payload: AcceptanceSampleRequestV2) -> dict[str, object]:
        return call("sample", payload.model_dump(mode="json"))

    @app.post(
        "/api/internal/acceptance/fault/prepare",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceFaultPrepareResponseV2,
    )
    def prepare_fault(
        payload: AcceptanceFaultPrepareRequestV2,
    ) -> dict[str, object]:
        return call("prepare_fault", payload.model_dump(mode="json"))

    @app.post(
        "/api/internal/acceptance/fault/ack",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceFaultAckResponseV2,
    )
    def acknowledge_fault(
        payload: AcceptanceFaultAckRequestV2,
    ) -> dict[str, object]:
        return call(
            "acknowledge_fault",
            payload.model_dump(mode="json"),
        )

    @app.post(
        "/api/internal/acceptance/finalize",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceFinalEnvelopeV2,
    )
    def finalize(payload: AcceptanceFinalizeRequestV2) -> dict[str, object]:
        return call("finalize", payload.model_dump(mode="json"))

    if v3_authority is not None:

        @app.post(
            "/api/internal/acceptance/v3/collectors/{collector_id}/finalize",
            dependencies=[Depends(require_controller)],
            response_model=AcceptanceControllerResultV3,
        )
        def finalize_collector(collector_id: str) -> dict[str, object]:
            if (
                re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}",
                    collector_id,
                )
                is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="collector identity is invalid",
                )
            try:
                if v3_authorization_guard is not None:
                    v3_authorization_guard()
                result = v3_authority.finalize_collector(collector_id)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "code": "invalid_acceptance_evidence",
                        "message": "acceptance evidence is invalid",
                    },
                ) from exc
            except RuntimeError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "code": "acceptance_state_conflict",
                        "message": "acceptance state conflict",
                    },
                ) from exc
            if not isinstance(result, dict):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="acceptance authority unavailable",
                )
            return result

    @app.post(
        "/api/internal/acceptance/proof",
        dependencies=[Depends(require_controller)],
    )
    def proof(payload: AcceptanceProofRequestV2) -> StreamingResponse:
        try:
            attestation, chunks = authority.proof_metadata(
                payload.model_dump(mode="json")
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_acceptance_evidence",
                    "message": "acceptance evidence is invalid",
                },
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "acceptance_state_conflict",
                    "message": "acceptance state conflict",
                },
            ) from exc
        return StreamingResponse(
            chunks,
            media_type="application/x-ndjson",
            headers={
                "Content-Length": str(attestation.journal_proof_bytes),
                "Digest": f"sha-256={attestation.journal_proof_sha256}",
                "X-Kuzet-Proof-Lines": str(attestation.journal_proof_lines),
            },
        )

    @app.get(
        "/live",
        dependencies=[Depends(require_controller)],
    )
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get(
        "/ready",
        dependencies=[Depends(require_controller)],
    )
    def ready() -> dict[str, str]:
        try:
            if (
                v3_authority is not None
                and v3_authorization_guard is not None
            ):
                v3_authorization_guard()
            authority.readiness_probe()
            if v3_authority is not None:
                v3_authority.readiness_probe()
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="acceptance controller is not ready",
            ) from exc
        return {"status": "ready"}

    return app


def create_v3_acceptance_controller_app(
    *,
    authority: Any,
    controller_token: str,
    runtime_lock_path: str | Path = "/tmp/kuzet-acceptance-controller-v3.lock",
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
    authorization_guard: Callable[[], None] | None = None,
) -> FastAPI:
    """Expose only collector-bound finalization; all evidence stays provider owned."""

    if (
        authority is None
        or not callable(getattr(authority, "finalize_collector", None))
        or not callable(getattr(authority, "readiness_probe", None))
        or (
            authorization_guard is not None
            and not callable(authorization_guard)
        )
        or len(controller_token) < 16
    ):
        raise ValueError("V3 acceptance controller requires authority and token")
    singleton = ProcessSingletonLock(runtime_lock_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        singleton.acquire()
        try:
            yield
        finally:
            singleton.release()

    app = FastAPI(
        title="Kuzet AI Acceptance Controller V3",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=max_request_body_bytes,
    )

    def require_controller(
        authorization: Annotated[
            str | None,
            Header(alias="Authorization"),
        ] = None,
    ) -> None:
        scheme, separator, credential = (authorization or "").partition(" ")
        if (
            separator != " "
            or scheme.casefold() != "bearer"
            or not credential
            or not hmac.compare_digest(credential, controller_token)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="acceptance controller authentication required",
            )

    @app.post(
        "/api/internal/acceptance/v3/collectors/{collector_id}/finalize",
        dependencies=[Depends(require_controller)],
        response_model=AcceptanceControllerResultV3,
    )
    def finalize_collector(collector_id: str) -> dict[str, object]:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", collector_id) is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="collector identity is invalid",
            )
        try:
            if authorization_guard is not None:
                authorization_guard()
            result = authority.finalize_collector(collector_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_acceptance_evidence",
                    "message": "acceptance evidence is invalid",
                },
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "acceptance_state_conflict",
                    "message": "acceptance state conflict",
                },
            ) from exc
        if not isinstance(result, dict):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="acceptance authority unavailable",
            )
        return result

    @app.get("/live", dependencies=[Depends(require_controller)])
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", dependencies=[Depends(require_controller)])
    def ready() -> dict[str, str]:
        try:
            if authorization_guard is not None:
                authorization_guard()
            authority.readiness_probe()
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="acceptance controller is not ready",
            ) from exc
        return {"status": "ready"}

    return app


def create_production_acceptance_controller_app() -> FastAPI:
    authority = build_production_acceptance_authority()
    if authority is None:
        raise RuntimeError("acceptance authority configuration is required")
    return create_acceptance_controller_app(
        authority=authority,
        controller_token=_read_controller_token(),
    )


def _require_distinct_v3_protected_roots(
    roots: tuple[tuple[str, Path], ...],
) -> None:
    identities: dict[tuple[int, int], str] = {}
    for label, path in roots:
        try:
            resolved = path.resolve(strict=True)
            metadata = path.stat()
        except OSError as exc:
            raise RuntimeError(
                f"acceptance V3 {label} root is unavailable"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not path.is_absolute()
            or path.is_symlink()
            or resolved != path
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise RuntimeError(
                f"acceptance V3 {label} root must be one exact directory"
            )
        previous = identities.get(identity)
        if previous is not None:
            raise RuntimeError(
                "acceptance V3 protected roots contain an inode alias: "
                f"{previous} and {label}"
            )
        identities[identity] = label


def create_production_acceptance_controller_v3_app() -> FastAPI:
    """Build the target-only V3 surface from protected provider-owned stores."""

    legacy_authority = build_production_acceptance_authority()
    if legacy_authority.signer is None or legacy_authority.trust_context is None:
        raise RuntimeError("acceptance V3 signing and trust authority are required")
    journal_path = Path(_required_environment("PILOT_ACCEPTANCE_JOURNAL_PATH"))
    snapshot_root = Path(_required_environment("PILOT_ACCEPTANCE_SNAPSHOT_DIR"))
    proof_root = Path(_required_environment("PILOT_ACCEPTANCE_PROOF_DIR"))
    channel_root = Path(_required_environment("PILOT_ACCEPTANCE_CHANNEL_DIR"))
    capture_root = Path(_required_environment("PILOT_ACCEPTANCE_CAPTURE_DIR"))
    _require_distinct_v3_protected_roots(
        (
            ("capture", capture_root),
            ("channel", channel_root),
            ("snapshot", snapshot_root),
            ("proof", proof_root),
        )
    )
    try:
        provider = ProtectedAcceptanceCaptureRepositoryV3(
            capture_root,
            trust_context=legacy_authority.trust_context,
        )
        snapshot_store = AcceptanceAuthoritySnapshotStoreV3(snapshot_root)
        proof_store = AcceptanceProofStoreV3(proof_root)
        state_store = AcceptanceAuthorityStateStoreV3(journal_path)
        authority = AcceptanceAuthorityV3(
            state_store=state_store,
            run_evidence_signer=legacy_authority.signer,
            acceptance_pass_signer=legacy_authority.signer,
        )
        controller = CollectorBoundAcceptanceControllerV3(
            provider=provider,
            snapshot_store=snapshot_store,
            authority=authority,
            proof_store=proof_store,
            trust_context=legacy_authority.trust_context,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("acceptance V3 protected stores are unavailable") from exc
    return create_acceptance_controller_app(
        authority=legacy_authority,
        v3_authority=controller,
        controller_token=_read_controller_token(),
        runtime_lock_path="/tmp/kuzet-acceptance-controller-v3.lock",
    )
