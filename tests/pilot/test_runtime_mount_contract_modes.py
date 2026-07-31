"""Executable acceptance/production mount-mode contract tests.

This suite deliberately uses only the standard library plus the configuration
model dependencies already needed by the mount validator.  It does not start
Docker or claim NVIDIA acceptance.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from protector.pilot.config import (
    CameraFeed,
    EvidenceRetention,
    KazakhstanStorage,
    QueueLimits,
    ReadyToStart,
    Resolution,
    SecretReference,
    SiteConfig,
)
from protector.pilot.runtime.mount_contract import (
    RuntimeBindMountV1,
    RuntimeMountContractV1,
    validate_runtime_mount_contract,
)


class RuntimeMountContractModeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime_uid = os.geteuid() or 10_001
        self.runtime_gid = os.getegid() or 10_001
        self._runtime_owned_paths: set[Path] = set()
        self.site = self._site()

        targets = {
            "site.yaml": Path("/run/config/site.yaml"),
            "runtime.yaml": Path("/run/config/runtime-manifest.yaml"),
            "capacity.yaml": Path("/run/config/measured-capacity.yaml"),
            "capacity.sig": Path("/run/config/measured-capacity.sig"),
            "capacity.pem": Path("/run/config/capacity-authority.pem"),
            "machine_token": Path("/run/secrets/machine_token"),
            "person.onnx": Path("/run/runtime/person.onnx"),
            "person.engine": Path("/run/runtime/person.engine"),
            "person.txt": Path("/run/runtime/person.txt"),
        }
        self.sources = {
            name: self._file(name, f"bounded-{name}".encode())
            for name in targets
        }
        self.spool = self._private_directory("spool")
        mounts = [
            RuntimeBindMountV1(
                source=self.sources[name],
                target=target,
                kind="file",
                read_only=True,
            )
            for name, target in targets.items()
        ]
        mounts.append(
            RuntimeBindMountV1(
                source=self.spool,
                target=Path("/srv/kuzet/evidence-spool"),
                kind="directory",
                read_only=False,
            )
        )
        for index in range(1, 21):
            source = self._file(
                f"camera_{index:02d}_rtsp",
                f"rtsp://fixture-{index:02d}".encode(),
            )
            mounts.append(
                RuntimeBindMountV1(
                    source=source,
                    target=Path(f"/run/secrets/camera_{index:02d}_rtsp"),
                    kind="file",
                    read_only=True,
                )
            )
        self.manifest = SimpleNamespace(
            artifact=SimpleNamespace(
                sha256=self._digest(self.sources["person.onnx"])
            ),
            artifact_path=Path("/run/runtime/person.onnx"),
            engine_sha256=self._digest(self.sources["person.engine"]),
            engine_path=Path("/run/runtime/person.engine"),
            nvinfer_config_sha256=self._digest(self.sources["person.txt"]),
            nvinfer_config_path=Path("/run/runtime/person.txt"),
        )
        self.acceptance = RuntimeMountContractV1(
            schema_version="runtime-mount-contract.v1",
            image_id=f"sha256:{'1' * 64}",
            mounts=tuple(mounts),
        )
        self.database = self._file(
            "runtime_database_url",
            b"postgresql+psycopg://runtime@example/pilot",
        )
        self.object_access = self._file(
            "runtime_object_store_access_key",
            b"object-access",
        )
        self.object_secret = self._file(
            "runtime_object_store_secret_key",
            b"object-secret",
        )
        self.journal = self._private_directory("runtime-journal")
        self.previews = self._private_directory("runtime-previews")
        production_mounts = (
            *(
                mount.model_copy(
                    update={
                        "storage_encryption_attested": True,
                        "storage_quota_bytes": 4 * 1024 * 1024 * 1024,
                    }
                )
                if mount.target == Path("/srv/kuzet/evidence-spool")
                else mount
                for mount in self.acceptance.mounts
            ),
            RuntimeBindMountV1(
                source=self.database,
                target=Path("/run/secrets/runtime_database_url"),
                kind="file",
                read_only=True,
            ),
            RuntimeBindMountV1(
                source=self.object_access,
                target=Path("/run/secrets/runtime_object_store_access_key"),
                kind="file",
                read_only=True,
            ),
            RuntimeBindMountV1(
                source=self.object_secret,
                target=Path("/run/secrets/runtime_object_store_secret_key"),
                kind="file",
                read_only=True,
            ),
            RuntimeBindMountV1(
                source=self.journal,
                target=Path("/var/lib/kuzet/journal"),
                kind="directory",
                read_only=False,
                storage_encryption_attested=True,
                storage_quota_bytes=512 * 1024 * 1024,
            ),
            RuntimeBindMountV1(
                source=self.previews,
                target=Path("/var/lib/kuzet/previews"),
                kind="directory",
                read_only=False,
                storage_encryption_attested=True,
                storage_quota_bytes=2 * 1024 * 1024 * 1024,
            ),
        )
        self.production = self.acceptance.model_copy(
            update={"mounts": production_mounts}
        )
        real_stat = Path.stat

        def stat_with_runtime_identity(
            path: Path,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            metadata = real_stat(path, *args, **kwargs)
            if path not in self._runtime_owned_paths:
                return metadata
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=self.runtime_uid,
                st_gid=self.runtime_gid,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
            )

        stat_patch = patch.object(
            Path,
            "stat",
            new=stat_with_runtime_identity,
        )
        stat_patch.start()
        self.addCleanup(stat_patch.stop)

    def _file(self, name: str, payload: bytes) -> Path:
        path = self.root / name
        path.write_bytes(payload)
        return path

    def _private_directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        self._runtime_owned_paths.add(path)
        return path

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _site() -> SiteConfig:
        feeds = tuple(
            CameraFeed(
                camera_id=f"camera-{index:02d}",
                source_index=index - 1,
                rtsp_url=SecretReference(
                    docker_secret=Path(
                        f"/run/secrets/camera_{index:02d}_rtsp"
                    )
                ),
                codec="h264",
                resolution=Resolution(width=1920, height=1080),
                fps=25.0,
                bitrate_kbps=2048,
                analytics_hz={"person": 5.0},
            )
            for index in range(1, 21)
        )
        return SiteConfig(
            ready_to_start=ReadyToStart(
                feeds=feeds,
                ntp_source="ntp.example.test",
                camera_map="camera-map-v1",
                site_access="approved",
                compute="nvidia-l4",
                notification_channel="human-confirmation",
                model_rights_decisions="model-register-v1",
            ),
            storage=KazakhstanStorage(
                country_code="KZ",
                endpoint="https://objects.example.test",
                bucket="pilot-evidence",
                retention=EvidenceRetention(
                    continuous_video_owner="customer_nvr",
                    continuous_video_storage_enabled=False,
                    encoded_ring_buffer_seconds=15,
                    evidence_retention_days=30,
                    metadata_retention_days=90,
                ),
            ),
            queues=QueueLimits(
                decode=8,
                analytics=16,
                verifier=4,
                events=16,
            ),
        )

    def _arguments(
        self,
        contract: RuntimeMountContractV1,
    ) -> dict[str, Any]:
        return {
            "site_config": self.site,
            "runtime_manifest": self.manifest,
            "contract": contract,
            "expected_image_id": contract.image_id,
            "site_config_source": self.sources["site.yaml"],
            "runtime_manifest_source": self.sources["runtime.yaml"],
            "measured_capacity_source": self.sources["capacity.yaml"],
            "measured_capacity_signature_source": self.sources["capacity.sig"],
            "capacity_authority_public_key_source": self.sources["capacity.pem"],
            "runtime_uid": self.runtime_uid,
            "runtime_gid": self.runtime_gid,
        }

    def _production_arguments(self) -> dict[str, Path]:
        return {
            "database_url_secret_source": self.database,
            "object_store_access_key_secret_source": self.object_access,
            "object_store_secret_key_secret_source": self.object_secret,
            "runtime_journal_source": self.journal,
            "runtime_preview_source": self.previews,
        }

    @staticmethod
    def _replace_source(
        contract: RuntimeMountContractV1,
        *,
        target: Path,
        source: Path,
    ) -> RuntimeMountContractV1:
        return contract.model_copy(
            update={
                "mounts": tuple(
                    mount.model_copy(update={"source": source})
                    if mount.target == target
                    else mount
                    for mount in contract.mounts
                )
            }
        )

    def test_acceptance_mode_remains_exactly_30_mounts_and_60_argv(self) -> None:
        argv = validate_runtime_mount_contract(
            **self._arguments(self.acceptance)
        )

        self.assertEqual(len(self.acceptance.mounts), 30)
        self.assertEqual(len(argv), 60)
        self.assertNotIn("runtime_database_url", "\n".join(argv))

    def test_complete_production_mode_is_exactly_35_mounts_and_70_argv(
        self,
    ) -> None:
        argv = validate_runtime_mount_contract(
            **self._arguments(self.production),
            **self._production_arguments(),
        )

        self.assertEqual(len(self.production.mounts), 35)
        self.assertEqual(len(argv), 70)
        rendered = "\n".join(argv)
        self.assertIn("dst=/var/lib/kuzet/journal", rendered)
        self.assertIn("dst=/var/lib/kuzet/previews", rendered)
        self.assertNotIn("rtsp://", rendered)

    def test_partial_production_authority_is_rejected(self) -> None:
        cases = (
            {"database_url_secret_source": self.database},
            {
                "database_url_secret_source": self.database,
                "object_store_access_key_secret_source": self.object_access,
                "object_store_secret_key_secret_source": self.object_secret,
            },
            {"runtime_journal_source": self.journal},
        )
        for supplied in cases:
            with self.subTest(supplied=tuple(supplied)):
                with self.assertRaisesRegex(ValueError, "supplied together"):
                    validate_runtime_mount_contract(
                        **self._arguments(self.acceptance),
                        **supplied,
                    )

    def test_production_storage_requires_attestation_and_private_mode(
        self,
    ) -> None:
        unattested = self.production.model_copy(
            update={
                "mounts": tuple(
                    mount.model_copy(
                        update={
                            "storage_encryption_attested": False,
                            "storage_quota_bytes": None,
                        }
                    )
                    if mount.target == Path("/srv/kuzet/evidence-spool")
                    else mount
                    for mount in self.production.mounts
                )
            }
        )
        with self.assertRaisesRegex(ValueError, "encryption and quota"):
            validate_runtime_mount_contract(
                **self._arguments(unattested),
                **self._production_arguments(),
            )

        unsafe = self._private_directory("unsafe-previews")
        unsafe.chmod(0o755)
        unsafe_contract = self._replace_source(
            self.production,
            target=Path("/var/lib/kuzet/previews"),
            source=unsafe,
        )
        with self.assertRaisesRegex(ValueError, "private and owned"):
            validate_runtime_mount_contract(
                **self._arguments(unsafe_contract),
                **(
                    self._production_arguments()
                    | {"runtime_preview_source": unsafe}
                ),
            )

    def test_production_sources_reject_equal_and_nested_paths(self) -> None:
        duplicate = self._replace_source(
            self.production,
            target=Path("/run/secrets/runtime_database_url"),
            source=self.sources["site.yaml"],
        )
        with self.assertRaisesRegex(ValueError, "unique and disjoint"):
            validate_runtime_mount_contract(
                **self._arguments(duplicate),
                **self._production_arguments(),
            )

        nested = self.journal / "nested-previews"
        nested.mkdir(mode=0o700)
        self._runtime_owned_paths.add(nested)
        nested_contract = self._replace_source(
            self.production,
            target=Path("/var/lib/kuzet/previews"),
            source=nested,
        )
        with self.assertRaisesRegex(ValueError, "unique and disjoint"):
            validate_runtime_mount_contract(
                **self._arguments(nested_contract),
                **(
                    self._production_arguments()
                    | {"runtime_preview_source": nested}
                ),
            )

    def test_production_sources_reject_hardlink_inode_aliases(self) -> None:
        hardlinked_database = self.root / "hardlinked-runtime-database"
        os.link(self.sources["site.yaml"], hardlinked_database)
        aliased = self._replace_source(
            self.production,
            target=Path("/run/secrets/runtime_database_url"),
            source=hardlinked_database,
        )

        with self.assertRaisesRegex(ValueError, "unique and disjoint"):
            validate_runtime_mount_contract(
                **self._arguments(aliased),
                **(
                    self._production_arguments()
                    | {"database_url_secret_source": hardlinked_database}
                ),
            )

    def test_production_spool_target_cannot_overlap_fixed_runtime_storage(
        self,
    ) -> None:
        for target in (
            Path("/var/lib/kuzet/journal"),
            Path("/var/lib/kuzet"),
        ):
            unsafe_site = self.site.model_copy(
                update={
                    "storage": self.site.storage.model_copy(
                        update={
                            "retention": (
                                self.site.storage.retention.model_copy(
                                    update={"encoded_spool_root": target}
                                )
                            )
                        }
                    )
                }
            )
            arguments = self._arguments(self.production)
            arguments["site_config"] = unsafe_site
            with self.subTest(target=target):
                with self.assertRaisesRegex(
                    ValueError,
                    "production evidence spool target",
                ):
                    validate_runtime_mount_contract(
                        **arguments,
                        **self._production_arguments(),
                    )

    def test_storage_attestation_rejects_boolean_quota(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid integer"):
            RuntimeBindMountV1(
                source=self.journal,
                target=Path("/var/lib/kuzet/other"),
                kind="directory",
                read_only=False,
                storage_encryption_attested=True,
                storage_quota_bytes=True,  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
