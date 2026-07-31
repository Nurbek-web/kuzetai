# Controlled-pilot handover manifest

Overall status: **PENDING implementation review and external execution**. This
inventory is completed only from measured, signed target evidence. Never
replace `PENDING` with an expected value, demo result, portable replay,
development-host result, hardware specification, mutable tag, or unsigned
operator assertion.

Each completed row needs the exact immutable value or artifact, a named
operator or reviewer, and an ISO-8601 UTC date. One missing mandatory row keeps
the controlled pilot disabled or shadow-only.

## Source and packaged images

| Item | Bound value / artifact | Status | Named operator/reviewer | UTC date |
|---|---|---|---|---|
| Repository source commit | — | PENDING | — | — |
| Clean source-tree/archive SHA-256 | — | PENDING | — | — |
| API/controller linux/amd64 container digest | — | PENDING | — | — |
| DeepStream runtime linux/amd64 container digest | — | PENDING | — | — |
| Operations image linux/amd64 container digest | — | PENDING | — | — |
| PostgreSQL container digest | — | PENDING | — | — |
| Nginx TLS proxy container digest | — | PENDING | — | — |
| Prometheus container digest | — | PENDING | — | — |
| Base Compose rendered inventory SHA-256 | — | PENDING | — | — |
| Runtime overlay rendered inventory SHA-256 | — | PENDING | — | — |
| Acceptance overlay rendered inventory SHA-256 | — | PENDING | — | — |
| Telegram overlay rendered inventory SHA-256 or disabled decision | — | PENDING | — | — |
| Backup overlay rendered inventory SHA-256 | — | PENDING | — | — |
| Restore overlay rendered inventory SHA-256 | — | PENDING | — | — |
| Administrator-bootstrap overlay rendered inventory SHA-256 | — | PENDING | — | — |
| Image provenance/SBOM archive | — | PENDING | — | — |
| Runtime package/tool version manifests and hashes | — | PENDING | — | — |
| Operations package/Python lock version manifests and hashes | — | PENDING | — | — |

Record registry-resolved `sha256:` content digests. Tags alone do not satisfy
an image row. Rendered inventories must redact secret bytes without removing
secret identifiers, mounts, networks, limits, or service arguments.

## Configuration, sources, models, and capacity

| Item | Bound value / artifact | Status | Named operator/reviewer | UTC date |
|---|---|---|---|---|
| Site configuration SHA-256 | — | PENDING | — | — |
| Runtime manifest SHA-256 | — | PENDING | — | — |
| Runtime mount-contract SHA-256 | — | PENDING | — | — |
| Runtime image ID/config/code SHA-256 tuple | — | PENDING | — | — |
| Reviewed GPU UUID | — | PENDING | — | — |
| NVIDIA driver version | — | PENDING | — | — |
| NVIDIA container-toolkit version/configuration hash | — | PENDING | — | — |
| Single-GPU Compose binding and rendered SHA-256 | — | PENDING | — | — |
| Expected/live migration revision/head (`0008_runtime_persistence`) and online-migration receipt | — | PENDING | — | — |
| Exact signed 20-source manifest digest | — | PENDING | — | — |
| Exact 20 camera Docker-secret name/path inventory | — | PENDING | — | — |
| Exact camera/control network IDs and configuration hashes | — | PENDING | — | — |
| Camera source-profile and site-quality evidence | — | PENDING | — | — |
| Model register and artifact/engine hashes | [model_register.md](model_register.md) | PENDING | — | — |
| Digest-pinned model builder image/entrypoint/mount-contract implementation review | — | PENDING | — | — |
| Model export-audit, engine-build, and deployment-audit receipt hashes | — | PENDING | — | — |
| Signed measured-capacity report and signature | — | PENDING | — | — |
| Measured effective-throughput headroom (minimum 25%) | — | PENDING | — | — |
| Fire site field matrix and decision | — | PENDING | — | — |
| Weapon site field matrix and decision | — | PENDING | — | — |
| Violence X-CLIP/ViT shadow decision | — | PENDING | — | — |
| Whole-frame OWLv2 shadow decision | — | PENDING | — | — |

There is no universal cameras-per-GPU coefficient. The headroom row requires
the exact frozen target workload and effective measured throughput.

## Security, storage, and operations

| Item | Bound value / artifact | Status | Named operator/reviewer | UTC date |
|---|---|---|---|---|
| Network-policy review and firewall evidence | — | PENDING | — | — |
| Kazakhstan storage residency/endpoint evidence | — | PENDING | — | — |
| Signed site/campaign/prefix/path storage-probe binding and SHA-256 | — | PENDING | — | — |
| Runtime spool quota/encryption/attestation | — | PENDING | — | — |
| Runtime journal quota/encryption/attestation | — | PENDING | — | — |
| Runtime preview quota/encryption/attestation | — | PENDING | — | — |
| Acceptance state/snapshot/proof/channel ownership and bounds | — | PENDING | — | — |
| Audit-retention review | — | PENDING | — | — |
| External secret inventory and rotation identifiers | — | PENDING | — | — |
| Service-role zero-membership/non-ownership/unprivileged catalog receipt | — | PENDING | — | — |
| API/runtime/retention exact `session_user`/`current_user` and denied `SET ROLE` receipt | — | PENDING | — | — |
| Effective bucket/resource conditional-create policy and canonical SHA-256 | — | PENDING | — | — |
| Versioning and exact lifecycle canonical JSON/SHA-256 | — | PENDING | — | — |
| Hourly policy/versioning/lifecycle drift-monitor and provider-actor-log receipt | — | PENDING | — | — |
| Evidence writer three-way conditional-create/overwrite/current-object receipt | — | PENDING | — | — |
| Preview writer three-way conditional-create/overwrite/current-object receipt | — | PENDING | — | — |
| Audit-archive writer three-way conditional-create/overwrite/current-object receipt | — | PENDING | — | — |
| Signed/verified exact-version delete, absence, cleanup, and storage-authority receipts | — | PENDING | — | — |
| API preview DB/S3 ACL receipt | — | PENDING | — | — |
| Runtime writer DB/S3 ACL receipt | — | PENDING | — | — |
| Retention DB/S3 ACL receipt | — | PENDING | — | — |
| Backup DB/S3 ACL receipt | — | PENDING | — | — |
| Notification DB/link ACL receipt | — | PENDING | — | — |
| Restore DB/storage ACL receipt | — | PENDING | — | — |
| Migration/provision/admin-bootstrap DB ACL receipts | — | PENDING | — | — |
| TLS certificate identity and expiry | — | PENDING | — | — |
| First-administrator bootstrap/revocation audit | — | PENDING | — | — |
| Telegram customer/network approval or disabled decision | — | PENDING | — | — |
| Signed encrypted backup report | — | PENDING | — | — |
| Signed fresh-target restore receipt | — | PENDING | — | — |
| Pre-migration backup and fresh-target restore rehearsal receipt | — | PENDING | — | — |
| Rollback image/config/model/engine/migration digest bundle and endpoint-switch approval | — | PENDING | — | — |
| Signed retention batch-plus-one fixture manifest | — | PENDING | — | — |
| Evidence arrival/drain/depth/oldest-age six-cycle receipt | — | PENDING | — | — |
| Audit arrival/drain/depth/oldest-age six-cycle receipt and irreducible-root record | — | PENDING | — | — |
| Audit/cycle receipt-root per-cycle bounds, quota, campaign forecast, lifecycle, and alert receipt | — | PENDING | — | — |
| Registered-preview arrival/drain/depth/oldest-age six-cycle receipt | — | PENDING | — | — |
| Orphan-preview bounded inventory instrumentation review and six-cycle arrival/drain/depth/oldest-age receipt | — | PENDING | — | — |

The API preview credentials must be distinct, read-only object-store
credentials. Runtime/retention/backup writer credentials do not satisfy that
row and must never be granted to the API. The receipt must show only
prefix-scoped `s3:GetObjectVersion`, bucket-level read-only
`s3:GetBucketVersioning`/`s3:GetLifecycleConfiguration`, and negative
current-object/list/write/delete/mutation probes. With `aws:kms`, it must also
show only key-scoped `kms:GenerateDataKey`/`kms:Decrypt`. The link-signing key
is deliberately shared only by the API and notification worker and is never
a machine credential.

The runtime writer identity receipt must separately show bucket
`s3:GetBucketVersioning`/`s3:GetLifecycleConfiguration`, reviewed-prefix
`s3:GetObject`/`s3:PutObject`, no `s3:GetObjectVersion`, exact current
retention with `NoncurrentDays=1`, and negative named-version
read/list/delete/cross-prefix/bucket-mutation probes. The retention identity
receipt must show the same bucket reads, prefix-conditioned
`s3:ListBucketVersions`, evidence-prefix
`s3:GetObjectVersion`/`s3:DeleteObjectVersion`, and separate archive-prefix
`s3:GetObject`/`s3:PutObject`, with negative simple-delete, evidence-write,
archive-delete, cross-prefix, lifecycle/versioning, and ACL probes. For
`aws:kms`, the runtime and retention receipts must bind only the reviewed key
and the necessary
`kms:GenerateDataKey`/`kms:Decrypt` operations.

For each of evidence, preview, and audit archive, the effective bucket/resource
policy must require `s3:if-none-match` equal to `*` (or a documented provider
equivalent with the same atomic and authorization semantics). Its three-way
receipt must prove: conditional create succeeds; the same key, changed bytes,
and changed metadata with `If-None-Match: *` fails with provider HTTP 409/412;
the overwrite without the header fails authorization with HTTP 403; and exact
HEAD/current GET/named-version GET prove the original bytes and metadata remain
current and unchanged. A 409/412 alone does not prove policy enforcement. If
the Kazakhstan provider cannot enforce the 403 boundary, storage acceptance
remains blocked.

The database ACL receipts must also prove exact process identities before any
domain access: `kuzet_api` for API, `kuzet_runtime` for runtime, and
`kuzet_retention` for both retention connections. Owner, migrator, or another
service URL is a failed probe, not an acceptable substitute. `NOINHERIT` alone
does not pass: every service role must have zero direct memberships, zero
database/schema/relation/routine ownership, no privileged role flag, and a
failed `SET ROLE kuzet_owner` probe.

The retention receipts must use database-clock eligibility and bind their
signed fixture, object versions, configured batches, policy/lifecycle digests,
and cycle outputs. Registered retirement and orphan preview deletion are
measured independently. Required targets are no failed batch, batch-plus-one
clearance within two cycles, cumulative drain at least cumulative eligible
arrival after the seed clears, measured drain capacity at least 125% of
arrival while a backlog exists, non-growing ending depth, and oldest eligible
age no greater than two 3,600-second cycles. Process uptime is not a result.
Each cycle must publish into a new non-overwriting directory and have a
detached verified signature. Because the current snapshot does not instrument
unregistered orphan versions, the orphan and aggregate rows remain blocked on
implementation review. Irreducible signed receipt roots must pass the reviewed
bytes/files-per-cycle and full-campaign quota forecast; monotonic receipt-root
existence is not itself a retention failure.

## Acceptance and handover evidence

| Item | Bound value / artifact | Status | Named operator/reviewer | UTC date |
|---|---|---|---|---|
| Ready-to-Start record | [ready_to_start.md](ready_to_start.md) | PENDING | — | — |
| V3 runner/controller/finalize-route correspondence implementation review | `scripts/pilot/replay_20.py`; `protector/pilot/acceptance_campaign.py`; `protector/pilot/acceptance_controller_v3.py`; focused tests | REVIEWED LOCALLY; TARGET NOT RUN | — | — |
| Runtime-restart append-only execution/epoch/continuation/C2 implementation proof | transition journal, three-epoch/channel/source-profile binding, authenticated collector acknowledgement, focused tests | REVIEWED LOCALLY; TARGET NOT RUN | — | — |
| Parser-tested exact 8-hour command and SHA-256 | — | PENDING | — | — |
| Parser-tested exact 72-hour command and SHA-256 | — | PENDING | — | — |
| Signed acceptance fixture/mount/nonce/channel inventory SHA-256 | — | PENDING | — | — |
| Signed 8-hour gate report and detached signature | — | PENDING | — | — |
| Signed 8-hour V3 snapshot/proof/channel evidence | — | PENDING | — | — |
| Signed 72-hour gate report and detached signature | — | PENDING | — | — |
| Signed 72-hour V3 snapshot/proof/channel evidence | — | PENDING | — | — |
| Raw bounded metrics and fault/recovery traces | — | PENDING | — | — |
| Cross-camera isolation evidence | — | PENDING | — | — |
| Human-confirmation/notification eligibility evidence | — | PENDING | — | — |
| Named operator drill roster, fixture digest, audit IDs, and signatures | — | PENDING | — | — |
| Confirmed/rejected candidate drill receipts | — | PENDING | — | — |
| Source-outage/evidence-pending/notification-failure drill receipts | — | PENDING | — | — |
| Storage-policy/role-drift/retention-backlog drill receipts | — | PENDING | — | — |
| Completed support roster and tested routes | — | PENDING | — | — |
| Signed exception list | — | PENDING | — | — |
| Final regression/test report | — | PENDING | — | — |

The retained-runtime continuation and runner/controller correspondence are
implemented and reviewed locally. The parser-matched command contracts are now
recorded in `ready_to_start.md`, but neither gate has run on the required
Linux/NVIDIA host and lawful exact-20 sources. Command digests, signed fixture
inventory, CUDA/DeepStream/TensorRT observations, GPU measurements, 8-hour and
72-hour reports, and exact-20 evidence therefore remain `PENDING`/`NOT RUN`.
The manifest must not treat a documented command or local fake/replay test as
target execution.

## Required sign-off

- Customer pilot owner: PENDING
- Customer privacy/security owner: PENDING
- Customer infrastructure/network owner: PENDING
- Kuzet deployment owner: PENDING
- Kuzet engineering reviewer: PENDING
- Named operator roster and human-confirmation drill: PENDING
- Backup/restore drill reviewer: PENDING
- Final controlled-pilot activation decision: PENDING

The manifest is an index, not an authorization by itself. Underlying signed
gate reports, hashes, audit proof, quality matrices, source profiles, restore
receipt, and approvals must all validate against the same frozen campaign.
Human confirmation remains mandatory for every alert candidate.
