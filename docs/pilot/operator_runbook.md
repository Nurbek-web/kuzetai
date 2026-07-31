# Controlled-pilot operator runbook

Status: **PENDING implementation review and target acceptance**. This runbook
is for a controlled pilot, not production-ready. The deployment must remain
fail-closed until the Ready-to-Start and target acceptance records are
complete.

## Safety boundary

- Treat every alert as a **candidate** requiring **human confirmation**.
- Never use the service for automatic police, fire-system, or door actions.
- Continuous raw video stays in the customer NVR. Export only the bounded
  evidence and metadata attached to an event.
- X-CLIP, ViT violence, and heavy whole-frame OWLv2 analytics remain shadow
  signals until their independent site gates pass.
- Face matching, if a future approved phase enables it, is entrance-only and
  limited to a lawful customer-supplied gallery.

## Start and stop

Only a trained, named operator or deployment engineer may start the pilot.

1. Confirm the signed [Ready-to-Start gate](ready_to_start.md), handover
   manifest, camera manifest, model register, secret mounts, time
   synchronization, storage capacity, and notification allowlist.
2. Follow the [deployment runbook](deployment_runbook.md). Do not reuse an
   earlier acceptance report for a new image, configuration, model, engine,
   camera, or host.
3. Verify all named cameras are visible and the API reports the expected
   degraded/healthy state before operators begin review.
4. To stop, disable approved notification delivery, stop intake, allow queued
   candidates to reach a terminal audited state, then stop the compose project.
   Record who stopped it, why, and the final audit sequence.

Emergency containment may stop intake immediately, but it must not delete the
audit journal or evidence. See [incident response](incident_response.md).

## Candidate review

1. Compare the timestamp, camera identity, bounded evidence preview, rule, and
   reason with the customer NVR view.
2. Select confirm or reject and enter the required reason. The action is
   attributed to the authenticated operator.
3. Only a confirmed candidate may enter an approved notification outbox.
   Delivery does not replace the confirmation audit record.
4. If evidence is unavailable, keep the event in **evidence pending** or reject
   it according to site policy. Never confirm solely from a model score.
5. This package does not provide a general evidence-export workflow. Use the
   customer NVR/customer-controlled procedure unless a separately reviewed,
   audited bounded export is installed. For any approved export, record its
   digest, recipient, lawful purpose, approval, and expiry; never export
   continuous raw video from Kuzet storage.

## Degraded states

| State | Operator action |
|---|---|
| **source outage** | Check NVR/source health and network reachability; do not interpret missing candidates as a safe scene. Escalate if recovery exceeds the signed gate. |
| stale or malformed timestamps | Suspend that camera's analytic claims, compare NTP/NVR clocks, and retain diagnostics. |
| **evidence pending** | Do not notify; verify local/object storage and retry through the bounded workflow. |
| model/quality/capacity gate missing | Keep the analytic shadow or disabled. Do not override fail-closed status. |
| **notification failure** | Preserve the confirmed event and outbox audit; use the approved human fallback contact process without fabricating delivery. |
| queue pressure or scheduled drops | Mark service degraded, stop optional heavy analytics, and escalate if acceptance thresholds are exceeded. |

## Camera replacement

A camera replacement is a configuration and acceptance change, even if its
display name is unchanged. Freeze intake for the old source, preserve its audit
history, assign the replacement a new immutable source identity, and record
codec, resolution, FPS, bitrate, view, provenance, and source hash. Re-run
source profiling, privacy/view approval, site quality checks, configuration
hashing, and the applicable capacity gate before enabling operator analytics.
Never silently redirect an accepted camera ID to a new RTSP source.

## Credentials, backup, restore, and rollback

- Rotate API, notification, storage, database, signing, and backup credentials
  through mounted secrets; never commit them. Record the rotation and revoke
  the previous material.
- Run the repository backup and restore-drill scripts from the deployment
  runbook. A backup without a verified restore is not accepted.
- Roll back only to digest-pinned containers, migration-compatible schema,
  configuration, engines, and model artifacts recorded in the handover
  manifest. Any changed workload requires new acceptance evidence.

## Operator drill and escalation

Before handover, every named operator must complete every drill below on the
reviewed training site. Use synthetic candidate identities and bounded
evidence; never stage an actual emergency or send an unapproved notification.
The required source-outage, evidence-pending, and notification-failure
scenarios are recorded as separate drill receipts.

| Drill | Required action and evidence | Pass condition |
|---|---|---|
| confirmed candidate | Compare source time/camera/evidence with the customer NVR, confirm once, and inspect review/audit/outbox state. | One attributed review; at most one eligible outbox row; no autonomous action. |
| rejected candidate | Reject with a bounded reason and retry the same idempotency key. | One attributed rejection; no notification eligibility. |
| source outage and return | Disconnect one reviewed replay/source, observe degraded state, restore it, and retain the other 19 camera states. | No cross-camera state change; recovery time is measured, not assumed. |
| evidence pending/failure | Hold or fail bounded evidence publication and attempt review. | Operator does not confirm from model confidence alone; failure remains visible and audited. |
| notification failure | Use a confirmed synthetic candidate with the connector failure fixture. | Durable failed/dead-letter evidence and the approved human fallback; no fabricated delivery. |
| storage-policy drift | Suspend versioning/lifecycle or deny a conditional-create probe in the isolated storage test fixture. | Runtime/retention fails closed; no overwrite or broad delete occurs. |
| role-membership drift | Add a forbidden test membership only in the disposable PostgreSQL drill and rerun role bootstrap/probes. | Drift is detected; service identity cannot `SET ROLE`; the disposable role is restored before teardown. |
| retention backlog | Use the signed batch-plus-one retention fixture from the deployment runbook. | Per-cycle evidence is new, signed, and non-overwriting; evidence/audit/registered-preview classes stay within bounds. Orphan and aggregate verdicts remain blocked until the bounded orphan-version instrumentation exists. |

For each drill record the campaign/configuration digest, trainer, named
operator, UTC start/end, synthetic fixture digest, expected and observed
result, audit IDs, remediation, and trainer/operator signatures. Site security
remains responsible for real-world escalation under customer policy;
technical support handles runtime health and evidence integrity.

## Per-shift checks

At shift start and after any deployment or policy change:

1. Match source commit, rendered Compose digest, active configuration digest,
   migration revision, model/engine hashes, and image digests to the handover
   manifest.
2. Confirm the exact database login identity and the archived zero-membership/
   non-ownership probe for `kuzet_api`, `kuzet_runtime`, and
   `kuzet_retention`.
3. Confirm object versioning remains enabled, exact lifecycle mappings match
   the reviewed digests, and the conditional-create policy plus positive and
   negative S3 probes are current.
4. Inspect evidence, preview, and audit-retention arrival versus drain,
   backlog depth, and oldest eligible age. Inspect orphan-version evidence as
   a separate class and the signed audit/cycle receipt-root quota and campaign
   forecast. A missing measurement, increasing backlog, failed batch, forecast
   breach, orphan instrumentation blocker, or policy drift is a degraded state
   and blocks activation.
5. Confirm only approved overlays and egress networks are present. Telegram
   remains absent unless both customer and network approvals are signed.

## Support roster

This roster **must be completed before activation** and copied into the
customer-controlled incident system. Do not put personal credentials or secret
tokens in this repository.

| Required route | Named owner and tested contact path | Status |
|---|---|---|
| Customer site security contact | Name, staffed telephone/radio route, and fallback | PENDING |
| Customer privacy/security contact | Name, incident-system queue, and urgent fallback | PENDING |
| Customer infrastructure contact | Name and NVR/network/NTP escalation route | PENDING |
| Kuzet technical incident contact | Name, support queue, telephone route, and fallback | PENDING |
| Kuzet deployment owner | Name and change/rollback approval route | PENDING |
| Approved notification-channel owner | Name and provider escalation route | PENDING |

Each route must be tested during the operator drill. A notification failure
uses the customer-approved fallback route; it never triggers an unapproved
automatic destination.
