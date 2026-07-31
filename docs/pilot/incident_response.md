# Controlled-pilot incident response

Status: **PENDING target acceptance**. Preserve safety, auditability, and
customer control. **No automatic police**, fire-service, fire-system, or door
action is permitted.

## First response

1. Protect people using the customer's established emergency procedures,
   independent of Kuzet AI.
2. Record UTC/local time, named operator, affected cameras, candidate IDs,
   service version, and the first observed symptom.
3. Choose reversible **containment**: disable notification delivery, isolate a
   failed source, pause optional analytics, or stop intake. Do not erase the
   journal, database, logs, or bounded evidence.
4. Preserve the relevant audit chain, configuration and image digests,
   metrics, exception records, bounded event evidence, and customer NVR
   references.

## Severity guide

- **Safety workflow:** notification occurred before confirmation, unauthorized
  state transition, or an operator cannot review a candidate.
- **Evidence/audit:** evidence missing or mismatched, journal/proof failure,
  cross-camera attribution, or clock/source identity ambiguity.
- **Availability/capacity:** source recovery breach, crash/OOM, queue or disk
  growth, scheduled-drop breach, or GPU headroom breach.
- **Security/privacy:** credential exposure, unauthorized access/export,
  unexpected egress, raw-video retention outside the customer NVR, or
  unapproved face/gallery use.

Treat safety, evidence/audit, and security/privacy incidents as critical until
triage proves otherwise.

## Scenario actions

### Notification before confirmation

Disable the channel, preserve outbox and delivery records, identify the exact
candidate and transition chain, notify the customer incident owner, and keep
the channel disabled until an independent review and regression test pass.

### Evidence missing or mismatched

Keep the candidate unconfirmed or evidence pending, quarantine the affected
evidence object without deleting it, compare its digest and source/camera
identity with the audit record, and use the customer NVR for human assessment.

### Source outage or cross-camera attribution

Mark affected views degraded. Stop claims for ambiguous camera identities,
preserve source supervision and timestamp diagnostics, and re-profile any
replaced source before resuming.

### Capacity, crash, or storage pressure

Stop optional shadow analytics first, then stop intake if boundedness is at
risk. Preserve metrics and crash artifacts. Never increase queue/disk limits or
reduce required headroom merely to obtain a pass.

### Retention backlog or object-policy drift

Disable new event publication if the reviewed storage policy no longer
enforces conditional create, bucket versioning is not `Enabled`, lifecycle
rules drift, an unconditional overwrite succeeds, or exact-version deletion
cannot be proved. Preserve the effective policy, version/lifecycle responses,
positive conditional-PUT and negative unconditional-overwrite probes, object
version inventory, and database-clock retention snapshots. Do not “repair” the
incident by broad deletion.

For evidence, preview, and audit archive separately, compare eligible arrivals,
successful drains, backlog depth, and oldest eligible age against the signed
target. A service process that stayed alive is not proof of drain. If the
oldest age or backlog grows, keep the pilot degraded, stop optional producers,
and use the customer NVR while the storage and database owners investigate.
Preserve every non-overwriting signed cycle receipt and its campaign binding.
Track irreducible audit/cycle receipt roots against their byte/file quota and
full-campaign forecast rather than expecting them to drain to zero. Missing
bounded orphan-version instrumentation or any forecast breach blocks aggregate
retention recovery.

### Database role or membership drift

Stop the affected service when `session_user` or `current_user` differs from
its exact service role, a service role has any direct role membership, owns a
database/schema/relation/routine, gains a privileged flag, or can `SET ROLE`.
Archive the admin-side catalog probe and the service-side negative probe.
Re-run the reviewed role bootstrap and grants only after root-cause analysis;
never substitute owner or migrator credentials for a service URL.

### Credential or privacy incident

Revoke affected credentials, contain egress, preserve access/export logs, and
involve the customer's privacy/security owner. Do not add external watchlists
or scrape face data.

## Recovery and closure

Recovery requires root cause, a tested corrective action, intact audit and
evidence chains, credential rotation where applicable, and customer approval.
Re-run every invalidated gate on a fresh target or fresh acceptance campaign.
Document owner, timeline, impact, notification, containment, recovery evidence,
exceptions, and follow-up. A model score or dashboard screenshot is not closure.
