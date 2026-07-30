# Controlled-pilot operator runbook

Status: **PENDING target acceptance**. This runbook is for a controlled pilot,
not production-ready. The deployment must remain fail-closed until
the Ready-to-Start and target acceptance records are complete.

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
5. Export an evidence package only through the audited export flow. Record its
   digest, recipient, lawful purpose, and expiry.

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

Before handover, every named operator must demonstrate confirmed, rejected,
source-outage, evidence-pending, and notification-failure scenarios. Record the
trainer, operator, time, outcome, and remediation. Site security remains
responsible for real-world escalation under customer policy; technical support
handles runtime health and evidence integrity.

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
