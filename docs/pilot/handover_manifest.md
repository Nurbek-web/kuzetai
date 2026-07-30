# Controlled-pilot handover manifest

Overall status: **PENDING**. Fill this from measured, signed target evidence.
Never replace PENDING with expected, example, demo, or Apple-host results. Each
completed row needs a named operator or named reviewer and UTC date.

| Item | Bound value / artifact | Status | Named operator/reviewer | Date |
|---|---|---|---|---|
| DeepStream runtime container digest | — | PENDING | — | — |
| API/controller container digest | — | PENDING | — | — |
| Operations image container digest | — | PENDING | — | — |
| Postgres container digest | — | PENDING | — | — |
| Nginx TLS proxy container digest | — | PENDING | — | — |
| Prometheus container digest | — | PENDING | — | — |
| Every optional overlay/service image digest | — | PENDING | — | — |
| Configuration hash | — | PENDING | — | — |
| Migration revision | — | PENDING | — | — |
| Exact 20-source manifest digest | — | PENDING | — | — |
| Model register and artifact/engine hashes | [model_register.md](model_register.md) | PENDING | — | — |
| 8-hour gate report and detached signature | — | PENDING | — | — |
| 72-hour gate report and detached signature | — | PENDING | — | — |
| Fire/weapon field matrix | — | PENDING | — | — |
| Network-policy review | — | PENDING | — | — |
| Audit-retention review | — | PENDING | — | — |
| Backup and restore-drill report | — | PENDING | — | — |
| Operator training records | — | PENDING | — | — |
| Signed exception list | — | PENDING | — | — |

## Required sign-off

- Customer pilot owner: PENDING
- Customer privacy/security owner: PENDING
- Kuzet deployment owner: PENDING
- Kuzet engineering reviewer: PENDING
- Named operator roster and human-confirmation drill: PENDING

The manifest is not an authorization by itself. The underlying signed gate
reports, hashes, audit proof, quality matrices, and source-profile evidence must
all validate against the same frozen campaign.
