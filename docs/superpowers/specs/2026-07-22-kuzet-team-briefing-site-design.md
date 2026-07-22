# Kuzet AI Teammate Briefing Site Design

Date: 2026-07-22

## Purpose

Create a self-contained Russian briefing that Nurbek can send to teammates who understand basic computer science but are not specialists in computer vision, model deployment, infrastructure, or AI product delivery. The audience also includes a business teammate.

The briefing must explain the project and the required work, not revolve around a deadline. It must be comprehensive without reading like a tender response or engineering audit. After one pass, a reader must be able to answer these questions correctly:

1. What problem is the customer asking Kuzet AI to solve?
2. What are the actual functional and non-functional requirements?
3. What does Kuzet AI already have, and what still has to be built or replaced?
4. Which implementation workstreams make up the real project?
5. How do the cameras, AI models, event logic, evidence, dashboard, security, and operator workflow connect?
6. Which capabilities are straightforward, conditional on testing/licensing, or inappropriate to promise?
7. What equipment, people, dependencies, acceptance tests, and budget are required?

The 20-day period is a constraint and a planning guideline. It is not the main information architecture of the briefing. The site may show an indicative work sequence, but it must organise the project around requirements, components, deliverables, and proof of completion.

## Deliverables

1. A responsive, publicly shareable Russian website that does not require login.
2. A downloadable Russian PDF that follows the same information structure.
3. Download links to the meeting offer and repository-specific implementation plan.

The website is the primary reading experience. The PDF is an offline/shareable companion, not a second contradictory source of truth.

## Content authority

The site consolidates and normalizes the following approved sources:

- `deliverables/kuzet_20_camera/Kuzet_AI_Final_Meeting_Offer_RU.docx`
- `deliverables/kuzet_20_camera/Kuzet_AI_20_Camera_Technical_Commercial_Proposal_RU.docx`
- `deliverables/kuzet_20_camera/Kuzet_AI_Internal_Readiness_and_Delivery_Plan_RU.docx`
- `docs/superpowers/specs/2026-07-22-kuzet-20-camera-pilot-design.md`
- `docs/superpowers/plans/2026-07-22-kuzet-20-camera-pilot.md`
- the supplied customer specification `ТС ВИДЕО ру каз услуга.docx`

Where older materials conflict with the approved meeting position, the site uses the approved controlled-pilot position:

- **19.8 million KZT excluding VAT** is the fixed software/integration price for the bounded 20-day pilot.
- **Up to 20.6 million KZT** is the indicative first-month Kazakhstan-cloud envelope.
- **Up to 31.3 million KZT** is the indicative on-premises envelope with an L4 server allowance.
- The 12–20-week and 6–12-month estimates describe later production hardening, broader OEM/VMS integration, certification, high availability, or the full original specification. They are not alternative prices for the same controlled pilot.

Requirements are the primary organising unit. Each requirement must state: why it exists, current readiness, required implementation, dependencies, and how completion will be verified. Dates appear only where they explain sequencing or a contractual constraint.

## Information architecture

The site has one route and a sticky section menu. It is read in this order:

### 1. Проект простыми словами

Explain the complete operator story without jargon:

- twenty cameras continuously provide video streams;
- the system checks selected frames for configured safety events;
- a stable event is created only after temporal/rule checks;
- the system preserves a short evidence clip and records the model/configuration used;
- an operator reviews the event and decides whether to dismiss or escalate it;
- the existing NVR remains responsible for continuous archive footage.

Then state the current truth: Kuzet AI has a working investor MVP, while a reliable 20-camera platform, operator workflow, persistence, security, model governance, and field validation are the actual project to be implemented.

### 2. Карта требований заказчика

Group the requirements by system area rather than by day:

- camera input and stream supervision;
- safety analytics;
- zones, loitering, and line crossing;
- event creation and evidence clips;
- dashboard and operator workflow;
- users, access control, 2FA, audit, and security;
- notifications and external integrations;
- storage, backup, monitoring, and recovery;
- face/attendance/watchlist requirements;
- reporting, mobile access, languages, support, and certification.

Each row uses five understandable fields: **что требуется**, **зачем это нужно**, **что есть сейчас**, **что надо сделать**, and **как проверить**. A status label identifies the requirement as straightforward, conditional, separately scoped, legally blocked, or excluded.

### 3. Что уже есть и чего не хватает

Show an evidence-based readiness matrix for the current repository:

- existing: file/video processing, single webcam path, curated demo scenarios, pose/tracking concepts, weapon cascade, fire/smoke detector, violence experiments, zones, incident fusion concept, overlay, and demo audit;
- missing or unsuitable for deployment: 20-stream supervisor, shared GPU batching, durable event database, event-time semantics, bounded evidence ring, secure dashboard, real notifications, model registry, licence register, health/metrics, backup/restore, deployment manifests, site benchmark, and soak/failure tests.

Explain the most important technical defects in plain language: the current three-pass file cache cannot serve 20 live cameras; curated 7/7 demo results are not accuracy; current model rights are not fully documented; fire fallback must fail closed; and frame-based fusion must become timestamp-based event logic.

### 4. Что именно предстоит построить

This is the central section of the site. Present eight implementation workstreams. Each workstream has a plain-language purpose, concrete outputs, dependencies, and definition of done.

1. **Потоки с 20 камер:** RTSP connection, hardware decoding, shared batching, timestamps, reconnect, health, and bounded queues.
2. **Логика событий:** per-camera tracking, zones/lines/loitering, timestamp-based fusion, cooldown, deduplication, and stable event IDs.
3. **Видеодоказательства:** encoded pre/post-event ring, 4–10 second clips, thumbnails, integrity hashes, retention, and storage limits.
4. **AI-модели:** commercially cleared artifacts, TensorRT export, per-model cadence, candidate verification, versioning, site evaluation, and fail-closed gates.
5. **Backend и данные:** PostgreSQL schema, event/evidence repositories, crash journal, search, filters, audit, and idempotency.
6. **Интерфейс оператора:** camera health, event queue, evidence review, confirm/reject, notes, model/gate status, and mobile-browser layout.
7. **Безопасность и уведомления:** TOTP, roles, TLS, secrets, signed evidence links, human-approved notification outbox, and delivery audit.
8. **Эксплуатация и проверка:** metrics, degraded states, log rotation, backup/restore, retention, replay testing, failure injection, and acceptance reporting.

The site should make clear that these workstreams can proceed in parallel, but their dependencies matter. For example, model integration cannot become operational before rights, artifact, site-quality, and capacity gates pass.

### 5. Что происходит с AI-моделями

For each model family, explain four fields in plain Russian:

- what it sees;
- what currently exists in the repository;
- why that is not yet a production guarantee;
- what must happen before deployment.

Explain that a model confidence such as 96% is not system accuracy. The site must use a short example showing the difference between confidence, precision, recall, and false alarms per camera-day.

### 6. Как части системы соединяются

Use a simple visual flow:

```text
Камеры → приём потоков → общая GPU-обработка → правила событий
       → короткий ролик → журнал → проверка оператором → уведомление
```

Explain shared batching, 2–5 Hz analytics, hardware decoding, timestamped per-camera state, bounded queues, encoded evidence rings, and the existing NVR in accessible language. Technical detail is placed under expandable “Подробнее” panels.

Add a second diagram that maps each implementation workstream to the runtime flow and clearly distinguishes the video data plane from the web/control plane.

### 7. Что система сможет делать, а что требует условий

Use a capability matrix rather than a deadline-based promise:

- **Можно реализовать как базовую функцию:** exact 20-stream supervision, dashboard/search, evidence, person tracking, zones/loitering/lines, roles/2FA/audit/TLS/backup, and one reviewed notification connector.
- **Можно реализовать как candidate/shadow capability, then validate:** fire/smoke, weapon, fight, and fall. Operational status depends on model rights, site data, quality, and capacity.
- **Separate subsystem and legal/product decision:** entrance-only face recognition, attendance, and official watchlist integration.
- **Do not implement as a claimed reliable safety function:** emotion or intention inference.
- **Later production work:** HA/SLA, formal security/fire certification, broad OEM/VMS compatibility, native mobile applications, and unlimited integrations.

### 8. Сервер, облако и хранение

Show the baseline server in one card:

- NVIDIA L4 24 GB;
- at least 16 physical CPU cores;
- 64 GB ECC RAM;
- mirrored 1 TB NVMe;
- 10GbE;
- existing NVR for continuous recording.

Explain why H100 is unnecessary. Include the storage example that 20 cameras at 2 Mb/s generate about 432 GB/day and that 500 GB is approximately 28 hours, not a 30-day archive.

Compare Kazakhstan cloud, on-premises L4, and customer-provided infrastructure. Clearly label infrastructure figures as allowances, not supplier quotes.

### 9. Как принимаем работу

Separate platform acceptance from AI quality:

- exact 20 streams in a long soak test;
- availability, queue age, reconnect time, scheduled drops, GPU/VRAM, evidence latency, and bounded disk;
- no crash, OOM, cross-camera state leakage, silent model failure, or notification before operator confirmation;
- per-model site matrix with positives and hard negatives;
- each conditional module ends as operator, shadow, or disabled with reasons.

Explain why “96% confidence” is not an acceptance criterion and why event-level precision, recall, missed events, false alarms per camera-day, latency, and evidence completeness are.

### 10. Цена и договорная граница

Present one approved price table and payment schedule:

- 19.8 million KZT fixed core;
- cloud envelope up to 20.6 million KZT;
- on-premises envelope up to 31.3 million KZT;
- 30/40/30 payments;
- infrastructure billed at approved actual supplier cost;
- one site and 20 named streams;
- 30 days of shadow support.

List exclusions in plain language and state that changes after Day 12 require a change request.

### 11. Зависимости, риски и решения

Use a practical requirement-to-risk register with owner and mitigation:

- missing camera/network access;
- unsuitable codec, GOP, bitrate, clock, or camera view;
- missing commercial model rights;
- insufficient target-GPU capacity;
- insufficient site positives and hard negatives;
- customer changes after scope freeze;
- privacy/biometric risk;
- hardware or cloud availability;
- fewer engineers than the parallel work requires.

For every dependency, state what work can continue, what work must pause, and what evidence closes the risk.

### 12. Рекомендуемая последовательность реализации

Show dependency order and parallel tracks first. Do not make dates the organising concept:

1. Freeze requirements, camera matrix, legal boundaries, acceptance definitions, and model rights.
2. Build the multistream runtime, durable event contract, evidence path, and basic control plane in parallel.
3. Add person/zones/lines and operator review before conditional high-risk models.
4. Integrate cleared fire/weapon models through shadow gates and capacity profiling.
5. Add hardening, observability, backup/restore, notifications, and operator training.
6. Run site scenarios, hard negatives, replay, failure drills, and the uninterrupted soak before handover.

Include a collapsed “Как это может лечь в 20 дней” planning example, but label it as a scheduling aid rather than the definition of the project. Show the required parallel team and explain that fewer people means reducing parallel scope or extending the date.

### 13. Словарь

Define at least these terms using one or two sentences and an example where helpful:

`RTSP`, `NVR`, `inference`, `model weight`, `confidence`, `precision`, `recall`, `false positive`, `shadow mode`, `operator mode`, `TensorRT`, `DeepStream`, `NVDEC`, `batching`, `latency`, `p95`, `RBAC`, `TOTP 2FA`, `audit log`, `Ready-to-Start`, `acceptance gate`, and `change request`.

### 14. Материалы

Provide the new accessible PDF plus the approved meeting offer and implementation plan. Label internal documents so teammates do not forward them to the customer by mistake.

## Reading model

The site uses two levels of depth:

- The default layer contains conclusions, examples, decisions, and numbers in plain Russian.
- Expandable “Подробнее” panels contain implementation details, model provenance, deployment architecture, acceptance formulas, and source links.

Every acronym is expanded on first use. English technical terms may appear in parentheses after the Russian explanation. The copy avoids unexplained phrases such as “zero-copy hot path,” “event-time fusion,” “N-of-M debounce,” or “model promotion gate.”

## Visual design

- Calm, professional Kuzet AI styling using the existing dark navy, blue, rose, green, amber, and neutral palette.
- White or very light reading surface with dark text; dark sections only for high-level decision blocks.
- No decorative stock imagery and no model-authored SVG illustrations.
- Status colors always include text labels/icons so meaning does not depend on color alone.
- Strong typographic hierarchy, generous spacing, readable line length, and large touch targets.
- Tables collapse into stacked cards on mobile.
- The first screen shows the decision, price, timeline, and current maturity—not generic dashboard navigation.

## Interactions

- Sticky section navigation with current-section highlighting.
- Expand/collapse technical detail panels with keyboard-accessible controls.
- Copy button for the meeting statement.
- “Наверх” control after long sections.
- Download links for PDF and supporting materials.
- Print stylesheet that preserves status labels, section headings, page breaks, and source links.

The site has no authentication, form submission, analytics tracker, database, or external user data collection.

## PDF design

The PDF mirrors the website's requirement- and workstream-led section order and terminology. It is A4, uses the same status system, includes a contents page, page numbers, source links, and a clear “Внутренний материал для команды” label. Expandable website details are represented as concise “Техническая справка” blocks. The work sequence appears after requirements, architecture, implementation workstreams, and acceptance—not before them.

The PDF and website use one canonical content dataset so price, scope, and status cannot diverge.

## Publishing

- Publish as a no-login shareable site.
- Do not include RTSP credentials, private customer identifiers, supplier credentials, access tokens, or local machine paths.
- The public content may describe the unnamed customer as “заказчик” and the site as “объект с 20 камерами.”
- Internal download links must be deliberately labelled. The site itself is suitable for teammates, not a final contractual offer.

## Error and ambiguity handling

- If a source contains an older conflicting price or duration, show it only as a separately labelled later-production scenario or omit it from the primary narrative.
- If a claim lacks a verified site benchmark, label it as a target, assumption, or gate rather than a result.
- If a conditional model has no commercial-rights evidence, its status is disabled or shadow; the site never implies silent fallback.
- Broken downloads or missing source artifacts fail the deployment build.

## Validation

Before publishing:

- Build must succeed without warnings that affect functionality.
- All section anchors and download targets must resolve.
- The PDF must render on A4 without clipped or orphaned content.
- Price totals and payment percentages must be verified mechanically.
- Search for contradictory approved prices, `TODO`, `TBD`, secrets, local paths, and customer identifiers.
- Check semantic headings, keyboard focus, contrast, reduced-motion behavior, and mobile card layouts.
- Verify the existing Python repository remains healthy with its current test and lint commands.

## Success criteria

A second- or third-year CS student and a business teammate should be able to read the first sections and correctly explain:

- what the customer is asking the product to do;
- what currently exists in the repository and what does not;
- the eight concrete implementation workstreams;
- how a camera frame becomes a reviewed event and evidence clip;
- why fire/weapon require gates and why faces are a separate subsystem;
- why emotions are excluded;
- why one L4 is the starting point rather than an H100;
- which requirements depend on customer access, model rights, site data, or later production work;
- how each major subsystem will be tested and accepted;
- why the price is 19.8 million KZT plus a separate infrastructure allowance.

The full site must remain useful as an internal reference without requiring access to the original Codex conversation.
