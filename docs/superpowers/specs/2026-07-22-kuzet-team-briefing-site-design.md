# Kuzet AI Teammate Briefing Site Design

Date: 2026-07-22

## Purpose

Create a self-contained Russian briefing that Nurbek can send to teammates who understand basic computer science but are not specialists in computer vision, model deployment, infrastructure, or AI product delivery. The audience also includes a business teammate.

The briefing must be comprehensive without reading like a tender response or engineering audit. It must let a reader answer five questions correctly after one pass:

1. What does Kuzet AI actually have today?
2. What can the team honestly deliver to the customer in 20 days?
3. What is experimental, deferred, or excluded?
4. How will 20 cameras work, what equipment is required, and why is an H100 unnecessary?
5. What price, team, dependencies, acceptance tests, and risks should the team communicate?

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
- The 12–20-week and 6–12-month estimates describe later production hardening, broader OEM/VMS integration, certification, high availability, or the full original specification. They are not alternative prices for the same Day-20 pilot.

## Information architecture

The site has one route and a sticky section menu. It is read in this order:

### 1. Главное за 2 минуты

Lead with the decision, not the technology:

- Kuzet AI today is an investor MVP, not a production VMS.
- A controlled 20-camera pilot is feasible in 20 calendar days after Ready-to-Start.
- The fixed core price is 19.8 million KZT excluding VAT.
- All critical events require human confirmation.
- Fire/smoke and weapon analytics are conditional; faces, emotions, native mobile applications, autonomous action, HA, and certification are outside Day 20.

Include a copyable “Что сказать на встрече” statement.

### 2. Три разных уровня готовности

Visually separate:

- **Сегодня:** curated investor demo and single-camera/file processing.
- **День 20:** bounded, human-in-the-loop pilot on the exact 20 streams.
- **После пилота:** production hardening, certification, HA, wider integrations, face entrance subsystem, and native mobile if separately contracted.

This section prevents the team from confusing the demo with the deliverable or the deliverable with a certified production product.

### 3. Что входит на День 20

Use a three-state scope matrix:

- **Твёрдо включено:** 20 RTSP feeds, camera health/reconnect/timestamps, dashboard/search, evidence clips, person tracking, zones/loitering/line crossing, TOTP/RBAC/TLS/audit/backup, one notification connector, operator workflow.
- **Условно:** fire/smoke and weapon candidate alerts after commercial-rights, target-site, and capacity gates.
- **Не входит / Этап 2:** fight/fall operational promises, face/watchlist/attendance, emotion inference, native mobile apps, autonomous calls/actions, formal certification, HA/SLA, continuous archive inside Kuzet.

### 4. Что происходит с AI-моделями

For each model family, explain four fields in plain Russian:

- what it sees;
- what currently exists in the repository;
- why that is not yet a production guarantee;
- what must happen before deployment.

Explain that a model confidence such as 96% is not system accuracy. The site must use a short example showing the difference between confidence, precision, recall, and false alarms per camera-day.

### 5. Как работают 20 камер

Use a simple visual flow:

```text
Камеры → приём потоков → общая GPU-обработка → правила событий
       → короткий ролик → журнал → проверка оператором → уведомление
```

Explain shared batching, 2–5 Hz analytics, hardware decoding, timestamped per-camera state, bounded queues, encoded evidence rings, and the existing NVR in accessible language. Technical detail is placed under expandable “Подробнее” panels.

### 6. Сервер, облако и хранение

Show the baseline server in one card:

- NVIDIA L4 24 GB;
- at least 16 physical CPU cores;
- 64 GB ECC RAM;
- mirrored 1 TB NVMe;
- 10GbE;
- existing NVR for continuous recording.

Explain why H100 is unnecessary. Include the storage example that 20 cameras at 2 Mb/s generate about 432 GB/day and that 500 GB is approximately 28 hours, not a 30-day archive.

Compare Kazakhstan cloud, on-premises L4, and customer-provided infrastructure. Clearly label infrastructure figures as allowances, not supplier quotes.

### 7. Цена и договорная граница

Present one approved price table and payment schedule:

- 19.8 million KZT fixed core;
- cloud envelope up to 20.6 million KZT;
- on-premises envelope up to 31.3 million KZT;
- 30/40/30 payments;
- infrastructure billed at approved actual supplier cost;
- one site and 20 named streams;
- 30 days of shadow support.

List exclusions in plain language and state that changes after Day 12 require a change request.

### 8. Программа на 20 дней

Show six understandable phases rather than a dense Gantt chart:

1. Before Day 1: complete Ready-to-Start and freeze customer inputs.
2. Days 1–2: verify the exact feeds, model rights, test matrix, and target infrastructure.
3. Days 3–7: 20-stream platform, dashboard, security, evidence, and zones.
4. Days 8–12: conditional analytics, notification, measurement, and scope freeze.
5. Days 13–18: site tests, hard negatives, tuning, and the 72-hour soak.
6. Days 19–20: restore drill, training, acceptance pack, and handover.

Show the required parallel team and explain that fewer people means reducing scope or extending the date.

### 9. Как принимаем работу

Separate platform acceptance from AI quality:

- 20 exact streams for 72 hours;
- availability, queue age, reconnect time, scheduled drops, GPU/VRAM, evidence latency, bounded disk;
- no crash, OOM, cross-camera state leakage, silent model failure, or notification before operator confirmation;
- per-model site matrix with positives and hard negatives;
- each conditional module ends as operator, shadow, or disabled with reasons.

### 10. Риски и зависимости

Use a short risk register with owner and mitigation:

- missing camera/network access;
- unsuitable codec or camera view;
- missing commercial model rights;
- insufficient L4 capacity;
- insufficient site test data;
- customer changes after scope freeze;
- privacy/biometric risk;
- hardware delivery risk.

### 11. Словарь

Define at least these terms using one or two sentences and an example where helpful:

`RTSP`, `NVR`, `inference`, `model weight`, `confidence`, `precision`, `recall`, `false positive`, `shadow mode`, `operator mode`, `TensorRT`, `DeepStream`, `NVDEC`, `batching`, `latency`, `p95`, `RBAC`, `TOTP 2FA`, `audit log`, `Ready-to-Start`, `acceptance gate`, and `change request`.

### 12. Материалы

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

The PDF mirrors the website's section order and terminology. It is A4, uses the same status system, includes a contents page, page numbers, source links, and a clear “Внутренний материал для команды” label. Expandable website details are represented as concise “Техническая справка” blocks.

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

A second- or third-year CS student and a business teammate should be able to read the first two sections in under five minutes and correctly explain:

- why the current demo is not production;
- what the 20-day pilot includes;
- why fire/weapon are conditional;
- why faces and emotions are excluded;
- why one L4 is the starting point rather than an H100;
- why the price is 19.8 million KZT plus a separate infrastructure allowance;
- what the customer must provide before Day 1;
- how the pilot will be accepted.

The full site must remain useful as an internal reference without requiring access to the original Codex conversation.
