# Kuzet AI Product and Reference Deployment Briefing Site Design

Date: 2026-07-22

## Purpose

Create a self-contained Russian briefing that Nurbek can send to teammates who understand basic computer science but are not specialists in computer vision, model deployment, infrastructure, or AI product delivery. The audience also includes a business teammate.

The briefing must explain **Kuzet AI as a reusable product platform**, not as a one-off 20-camera contract. The current opportunity—two buildings and approximately 20 cameras—is the first concrete reference deployment used to validate, package, and improve the platform. It is not the platform's architectural limit or its only market.

The site must be comprehensive without reading like a tender response or engineering audit. After one pass, a reader must be able to answer these questions correctly:

1. What product is Kuzet AI building, for whom, and what operational problem does it solve?
2. Which platform capabilities are reusable for every customer, and which settings/integrations are configured per organization or site?
3. What are the product's functional, technical, operational, security, and AI-governance requirements?
4. What does Kuzet AI already have, and what still has to be built, replaced, licensed, or validated?
5. Which implementation workstreams make up the actual product?
6. How do organizations, sites, buildings, cameras, AI modules, event logic, evidence, users, and notifications connect?
7. How does the architecture scale from one reference deployment to multiple organizations and larger camera fleets?
8. Which capabilities are straightforward, conditional on testing/licensing, separately scoped, or inappropriate to promise?
9. How does the first two-building deployment fit into the wider product strategy, implementation, validation, and commercial model?

The first deployment's 20-camera count and 20-day commercial target are constraints and validation inputs, not the site's organising concepts. The briefing is organised around the product, reusable architecture, requirements, implementation workstreams, deployment lifecycle, scale, and proof of completion.

## Deliverables

1. A responsive, publicly shareable Russian website that does not require login.
2. A downloadable Russian PDF that follows the same information structure.
3. Download links to the first-deployment meeting offer and repository-specific implementation plan.

The website is the primary reading experience. The PDF is an offline/shareable companion, not a second contradictory source of truth.

## Content authority

The site consolidates and normalizes the following approved sources:

- `deliverables/kuzet_20_camera/Kuzet_AI_Final_Meeting_Offer_RU.docx`
- `deliverables/kuzet_20_camera/Kuzet_AI_20_Camera_Technical_Commercial_Proposal_RU.docx`
- `deliverables/kuzet_20_camera/Kuzet_AI_Internal_Readiness_and_Delivery_Plan_RU.docx`
- `docs/superpowers/specs/2026-07-22-kuzet-20-camera-pilot-design.md`
- `docs/superpowers/plans/2026-07-22-kuzet-20-camera-pilot.md`
- the supplied customer specification `ТС ВИДЕО ру каз услуга.docx`

The site distinguishes three kinds of information instead of blending them:

- **Product facts and design:** reusable Kuzet AI capabilities, architecture, workstreams, lifecycle, scale, model governance, and operating model.
- **Current readiness evidence:** what the repository and models demonstrate today, plus missing production capabilities.
- **Reference-deployment facts:** two buildings, approximately 20 named streams, the initial scope, commercial envelope, customer dependencies, and site acceptance.

Where older materials conflict with the approved first-deployment meeting position, the site uses the approved controlled-pilot position:

- **19.8 million KZT excluding VAT** is the fixed software/integration price for the bounded first deployment, not the permanent universal product price.
- **Up to 20.6 million KZT** is the indicative first-month Kazakhstan-cloud envelope.
- **Up to 31.3 million KZT** is the indicative on-premises envelope with an L4 server allowance.
- The 12–20-week and 6–12-month estimates describe later production hardening, broader OEM/VMS integration, certification, high availability, or the full original specification. They are not alternative prices for the same controlled pilot.
- Twenty cameras is the target capacity profile to validate first. It is not presented as a fixed platform maximum. Larger deployments require measured node capacity and horizontal partitioning.

Product capabilities and requirements are the primary organising units. Each requirement must state: why it exists, whether it is reusable or site-specific, current readiness, required implementation, dependencies, and how completion will be verified. Dates and camera counts appear only where they explain a reference deployment, capacity profile, sequencing decision, or contractual constraint.

## Information architecture

The site has one route and a sticky section menu. It is read in this order:

### 1. Что такое Kuzet AI

Define the product in one sentence: **Kuzet AI is a modular safety-video platform that connects to an organization's existing cameras, turns selected video observations into reviewable safety events, preserves evidence, and gives an operator a controlled response workflow.**

Explain the value using the complete operator story without jargon:

```text
Камера → наблюдение → кандидат события → проверка правилами
       → короткое доказательство → решение оператора → действие
```

The product is not merely a collection of AI models and is not a replacement for every VMS/NVR function. Its reusable value is the combination of video ingestion, analytics orchestration, reliable event semantics, evidence, human review, security, and operations.

### 2. Для кого и какие задачи решаем

Describe target organizations without claiming that every vertical is already validated:

- schools, universities, camps, and educational campuses;
- offices, business centres, and public buildings;
- warehouses, industrial sites, and controlled facilities;
- organizations that already have cameras but lack consistent event detection and operator workflow.

Explain the reusable use cases: restricted zones, loitering, line crossing, fire/smoke candidates, weapon candidates, aggression/fall experiments, camera health, evidence, review, escalation, audit, and reporting. Show which use cases need separate legal or domain approval.

### 3. Что является платформой, а что настраивается под объект

Use two clear columns:

- **Reusable platform core:** organization/site/building/camera hierarchy, stream runtime, event schema and engine, model registry, evidence service, dashboard, users/roles, audit, notification framework, metrics, deployment tooling, backup/restore, and acceptance reporting.
- **Per-customer configuration:** camera addresses and profiles, buildings, zones and lines, enabled analytics, thresholds, evidence retention, users, notification channel, language, integrations, legal basis, and site acceptance scenarios.

Explain that the goal is to onboard a new organization mainly through configuration, model/site validation, and integrations—not by rewriting the platform.

### 4. Масштабируемая модель продукта

Show the product hierarchy:

```text
Платформа Kuzet AI
  └─ Организация
      ├─ Объект / кампус
      │   ├─ Здание
      │   │   ├─ Камеры
      │   │   ├─ Зоны и линии
      │   │   └─ Политики и AI-модули
      │   └─ Локальный узел обработки
      └─ Пользователи, роли, события, аудит и отчёты
```

Explain the scaling model in plain language:

- one GPU node handles a measured number of camera profiles;
- larger sites divide cameras across additional nodes;
- multiple sites are partitioned independently so a failure does not mix state or stop every customer;
- a central control plane may manage configuration, users, aggregate health, and permitted event metadata;
- continuous video can remain local while events and short evidence follow the customer's residency policy;
- capacity is demonstrated by benchmark profiles, never by the word “unlimited.”

### 5. Карта требований продукта

Group requirements by reusable system capability:

- organization/site/building/camera configuration;
- camera input, profile inventory, timestamps, supervision, and reconnect;
- analytics scheduling and model lifecycle;
- person tracking, zones, loitering, and line crossing;
- candidate events, deduplication, evidence, and operator decisions;
- dashboard, search, reporting, and mobile-browser access;
- users, roles, 2FA, TLS, secrets, audit, and tenant/site isolation;
- notification connectors and external integrations;
- storage, retention, backup, monitoring, recovery, and upgrades;
- field evaluation, model registry, versioning, rollback, and acceptance;
- optional biometric, attendance, and official watchlist subsystem;
- support, certification, HA/SLA, localization, and commercial licensing.

Each row uses six understandable fields: **возможность**, **зачем нужна**, **platform или site-specific**, **что есть**, **что надо сделать**, and **как проверить**. Status labels identify foundation, conditional analytic, separate module, legally blocked, or excluded.

### 6. Что уже есть и чего не хватает

Show an evidence-based readiness matrix for the current repository:

- existing: file/video processing, single webcam path, curated demo scenarios, pose/tracking concepts, weapon cascade, fire/smoke detector, violence experiments, zones, incident fusion concept, overlay, and demo audit;
- missing or unsuitable for a reusable product: multi-stream/node runtime, organization/site data model, shared GPU batching, durable event database, timestamp-based semantics, bounded evidence service, secure operator console, real notification framework, model/licence registry, tenant/site isolation, deployment templates, health/metrics, backup/restore, upgrade/rollback, site benchmark, and soak/failure tests.

Explain the important gaps in plain language: the current three-pass file cache cannot be the live platform; curated 7/7 demo results are not accuracy; model rights are not fully documented; model failure must be visible and fail closed; and frame-based fusion must become timestamp-based event logic.

### 7. Что именно предстоит построить

This is the central section. Present nine reusable implementation workstreams. Each has a purpose, outputs, dependencies, and definition of done.

1. **Модель организаций и объектов:** organization/site/building/camera entities, configuration versions, roles, policies, and isolation boundaries.
2. **Видеоконтур:** RTSP profiles, hardware decoding, shared batching, timestamps, reconnect, health, bounded queues, and node capacity management.
3. **Логика событий:** independent per-camera state, tracking, zones/lines/loitering, timestamp-based fusion, cooldown, deduplication, and stable event IDs.
4. **AI-модули и MLOps:** commercially cleared artifacts, common detector interface, TensorRT export, cadence, candidate verification, registry, site evaluation, rollout, and rollback.
5. **Видеодоказательства:** encoded pre/post-event ring, clips, thumbnails, hashes, retention, storage limits, and source/NVR reference.
6. **Backend и данные:** PostgreSQL schema, crash journal, repositories, search, audit, idempotency, exports, and organization/site scoping.
7. **Интерфейс оператора:** health, event queue, evidence, confirm/reject, notes, model status, reporting, and responsive browser experience.
8. **Безопасность, уведомления и интеграции:** TOTP, RBAC, TLS, secrets, signed evidence links, reviewed-event outbox, connector contracts, and delivery audit.
9. **Эксплуатация и поставка:** metrics, degraded modes, containers, deployment profiles, backup/restore, retention, upgrades, replay/failure tests, acceptance reports, and runbooks.

Explain that the first deployment exercises these reusable workstreams. Customer-specific code is permitted only behind a documented adapter or configuration boundary.

### 8. Что происходит с AI-моделями

For each model family, explain: what it sees, current evidence, production gap, reusable interface, site-specific validation, commercial-rights status, and promotion state.

Cover person/tracking, zones/lines, fire/smoke, weapon, aggression/fight, fall, and the separate face subsystem. Explain that “96% confidence” is not product accuracy. Use a short example showing confidence, precision, recall, missed events, and false alarms per camera-day.

Status is always one of: `disabled`, `shadow`, or `operator`. A model can be available in the platform catalogue while remaining disabled for a particular organization or camera profile.

### 9. Как части платформы соединяются

Use two diagrams:

```text
Локальный видеоконтур
Камеры → декодирование → общая GPU-обработка → события → evidence ring
```

```text
Управляющий контур
Конфигурация → журнал/БД → интерфейс оператора → решение → уведомление/аудит
```

Explain data plane versus control plane, shared batching, per-camera timestamps, bounded queues, event/evidence contracts, site isolation, and how additional nodes/sites attach without changing operator semantics.

### 10. Жизненный цикл нового заказчика

Show the repeatable onboarding process:

1. requirements and legal boundary;
2. camera/site inventory and connectivity profile;
3. deployment profile and capacity estimate;
4. zones, policies, users, retention, and integrations;
5. model-rights review and shadow configuration;
6. replay/site validation and threshold selection;
7. operator training and controlled activation;
8. monitoring, support, periodic model review, and expansion.

The key product objective is to make this lifecycle repeatable and increasingly configuration-driven.

### 11. Что система сможет делать, а что требует условий

Use a general capability matrix:

- **Platform foundations:** multistream supervision, event/evidence workflow, person/zones/lines, operator console, users/security/audit, monitoring, and reviewed notifications.
- **Conditional analytics:** fire/smoke, weapon, fight, and fall; availability and operating mode depend on model rights, domain/site data, quality, and node capacity.
- **Separate module:** entrance-only face recognition, attendance, and official watchlist integration with legal authority and licensed SDK.
- **Do not sell as reliable inference:** emotions or intentions.
- **Production tiers:** HA/SLA, certification, advanced reporting, native mobile, OEM/VMS integrations, and central multi-site operations are packaged separately.

### 12. Первый reference deployment: два здания и 20 камер

Present the current opportunity as the first product profile, not the product definition:

- two buildings;
- approximately 20 named RTSP streams;
- one organization and one operational team;
- local/cloud/on-prem deployment choice;
- current scope, dependencies, acceptance, and known exclusions;
- lessons and reusable artifacts that must feed back into the platform.

The commercial facts for this reference deployment are:

- 19.8 million KZT fixed software/integration core;
- Kazakhstan-cloud envelope up to 20.6 million KZT;
- on-premises envelope up to 31.3 million KZT;
- 30/40/30 payments;
- infrastructure billed at approved actual supplier cost;
- 30 days of shadow support.

Label these as the current opportunity's offer. A future product price book may use onboarding, per-camera/per-site subscription, analytics modules, infrastructure, integration, and support tiers, but no general SKU price is invented in this briefing.

### 13. Сервер, облако и хранение

Show the first capacity profile: NVIDIA L4 24 GB, at least 16 physical CPU cores, 64 GB ECC RAM, mirrored NVMe, 10GbE, and existing NVR for continuous recording. Explain why H100 is unnecessary for this profile.

Include the reference calculation: 20 cameras at 2 Mb/s generate about 432 GB/day, so 500 GB is approximately 28 hours rather than a 30-day archive. Then teach the reusable sizing method: camera count × bitrate × retention, plus measured analytics rate, model mix, codec decode, evidence volume, and headroom.

Compare site-local, Kazakhstan-cloud, hybrid, and customer-provided infrastructure as deployment profiles. Costs remain allowances until supplier quotes and benchmark evidence exist.

### 14. Как проверяем платформу и каждое внедрение

Separate reusable product verification from site acceptance:

- **Platform:** contracts, migrations, isolation, security, event idempotency, bounded queues/storage, deployment reproducibility, upgrade/rollback, backup/restore, and connector tests.
- **Capacity profile:** camera/codec/resolution/model mix, queue age, drops, GPU/VRAM/NVDEC, evidence latency, and failure recovery.
- **Site:** exact streams, camera views, zones, users, integration, retention, positives, hard negatives, false alarms, missed events, and operator workflow.
- **Model:** precision, recall, operating threshold, failure slices, false alarms per camera-day, artifact/config versions, and `disabled`/`shadow`/`operator` decision.

The first deployment uses a 20-stream long soak as one profile. Later customers run their own frozen profile rather than inheriting an unverified “20 cameras means everything works” claim.

### 15. Зависимости, риски и продуктовые решения

Use a risk register covering access, codec/profile diversity, commercial model rights, site data, GPU capacity, customer-specific scope creep, privacy/biometrics, infrastructure supply, organization isolation, upgrade compatibility, and support staffing.

For every risk, state whether it affects the reusable platform, only one deployment, or both; who owns it; what can continue; what must pause; and what evidence closes it.

### 16. Рекомендуемая последовательность реализации

Show dependency order and parallel product tracks:

1. Freeze the product boundary, domain model, event/evidence contracts, model policy, and deployment profiles.
2. Build the multistream runtime, organization/site-aware backend, evidence path, and operator shell in parallel.
3. Complete reliable person/zones/lines and human review before operational high-risk analytics.
4. Integrate cleared fire/weapon models through the same registry/gate interface.
5. Add security, observability, backup/restore, deployment automation, connector contracts, and upgrade/rollback.
6. Use the first two-building deployment to validate the reference capacity profile and onboarding lifecycle.
7. Feed lessons back into reusable configuration, documentation, model/site test packs, and future pricing/support tiers.

Include the current 20-day work allocation only as a collapsed example for the first opportunity. The primary roadmap is capability- and dependency-led.

### 17. Словарь

Define product and AI terms using one or two sentences and examples: `organization`, `site`, `building`, `data plane`, `control plane`, `RTSP`, `NVR`, `inference`, `model weight`, `confidence`, `precision`, `recall`, `false positive`, `shadow mode`, `operator mode`, `TensorRT`, `DeepStream`, `NVDEC`, `batching`, `latency`, `p95`, `RBAC`, `TOTP 2FA`, `audit log`, `Ready-to-Start`, `capacity profile`, `acceptance gate`, and `change request`.

### 18. Материалы

Provide the new accessible PDF plus the approved first-deployment meeting offer and implementation plan. Label the meeting offer as deployment-specific and label internal documents so teammates do not forward them to customers by mistake.

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
- The first screen shows the product definition, target problem, reusable platform layers, and current maturity. The first-deployment price and timeline appear later in their clearly labelled reference-deployment section.

## Interactions

- Sticky section navigation with current-section highlighting.
- Expand/collapse technical detail panels with keyboard-accessible controls.
- Copy buttons for the one-paragraph product explanation and the separate first-deployment meeting statement.
- “Наверх” control after long sections.
- Download links for PDF and supporting materials.
- Print stylesheet that preserves status labels, section headings, page breaks, and source links.

The site has no authentication, form submission, analytics tracker, database, or external user data collection.

## PDF design

The PDF mirrors the website's product-, capability-, and workstream-led section order and terminology. It is A4, uses the same status system, includes a contents page, page numbers, source links, and a clear “Внутренний материал для команды” label. Expandable website details are represented as concise “Техническая справка” blocks. The reference deployment, its price, and its schedule appear only after the reusable product architecture and requirements are understood.

The PDF and website use one canonical content dataset so price, scope, and status cannot diverge.

## Publishing

- Publish as a no-login shareable site.
- Do not include RTSP credentials, private customer identifiers, supplier credentials, access tokens, or local machine paths.
- The public content describes a general Kuzet AI product and one unnamed “первое reference-внедрение: два здания, около 20 камер.”
- Internal download links must be deliberately labelled. The site itself is suitable for teammates, not a final contractual offer.

## Error and ambiguity handling

- If a source contains an older conflicting price or duration, show it only as a separately labelled later-production or other deployment scenario, or omit it from the primary narrative.
- Never present the first deployment's camera count, server choice, scope, or price as a permanent platform maximum, universal hardware rule, or general product price book.
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

- what Kuzet AI is as a reusable product and which organizations it may serve;
- what is reusable platform core and what is configured per customer/site;
- how organizations, sites, buildings, cameras, local processing nodes, users, and events relate;
- what currently exists in the repository and what does not;
- the nine concrete reusable implementation workstreams;
- how a camera frame becomes a reviewed event and evidence clip;
- why fire/weapon require gates and why faces are a separate subsystem;
- why emotions are excluded;
- how the platform scales by measured node capacity and site partitioning;
- why one L4 is the first reference capacity profile rather than an H100 or a universal limit;
- which requirements are platform foundations, site-specific configuration, conditional analytics, or later product tiers;
- how each major subsystem will be tested and accepted;
- why 19.8 million KZT plus infrastructure allowance belongs to the first deployment and is not yet a general SKU price.

The full site must remain useful as an internal reference without requiring access to the original Codex conversation.
