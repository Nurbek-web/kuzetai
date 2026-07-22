# Kuzet AI Platform Briefing Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publicly publish a Russian, single-page Kuzet AI platform briefing with a matching downloadable PDF, written for CS students and a business teammate and treating the two-building/20-camera opportunity only as the first reference deployment.

**Architecture:** Keep all briefing facts in one structured UTF-8 JSON file. A typed React view renders that content as an accessible one-page site, and a deterministic Python script reads the same JSON to create the PDF. Static downloads live under `public/downloads/`; the site has no login, database, or runtime secrets. Product concepts lead every section, while opportunity-specific prices and capacity appear only in an explicitly labelled reference-deployment block.

**Tech Stack:** Sites starter (vinext/React/TypeScript), CSS, Node built-in test runner, Python 3.12 with ReportLab, Sites hosting, and a generated raster Open Graph preview.

---

## Task 1: Initialize and verify the Sites project

**Files:**
- Create: `briefing-site/` using the Sites starter
- Verify: `briefing-site/package.json`
- Verify: `briefing-site/.openai/hosting.json`
- Modify: `briefing-site/package.json`

- [ ] Run the official Sites initializer against the exact destination:

  ```bash
  bash "/Users/nurbek/.codex/plugins/cache/openai-bundled/sites/0.1.30/scripts/init-site.sh" "/Users/nurbek/Projects/kuzetai/briefing-site"
  ```

- [ ] Inspect the generated scripts and dependency versions; retain the starter's package manager and do not replace its hosting configuration.

- [ ] Add deterministic project scripts to `package.json`:

  ```json
  {
    "scripts": {
      "check:content": "node --test tests/content.test.mjs",
      "build:pdf": "python3 scripts/build_briefing_pdf.py",
      "prepare:briefing": "npm run check:content && npm run build:pdf",
      "check": "npm run check:content && npm run build"
    }
  }
  ```

  Preserve every starter-required script and adapt `npm` only if the scaffold explicitly selects another package manager.

- [ ] Start the generated development server in a retained terminal session and open its exact localhost URL once in the in-app browser.

- [ ] Confirm the untouched starter loads without console or network errors before replacing its content.

- [ ] Commit only the initialized project and package-script change:

  ```bash
  git add briefing-site
  git commit -m "chore: initialize Kuzet briefing site"
  ```

## Task 2: Create the canonical Russian content source and guardrails

**Files:**
- Create: `briefing-site/content/briefing.ru.json`
- Create: `briefing-site/lib/briefing.ts`
- Create: `briefing-site/tests/content.test.mjs`

- [ ] Write a failing Node test that loads `content/briefing.ru.json` and asserts all of the following:
  - the document has exactly the 18 approved top-level section IDs in their approved order;
  - section IDs and navigation labels are unique;
  - the platform definition and reusable hierarchy are present;
  - every requirement has `purpose`, `scope`, `currentState`, `workNeeded`, `verification`, and `status`;
  - every implementation workstream has `purpose`, `outputs`, `dependencies`, and `doneWhen`;
  - every AI family has current evidence, production gap, validation approach, rights state, and promotion state;
  - the values `19.8`, `20.6`, `31.3`, and `30/40/30` occur only inside the explicitly labelled `reference-deployment` content;
  - no sentence calls demo confidence “accuracy,” promises unlimited camera capacity, or presents 20 cameras/20 days as the product definition;
  - all local download URLs start with `/downloads/` and contain no workstation paths.

- [ ] Run the test and confirm the expected file-not-found or schema failure:

  ```bash
  cd "/Users/nurbek/Projects/kuzetai/briefing-site"
  node --test tests/content.test.mjs
  ```

- [ ] Build `briefing.ru.json` from the approved design specification and source deliverables. Keep language plain, define jargon on first use, use short paragraphs, and label uncertainty explicitly. The JSON must cover:
  - product story and target customers;
  - reusable core versus per-site configuration;
  - organization/site/building/camera/node hierarchy and scale model;
  - complete requirement map;
  - evidence-based current readiness;
  - nine implementation workstreams;
  - model-by-model production path;
  - data/control plane architecture and onboarding lifecycle;
  - capability matrix, verification, risks, decisions, glossary, and sources;
  - a clearly isolated first-reference-deployment case with its approved commercial figures.

- [ ] Add strict TypeScript interfaces and a typed exported loader in `lib/briefing.ts`. Validate required arrays at import time and fail the build on malformed content.

- [ ] Run the content test until it passes:

  ```bash
  npm run check:content
  ```

- [ ] Commit the canonical content and tests:

  ```bash
  git add briefing-site/content briefing-site/lib briefing-site/tests
  git commit -m "feat: add canonical Russian platform briefing"
  ```

## Task 3: Build the guided single-page reading experience

**Files:**
- Modify: `briefing-site/app/layout.tsx`
- Modify: `briefing-site/app/page.tsx`
- Modify: `briefing-site/app/globals.css`
- Create: `briefing-site/app/components/SectionNav.tsx`
- Create: `briefing-site/app/components/StatusBadge.tsx`
- Create: `briefing-site/app/components/PlatformMap.tsx`
- Create: `briefing-site/app/components/ArchitectureFlow.tsx`
- Create: `briefing-site/app/components/RequirementTable.tsx`
- Create: `briefing-site/app/components/WorkstreamGrid.tsx`
- Create: `briefing-site/app/components/ModelMatrix.tsx`
- Create: `briefing-site/app/components/ReferenceDeployment.tsx`
- Create: `briefing-site/app/components/DownloadPanel.tsx`

- [ ] Replace the starter metadata with the Russian title, description, language, canonical social metadata, and `/og.png` reference. Do not claim production readiness or measured accuracy.

- [ ] Implement the page in the approved section order. Above the fold must answer three questions in plain Russian: what Kuzet AI is, what is already real, and what the team must build next.

- [ ] Implement a sticky desktop section rail and a compact mobile section selector. All links must use stable section anchors and remain usable with JavaScript disabled.

- [ ] Render the platform hierarchy and two architecture flows as semantic HTML/CSS diagrams. Include text equivalents for screen readers; do not use authored SVGs.

- [ ] Render requirements, AI families, capabilities, risks, and verification as scannable cards on mobile and compact matrices on desktop. Use consistent status badges for `основа`, `условно`, `отдельный модуль`, `юридически заблокировано`, and `не обещаем`.

- [ ] Put deeper engineering explanations, formulas, sources, and definitions in native `<details>` elements. Keep the main reading path concise and understandable without opening them.

- [ ] Make the reference-deployment block visually distinct and repeat that its prices, 20 streams, and target schedule are not universal platform limits.

- [ ] Apply a restrained Kuzet visual system: dark navy text, white/warm-gray surfaces, alert red only for boundaries/risks, blue for platform structure, amber for conditional items, 16px minimum body type, generous line height, no decorative gradients, and reduced-motion support.

- [ ] Run the content check and production build:

  ```bash
  npm run check:content
  npm run build
  ```

- [ ] Commit the implemented page:

  ```bash
  git add briefing-site/app
  git commit -m "feat: build guided Kuzet platform briefing"
  ```

## Task 4: Produce the matching downloadable PDF from the same content

**Files:**
- Create: `briefing-site/scripts/build_briefing_pdf.py`
- Create: `briefing-site/public/downloads/Kuzet_AI_Platform_Briefing_RU.pdf`
- Create: `briefing-site/public/downloads/Kuzet_AI_Reference_Deployment_Offer_RU.pdf`
- Create: `briefing-site/public/downloads/Kuzet_AI_Internal_Readiness_Plan_RU.pdf`
- Create: `briefing-site/public/downloads/Kuzet_AI_Technical_Proposal_Reference_RU.pdf`

- [ ] Implement a deterministic A4 PDF generator that reads `content/briefing.ru.json`, embeds a Cyrillic font, uses repeated headers/footers and page numbers, prevents split headings, and mirrors the site's product-first order.

- [ ] Keep matrices readable by using concise summary rows in the main PDF and detailed continuation blocks below them; never shrink body text below 9 pt.

- [ ] Copy the three already verified supporting PDFs into `public/downloads/` with the safe public names above. Label them in site copy as reference-deployment/internal material, not current universal price lists.

- [ ] Generate the primary PDF:

  ```bash
  cd "/Users/nurbek/Projects/kuzetai/briefing-site"
  python3 scripts/build_briefing_pdf.py
  ```

- [ ] Render every PDF page to PNG using the PDF skill's Poppler workflow, inspect all pages, and correct overflows, clipped text, blank pages, bad table breaks, missing glyphs, and inconsistent spacing.

- [ ] Verify PDF text and links programmatically, including the exact title, platform definition, reference-deployment warning, approved prices, and all 18 section headings.

- [ ] Run the site content test again so every linked download resolves inside `public/downloads/`.

- [ ] Commit the generator and verified downloads:

  ```bash
  git add briefing-site/scripts briefing-site/public/downloads briefing-site/tests
  git commit -m "feat: add downloadable Kuzet briefing materials"
  ```

## Task 5: Add and verify the social preview asset

**Files:**
- Create: `briefing-site/public/og.png`
- Verify: `briefing-site/app/layout.tsx`

- [ ] After the page design is stable, generate exactly one raster 1200×630 social-preview card. It should use the approved navy/blue/red visual language and contain only short, legible Russian text: `Kuzet AI` and `Платформа видеоаналитики безопасности`.

- [ ] Inspect the generated image at original resolution. Reject it if Cyrillic is malformed, text is clipped, or the image implies unsupported surveillance/biometric capability.

- [ ] Wire the verified image into Open Graph and Twitter metadata and confirm the built page references `/og.png`.

- [ ] Commit the preview asset and metadata:

  ```bash
  git add briefing-site/public/og.png briefing-site/app/layout.tsx
  git commit -m "feat: add Kuzet briefing social preview"
  ```

## Task 6: Perform content, responsive, accessibility, and repository verification

**Files:**
- Modify as needed: `briefing-site/app/**`
- Modify as needed: `briefing-site/content/briefing.ru.json`
- Modify as needed: `briefing-site/scripts/build_briefing_pdf.py`

- [ ] Run the complete site checks from a clean process:

  ```bash
  cd "/Users/nurbek/Projects/kuzetai/briefing-site"
  npm run prepare:briefing
  npm run build
  ```

- [ ] Open the exact local dev URL and inspect at desktop, tablet, and narrow mobile widths. Verify navigation, `<details>`, tables/cards, architecture flows, long Russian words, status legends, all downloads, and absence of horizontal overflow.

- [ ] Check browser console and network logs. Fix every missing asset, hydration warning, runtime exception, and failed download.

- [ ] Confirm keyboard-only navigation, visible focus, heading order, landmarks, descriptive links, contrast, reduced motion, and text alternatives for diagrams.

- [ ] Ask two independent reviewers to inspect (a) technical/product correctness and (b) Russian clarity/business readability. Apply only findings supported by the approved facts, then rerun all site checks.

- [ ] Re-run the existing Kuzet repository regression suite to ensure the standalone site did not disturb the computer-vision code:

  ```bash
  cd "/Users/nurbek/Projects/kuzetai"
  uv run pytest tests/ -q
  uv run ruff check protector tests cli.py
  git diff --check
  ```

- [ ] Commit verified corrections, if any:

  ```bash
  git add briefing-site
  git commit -m "fix: polish and verify Kuzet platform briefing"
  ```

## Task 7: Publish the public no-login site and smoke-test it

**Files:**
- Verify: `briefing-site/.openai/hosting.json`

- [ ] Read the hosting configuration from the finished project and create/update the Sites project using the approved public, no-login visibility.

- [ ] Upload the production build as a new version, deploy it, and wait for the deployment to reach a successful terminal state.

- [ ] Open the final public URL in the browser and smoke-test the hero, section navigation, one expandable detail, the primary PDF, each supporting download, `/og.png`, and mobile layout.

- [ ] Record the public URL and deployment/version identifiers in the handoff. Do not describe publication as complete until the public URL and downloads have been opened successfully.

## Final acceptance criteria

- [ ] A teammate can understand the product, architecture, requirements, workstreams, model limitations, scale model, and next decisions without reading the original chat.
- [ ] The site frames Kuzet AI as a reusable platform; 20 cameras and 20 days appear only as reference-deployment constraints.
- [ ] Current demo evidence is never presented as production accuracy.
- [ ] Prices are accurate, visibly scoped to the current opportunity, and not generalized into an invented product price list.
- [ ] The Russian website is public without login, responsive, keyboard usable, and free of console/network errors.
- [ ] The primary PDF matches the site, renders cleanly, and all four downloads work from both local and public URLs.
- [ ] Site build, content tests, PDF checks, repository tests, Ruff, and `git diff --check` all pass.
