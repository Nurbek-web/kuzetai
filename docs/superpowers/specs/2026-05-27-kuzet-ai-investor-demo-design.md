# Kuzet AI Investor Demo Design

Date: 2026-05-27

## Goal

Create an investor-ready demo package for Russian-speaking investors that makes Kuzet AI feel like a serious AI operations platform, not just an annotated-video script.

The demo should prove two things:

- Kuzet AI can detect meaningful school/campus safety incidents from video.
- Kuzet AI can stay quiet during normal scenes and present evidence before escalation.

The investor-facing brand is **Kuzet AI**. The internal Python package can remain `protector` for this phase to avoid a risky repo-wide rename.

## Audience And Tone

The audience is Russian-speaking investors. Investor-facing UI, reel copy, alert previews, and title cards should be in polished Russian.

Tone should be business-clean and credible:

- Avoid horror language and exaggerated urgency.
- Avoid production deployment claims.
- Avoid production accuracy claims.
- Label replay and simulated messaging clearly.

Recommended core positioning:

> Kuzet AI — ИИ-видеоаналитика для безопасности школ и кампусов

## Demo Package

The demo package has two linked deliverables:

1. A Russian investor-facing dashboard in replay mode.
2. A pre-rendered investor reel that shows the dashboard and selected proof clips.

The reel should feel like a product walkthrough with evidence, not a montage of raw detections.

## Dashboard Design

The main dashboard experience becomes a **Консоль разбора сценариев**.

It should replace the current clip-library-first presentation with a product surface designed for investor review.

Required dashboard sections:

- Header:
  - `Kuzet AI`
  - `ИИ-видеоаналитика для безопасности школ и кампусов`
  - `Локальный MVP · Режим повтора`
- Scenario buttons:
  - `Без инцидентов`
  - `Запретная зона`
  - `Агрессия`
  - `Дым / огонь`
- Main replay panel:
  - Plays the selected annotated MP4.
  - Uses the existing pre-rendered outputs from `demos/reel/annotated/`.
- Verdict panel:
  - Shows `Без инцидентов` for clean scenes.
  - Shows incident module, confidence, and first event time for incident scenes.
- Evidence timeline:
  - Summarizes incident events from the JSON log.
  - Shows timestamp, module, confidence, and reason.
- Detection details:
  - Uses JSON fields already emitted by the pipeline.
  - Keeps raw details visible enough to prove the system is not hand-waved.
- Telegram preview:
  - Shows a generated message for incident scenarios.
  - Must be labeled `Демо-режим` or `Предпросмотр Telegram`.
  - Must not imply that a live Telegram message was sent.

The current `Live Camera` tab can remain secondary. The investor path should start on the scenario review dashboard.

## Reel Design

The reel should be rebuilt around product proof.

Recommended scene order:

1. Russian Kuzet AI title card.
   - `Kuzet AI`
   - `ИИ-видеоаналитика для безопасности школ и кампусов`
2. Dashboard opening.
   - Show replay mode.
   - Show empty incident queue or all-clear state.
3. All-clear proof.
   - Use `calm_monitoring`.
   - Make the `0 incidents` result visually obvious.
   - This is the false-positive restraint proof.
4. Restricted zone scenario.
   - Use one clean zone case.
   - Show the evidence timeline and Telegram preview.
5. Violence scenario.
   - Use the strongest institutional-looking fight clip.
   - Prefer `fight_institution` unless a later review finds a better clip.
   - Show confidence and debounce/evidence rather than only a red banner.
6. Fire/smoke scenario.
   - Use `fire_detection`.
   - Present it as alarm detection evidence, while avoiding overclaiming model quality.
7. Escalation workflow.
   - Show the Telegram preview in demo mode.
   - Include location, incident type, confidence, timestamp, and review action.
8. Closing card.
   - Communicate that the MVP runs locally now and can become a cloud campus safety platform.

Avoid or de-emphasize:

- The noisy `multi_finale` scene if it floods zone events.
- Weapon detection until a clean weapon clip exists.
- Any claim that the system is deployed live in schools.

## Russian Copy

Recommended dashboard labels:

- `Консоль разбора сценариев`
- `Режим повтора`
- `Без инцидентов`
- `Инцидент обнаружен`
- `Лента доказательств`
- `Детали детекции`
- `Предпросмотр Telegram`
- `Демо-режим`
- `Агрессия`
- `Запретная зона`
- `Дым / огонь`

Recommended Telegram preview:

```text
Kuzet AI
Демо-предпросмотр Telegram

Обнаружена агрессия · Коридор A
Уверенность: 94%
Время: 00:02

Открыть карточку инцидента →
```

For all-clear:

```text
Без инцидентов
Сцена отслеживается, тревога не поднята.
```

For incident opening:

```text
Инцидент открыт после проверки сигнала
Порог, уверенность, временная метка и причина сохранены в журнале.
```

## Data Flow

The design should reuse existing artifacts:

1. Scenario metadata points to annotated MP4 files and JSON logs.
2. Dashboard loads selected scenario.
3. Dashboard derives:
   - incident count,
   - verdict,
   - first event time,
   - peak confidence,
   - readable evidence timeline,
   - Telegram preview message.
4. Reel builder uses the same curated scenario set and Russian title cards.

This keeps the dashboard and reel consistent.

## Error Handling

If an annotated MP4 is missing:

- Show a Russian message telling the operator to rebuild the reel artifacts.
- Do not crash the dashboard.

If a JSON log is missing or invalid:

- Still load the video if it exists.
- Show `Журнал событий не найден`.
- Suppress Telegram preview unless the scenario has incident metadata.

If a scenario has no incidents:

- Show `Без инцидентов`.
- Show an empty evidence timeline.
- Do not show a Telegram escalation message.

## Testing And Verification

Before calling the implementation complete:

- Run unit tests with `uv run pytest tests/ -v`.
- Launch the dashboard with `uv run python -m cli serve --port 7860`.
- Verify the dashboard opens on the Russian scenario review experience.
- Verify all four scenario buttons load the expected video and summary.
- Verify the all-clear scenario shows zero incidents and no Telegram escalation.
- Verify incident scenarios show Telegram preview labeled as demo mode.
- Rebuild or assemble the investor reel and verify Russian title cards and selected scenes.

## Non-Goals

This phase does not include:

- Real Telegram bot delivery.
- Production live multi-camera monitoring.
- Repo-wide package rename from `protector` to `kuzet`.
- New weapon-detection footage.
- New accuracy benchmark claims.
- New model training.

## Open Implementation Notes

- Keep existing detector and pipeline code stable unless a display bug blocks the investor demo.
- Prefer a small scenario summary helper over duplicating JSON parsing in UI and reel code.
- If Russian text causes font issues in OpenCV/Pillow title cards, use a font with Cyrillic support from the system.
- Consider ignoring `.superpowers/` in git before future brainstorming sessions, but do not bundle companion artifacts into the implementation commit.
