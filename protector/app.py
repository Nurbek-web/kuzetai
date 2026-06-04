from __future__ import annotations

import html
from pathlib import Path

import cv2
import gradio as gr
import yaml

from protector.config import REPO_ROOT
from protector.demo_scenarios import DemoScenario, build_scenario_summary, iter_manifest_scenarios
from protector.webcam_session import SessionKpis, WebcamSession

DEMOS_DIR = REPO_ROOT / "demos"
MANIFEST_PATH = DEMOS_DIR / "clips_manifest.yaml"

CSS = """
body { background-color: #0f172a; }
.gradio-container { background-color: #0f172a !important; font-family: 'Inter', sans-serif; color: #e5e7eb; max-width: 1180px !important; margin: 0 auto !important; }
.gradio-container h1, .gradio-container h2, .gradio-container h3,
.gradio-container p, .gradio-container label { color: #e5e7eb !important; }
.gradio-container a { color: #93c5fd !important; }
.header-bar { background: #111827;
               padding: 20px 28px; border-bottom: 2px solid #E11D48;
               display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.header-title { color: #ffffff; font-size: 30px; font-weight: 750; letter-spacing: 0; }
.header-sub { color: #94a3b8; font-size: 14px; margin-top: 4px; }
.mode-chip { color: #bbf7d0; background: #064e3b; border: 1px solid #22c55e;
             border-radius: 999px; padding: 7px 12px; font-size: 12px; font-weight: 700; white-space: nowrap; }
.scenario-copy { color: #cbd5e1; font-size: 15px; line-height: 1.5; margin: 6px 0 18px; }
.scenario-buttons button { min-height: 44px; font-weight: 700 !important; }
.status-card { border: 1px solid #334155; background: #111827; border-radius: 8px; padding: 14px 16px; }
.status-kicker { color: #94a3b8; font-size: 12px; font-weight: 700; text-transform: uppercase; }
.status-verdict { color: #fff; font-size: 24px; font-weight: 800; margin: 8px 0 4px; letter-spacing: 0; }
.status-meta { color: #cbd5e1; font-size: 13px; line-height: 1.45; }
.timeline { display: grid; gap: 8px; }
.timeline-row { border: 1px solid #334155; background: #111827; border-radius: 8px; padding: 10px 12px; }
.timeline-top { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:5px; }
.timeline-module { color:#fff; font-weight:750; }
.timeline-conf { color:#fecaca; background:#7f1d1d; border-radius:999px; padding:3px 8px; font-size:12px; font-weight:800; }
.timeline-time { color:#93c5fd; font-size:12px; font-weight:700; }
.timeline-reason { color:#cbd5e1; font-size:12px; }
.empty-state { color:#bbf7d0; border:1px solid #166534; background:#052e16; border-radius:8px; padding:12px; }
.secondary-tools { border-top: 1px solid #334155; margin-top: 16px; padding-top: 12px; }
.kpi-strip { display:flex; flex-wrap:wrap; gap:14px; padding:12px 14px; background:#0b1220; border:1px solid #334155; border-radius:8px; margin-top:10px; }
.kpi-cell  { display:flex; flex-direction:column; min-width:88px; }
.kpi-cell .kpi-label { color:#94a3b8; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; }
.kpi-cell .kpi-value { color:#fff; font-size:22px; font-weight:800; }
.kpi-cell.alert .kpi-value { color:#fecaca; }
"""


def _load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        return {"clips": []}
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f) or {"clips": []}


def _artifact_paths(scenario_id: str) -> tuple[Path, Path]:
    annotated_path = DEMOS_DIR / "reel" / "annotated" / f"{scenario_id}_annotated.mp4"
    return annotated_path, annotated_path.with_suffix(".json")


def _summary_for(scenario: DemoScenario | str) -> dict:
    scenario_id = scenario.id if isinstance(scenario, DemoScenario) else scenario
    video_path, log_path = _artifact_paths(scenario_id)
    scenario_override = scenario if isinstance(scenario, DemoScenario) else None
    return build_scenario_summary(scenario_id, video_path, log_path, scenario=scenario_override)


def _verdict_html(summary: dict) -> str:
    verdict = html.escape(str(summary["verdict"]))
    count = int(summary["incident_count"])
    confidence = html.escape(str(summary["peak_confidence"] or "—"))
    if count == 0 and summary["verdict"] == "Без инцидентов":
        meta = "Сцена отслеживается, тревога не поднята."
    elif summary["verdict"] == "Журнал событий не найден":
        meta = "Запустите сборку демо-ролика, чтобы создать JSON-журнал."
    else:
        meta = f"Инцидентов: {count} · Пиковая уверенность: {confidence}"
    return f"""
    <div class="status-card">
      <div class="status-kicker">Вердикт</div>
      <div class="status-verdict">{verdict}</div>
      <div class="status-meta">{html.escape(meta)}</div>
    </div>
    """


def _timeline_html(summary: dict) -> str:
    rows = summary["timeline"]
    if not rows:
        return '<div class="empty-state">Лента доказательств пуста: инцидентов нет.</div>'

    body = []
    for row in rows:
        body.append(
            f"""
            <div class="timeline-row">
              <div class="timeline-top">
                <div>
                  <div class="timeline-module">{html.escape(row["module_label"])}</div>
                  <div class="timeline-time">t={html.escape(row["time"])} сек</div>
                </div>
                <div class="timeline-conf">{html.escape(row["confidence"])}</div>
              </div>
              <div class="timeline-reason">{html.escape(row["reason"])}</div>
            </div>
            """
        )
    return f'<div class="timeline">{"".join(body)}</div>'


def _telegram_text(summary: dict) -> str:
    return summary["telegram_preview"] or "Эскалация не требуется: инцидентов нет."


def _load_scenario(scenario: DemoScenario):
    summary = _summary_for(scenario)
    return (
        summary["video"],
        _verdict_html(summary),
        _timeline_html(summary),
        _telegram_text(summary),
        summary["raw_log"],
    )


def _build_scenario_review_tab(manifest: dict) -> None:
    scenarios = iter_manifest_scenarios(manifest)
    default_scenario = scenarios[0] if scenarios else DemoScenario(
        "calm_monitoring",
        "Без инцидентов",
        "Без инцидентов",
        "Кампус",
    )
    default = _summary_for(default_scenario)

    gr.Markdown(
        """
        ## Консоль разбора сценариев
        <div class="scenario-copy">
        Режим повтора для инвесторского демо: Kuzet AI показывает спокойные сцены,
        оружие, агрессию, дым/огонь, доказательства из JSON-журнала и демо-предпросмотр Telegram без live-отправки.
        </div>
        """
    )

    with gr.Row():
        with gr.Column(scale=7):
            video_out = gr.Video(
                label="Аннотированное видео",
                value=default["video"],
                height=430,
            )
            with gr.Row(elem_classes=["scenario-buttons"]):
                buttons = []
                for scenario in scenarios:
                    button = gr.Button(scenario.title, variant="secondary")
                    buttons.append((button, scenario))

        with gr.Column(scale=5):
            verdict = gr.HTML(_verdict_html(default), label="Вердикт")
            gr.Markdown("### Лента доказательств")
            timeline = gr.HTML(_timeline_html(default), label="Лента доказательств")
            telegram = gr.Textbox(
                label="Предпросмотр Telegram · Демо-режим",
                value=_telegram_text(default),
                lines=7,
                interactive=False,
            )
            raw_log = gr.JSON(label="Детали детекции из JSON", value=default["raw_log"])

    for button, scenario in buttons:
        button.click(
            lambda selected=scenario: _load_scenario(selected),
            outputs=[video_out, verdict, timeline, telegram, raw_log],
        )


def _build_library_tab(manifest: dict) -> None:
    clips = manifest.get("clips", [])

    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### Все подготовленные клипы")
            clip_buttons = []
            for clip in clips:
                btn = gr.Button(
                    clip.get("title", clip["id"]),
                    variant="secondary",
                    size="sm",
                )
                clip_buttons.append((btn, clip))

        with gr.Column(scale=2):
            video_out = gr.Video(label="Аннотированное видео", height=400)
            event_log = gr.JSON(label="Журнал событий", value={})

    for btn, clip in clip_buttons:
        annotated_path = DEMOS_DIR / "reel" / "annotated" / f"{clip['id']}_annotated.mp4"
        log_path = annotated_path.with_suffix(".json")

        def make_loader(ap: Path, lp: Path):
            def load_clip():
                video = str(ap) if ap.exists() else None
                summary = build_scenario_summary(clip["id"], ap, lp)
                log = summary["raw_log"]
                return video, log

            return load_clip

        btn.click(make_loader(annotated_path, log_path), outputs=[video_out, event_log])


def _kpi_html(kpis: SessionKpis) -> str:
    alert_cls = " alert" if kpis.incidents > 0 else ""
    wconf = kpis.weapon_conf
    wconf_color = "#fecaca" if wconf >= 0.40 else "#fbbf24" if wconf >= 0.25 else "#94a3b8"
    mod_badges = " ".join(
        f'<span style="color:{"#fecaca" if m["active"] else "#4ade80" if m["loaded"] else "#94a3b8"};'
        f'font-weight:700;font-size:12px">{html.escape(m["label"])}</span>'
        for m in kpis.modules
    )
    return (
        f'<div class="kpi-strip">'
        f'<div class="kpi-cell"><div class="kpi-label">Время</div>'
        f'<div class="kpi-value">{html.escape(kpis.elapsed_str)}</div></div>'
        f'<div class="kpi-cell"><div class="kpi-label">FPS</div>'
        f'<div class="kpi-value">{kpis.fps:.1f}</div></div>'
        f'<div class="kpi-cell"><div class="kpi-label">Кадров</div>'
        f'<div class="kpi-value">{kpis.frames}</div></div>'
        f'<div class="kpi-cell{alert_cls}"><div class="kpi-label">Инцидентов</div>'
        f'<div class="kpi-value">{kpis.incidents}</div></div>'
        f'<div class="kpi-cell"><div class="kpi-label">Оружие (ув.)</div>'
        f'<div class="kpi-value" style="color:{wconf_color};font-size:20px">'
        f'{wconf:.0%}</div></div>'
        f'<div class="kpi-cell"><div class="kpi-label">Последний</div>'
        f'<div class="kpi-value" style="font-size:13px;padding-top:5px">'
        f'{html.escape(kpis.last_incident_str)}</div></div>'
        f'<div class="kpi-cell" style="min-width:160px"><div class="kpi-label">Модули</div>'
        f'<div style="display:flex;gap:8px;padding-top:4px">{mod_badges}</div></div>'
        f'</div>'
    )


def _incident_log_html(incidents: list) -> str:
    from protector.overlay import module_label as _ml

    if not incidents:
        return '<div class="empty-state">Норма: инцидентов нет.</div>'
    body = []
    for inc in incidents:
        body.append(
            f'<div class="timeline-row">'
            f'<div class="timeline-top">'
            f'<div><div class="timeline-module">{html.escape(_ml(inc.module))}</div>'
            f'<div class="timeline-time">t={inc.start_t:.1f} сек</div></div>'
            f'<div class="timeline-conf">{inc.confidence:.0%}</div>'
            f'</div>'
            f'<div class="timeline-reason">{html.escape(inc.reason[:50])}</div>'
            f'</div>'
        )
    return f'<div class="timeline">{"".join(body)}</div>'


def _build_live_tab() -> None:
    gr.Markdown(
        "### Живая камера\n"
        "Реальная инференс-камера: поза, оружие, дым/огонь. Демо-окно ~1–3 минуты.\n\n"
        "_Детекторы загружаются при первом кадре — несколько секунд ожидания нормально._\n\n"
        "_Разрешите доступ к камере в браузере. Если кадр пустой — проверьте, что камера не занята другим приложением._"
    )

    _empty_kpis = WebcamSession().kpis()
    state = gr.State(value=WebcamSession())

    with gr.Row():
        with gr.Column(scale=3):
            webcam_in = gr.Image(sources=["webcam"], streaming=True, label="Камера")
            reset_btn = gr.Button("Сбросить сессию", variant="secondary")
        with gr.Column(scale=4):
            webcam_out = gr.Image(label="Аннотированный кадр", streaming=True)
            kpi_strip = gr.HTML(_kpi_html(_empty_kpis), label="KPI")
            gr.Markdown("#### Лента инцидентов")
            incident_log = gr.HTML(_incident_log_html([]), label="Инциденты")

    def on_frame(frame_rgb, sess: WebcamSession):
        if frame_rgb is None:
            return None, _kpi_html(sess.kpis()), _incident_log_html(sess.recent_incidents())
        import numpy as np  # noqa: F401

        frame_bgr = cv2.cvtColor(frame_rgb, cv2.COLOR_RGB2BGR)
        try:
            annotated_bgr = sess.process_frame(frame_bgr)
            annotated_rgb = cv2.cvtColor(annotated_bgr, cv2.COLOR_BGR2RGB)
        except Exception:
            annotated_rgb = frame_rgb
        return (
            annotated_rgb,
            _kpi_html(sess.kpis()),
            _incident_log_html(sess.recent_incidents()),
        )

    webcam_in.stream(
        on_frame,
        inputs=[webcam_in, state],
        outputs=[webcam_out, kpi_strip, incident_log],
    )

    def on_reset(sess: WebcamSession):
        sess.reset()
        return _kpi_html(sess.kpis()), _incident_log_html(sess.recent_incidents())

    reset_btn.click(on_reset, inputs=state, outputs=[kpi_strip, incident_log])


def _build_how_it_works_tab() -> None:
    gr.Markdown("""
    ## Как работает Kuzet AI

    ### Архитектура

    ```
    Видео / камера
          │
          ├─ YOLO Pose + ByteTrack  →  скелеты людей + track ID
          ├─ YOLO Weapons           →  быстрые кандидаты пистолета / ножа
          ├─ OWLv2 Verifier         →  подтверждение сильных кандидатов оружия
          ├─ YOLO Fire/Smoke        →  дым / огонь
          │
          └─ [Режим файла]
               ├─ X-CLIP             →  оценка агрессии по окну кадров
               └─ ViT Classifier     →  второй сигнал по кадрам
                         │
                         ▼
                  Incident Fusion  →  N-of-M дебаунсинг → инциденты
                         │
                         ▼
                  Overlay Renderer  →  MP4 + JSON-журнал
    ```

    ### Модули

    | Модуль | Модель | Подход |
    |---|---|---|
    | **Pose + Tracking** | YOLOv8n-pose + ByteTrack | Скелеты и track ID |
    | **Оружие** | YOLO ensemble + OWLv2 verifier | Двухэтапная проверка пистолета / ножа |
    | **Агрессия** | X-CLIP + ViT | Видео-классификация и второй сигнал |
    | **Дым / огонь** | YOLO backend | Детекция тревожных объектов |

    ### Честная рамка MVP

    Демо работает в режиме повтора на подготовленных клипах. Telegram показан как
    демо-предпросмотр, без live-отправки. Цель — показать продуктовый workflow:
    сигнал, доказательства, журнал, эскалация ответственному сотруднику.

    ---
    *MVP работает локально на Apple Silicon.*
    """)


def create_app() -> gr.Blocks:
    manifest = _load_manifest()

    with gr.Blocks(title="Kuzet AI", fill_width=True) as app:
        gr.HTML("""
        <div class="header-bar">
          <div>
            <div class="header-title">Kuzet AI</div>
            <div class="header-sub">ИИ-видеоаналитика для безопасности школ и кампусов</div>
          </div>
          <div class="mode-chip">Локальный MVP · Режим повтора</div>
        </div>
        """)

        with gr.Tabs():
            with gr.Tab("Консоль сценариев"):
                _build_scenario_review_tab(manifest)

            with gr.Tab("Живая камера"):
                _build_live_tab()

        with gr.Accordion("Дополнительно: библиотека и архитектура", open=False):
            with gr.Tab("Библиотека клипов"):
                _build_library_tab(manifest)

            with gr.Tab("Как это работает"):
                _build_how_it_works_tab()

    return app


def launch(port: int = 7860) -> None:
    app = create_app()
    app.launch(server_port=port, share=False, css=CSS, theme=gr.themes.Base(), footer_links=[])
