"""
Build Kuzet AI deployment cost model Excel workbook.
Usage: uv run python docs/build_cost_model.py
Output: docs/kuzet_cost_model.xlsx
"""
from __future__ import annotations
import math
from pathlib import Path
import openpyxl
from openpyxl.styles import (
    PatternFill, Font, Alignment, Border, Side, numbers
)
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.chart.series import SeriesLabel

OUT = Path(__file__).parent / "kuzet_cost_model.xlsx"

# ── colour palette ────────────────────────────────────────────────────────────
C_HEADER   = "1E3A5F"   # dark navy
C_INPUT    = "FFF9C4"   # pale yellow  → user fills these
C_FORMULA  = "E8F5E9"   # pale green   → computed
C_SECTION  = "D0E4F7"   # light blue   → section headers
C_WARN     = "FFF3CD"   # amber        → unverified / estimate
C_WHITE    = "FFFFFF"
C_TITLE    = "E11D48"   # Kuzet red

def _fill(hex_color: str) -> PatternFill:
    return PatternFill("solid", fgColor=hex_color)

def _font(bold=False, color="000000", size=11) -> Font:
    return Font(bold=bold, color=color, size=size, name="Calibri")

def _border(style="thin") -> Border:
    s = Side(style=style)
    return Border(left=s, right=s, top=s, bottom=s)

def _hdr(ws, row, col, text, width_hint=None):
    c = ws.cell(row=row, column=col, value=text)
    c.fill = _fill(C_HEADER)
    c.font = _font(bold=True, color="FFFFFF")
    c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
    c.border = _border()
    if width_hint:
        ws.column_dimensions[get_column_letter(col)].width = width_hint

def _section(ws, row, col, text, span=1, color=C_SECTION):
    c = ws.cell(row=row, column=col, value=text)
    c.fill = _fill(color)
    c.font = _font(bold=True, size=11)
    c.alignment = Alignment(horizontal="left", vertical="center")
    c.border = _border()
    if span > 1:
        ws.merge_cells(start_row=row, start_column=col,
                       end_row=row, end_column=col + span - 1)

def _inp(ws, row, col, value, fmt="General", note=None):
    """Yellow input cell."""
    c = ws.cell(row=row, column=col, value=value)
    c.fill = _fill(C_INPUT)
    c.font = _font()
    c.border = _border()
    c.number_format = fmt
    c.alignment = Alignment(horizontal="right")
    if note:
        c.comment = openpyxl.comments.Comment(note, "Kuzet AI Model")
    return c

def _calc(ws, row, col, formula, fmt="General"):
    """Green formula cell."""
    c = ws.cell(row=row, column=col, value=formula)
    c.fill = _fill(C_FORMULA)
    c.font = _font()
    c.border = _border()
    c.number_format = fmt
    c.alignment = Alignment(horizontal="right")
    return c

def _lbl(ws, row, col, text, bold=False, wrap=False):
    c = ws.cell(row=row, column=col, value=text)
    c.font = _font(bold=bold)
    c.border = _border()
    c.alignment = Alignment(wrap_text=wrap, vertical="center")
    return c

def _warn(ws, row, col, text):
    c = ws.cell(row=row, column=col, value=text)
    c.fill = _fill(C_WARN)
    c.font = _font(size=9)
    c.alignment = Alignment(wrap_text=True, vertical="center")

NUM_KZT  = '#,##0 [$₸-43F]'
NUM_PCT  = '0.0%'
NUM_INT  = '#,##0'
NUM_USD  = '$#,##0'
NUM_2DP  = '#,##0.00'

# ── Sheet 1: INPUTS ───────────────────────────────────────────────────────────
def build_inputs(wb: openpyxl.Workbook) -> openpyxl.worksheet.worksheet.Worksheet:
    ws = wb.active
    ws.title = "Inputs"
    ws.sheet_view.showGridLines = True
    ws.column_dimensions["A"].width = 38
    ws.column_dimensions["B"].width = 20
    ws.column_dimensions["C"].width = 16
    ws.column_dimensions["D"].width = 44

    # Title
    t = ws.cell(row=1, column=1, value="Kuzet AI — Cost Model Inputs")
    t.font = Font(bold=True, size=16, color=C_TITLE, name="Calibri")
    ws.merge_cells("A1:D1")
    t.alignment = Alignment(horizontal="left")

    ws.cell(row=2, column=1, value="Yellow = fill from Yandex meeting  |  Green = auto-calculated  |  Amber = unverified estimate")
    ws.merge_cells("A2:D2")
    ws.cell(row=2, column=1).font = _font(size=9)

    r = 4
    def block(title):
        nonlocal r
        _section(ws, r, 1, title, span=4)
        r += 1

    def row_inp(label, val, fmt="General", unit="", note=None):
        nonlocal r
        _lbl(ws, r, 1, label)
        _inp(ws, r, 2, val, fmt=fmt, note=note)
        _lbl(ws, r, 3, unit)
        r += 1
        return r - 1   # return row number for reference

    def row_lbl(label, val, unit="", fmt="General"):
        nonlocal r
        _lbl(ws, r, 1, label)
        c = ws.cell(row=r, column=2, value=val)
        c.font = _font()
        c.border = _border()
        c.number_format = fmt
        c.alignment = Alignment(horizontal="right")
        _lbl(ws, r, 3, unit)
        r += 1

    # ── SCALE ─────────────────────────────────────────────────────────────────
    block("📐 Deployment Scale")
    row_lbl("Total schools", 1170, "schools")
    row_lbl("Cameras per school (avg)", 27, "cameras")
    row_lbl("Total camera streams  [= schools × cams]", "=Inputs!B5*Inputs!B6", "streams", NUM_INT)
    row_inp("Camera resolution", "1080p", note="720p / 1080p / 4K — affects bitrate & GPU count")
    row_inp("Video codec", "H.265", note="H.264 ≈ 2–3 Mbps/stream; H.265 ≈ 1–1.5 Mbps/stream")
    row_inp("Bitrate per stream (Mbps)", 1.5, "#,##0.0",  "Mbps",
            note="H.265@15fps≈1.5; H.264@30fps≈3.0 (source: Reolink / Hikvision)")
    r_streams = 7  # row of total streams formula

    r += 1
    block("⏱  Operating Schedule")
    row_inp("School days per month", 22, NUM_INT, "days",
            note="Typical Kazakhstan school calendar")
    row_inp("Active hours per school day", 12, NUM_INT, "hours",
            note="07:00–19:00 typical")
    row_lbl("Active hours / month [= days × hrs]", "=Inputs!B13*Inputs!B14", "h/mo", NUM_INT)
    row_inp("Concurrency factor (c)", 0.55, NUM_PCT, "",
            note="Fraction of cameras that need simultaneous inference. "
                 "c=0.55 = peak passing-period load. Safety-critical: don't go below 0.50.")

    r += 1
    block("☁️  Cloud GPU — Yandex T4i (VERIFIED: official KZT price-list, 2026-01-01)")
    row_inp("T4i GPU rate (₸/GPU·hour)", 1191.0715, NUM_KZT, "₸/GPU·h",
            note="Official Yandex KZ price-list screenshot, eff. 2026-01-01")
    row_inp("T4i vCPU rate (₸/100%-vCPU·hour)", 8.70, NUM_KZT, "₸/vCPU·h",
            note="Official Yandex KZ price-list screenshot, eff. 2026-01-01")
    row_inp("T4i RAM rate (₸/GB·hour)", 2.3304, NUM_KZT, "₸/GB·h",
            note="Official Yandex KZ price-list screenshot, eff. 2026-01-01")
    row_inp("vCPUs per T4i VM", 8, NUM_INT, "vCPU")
    row_inp("RAM per T4i VM (GB)", 32, NUM_INT, "GB")
    row_lbl("T4i box total rate (₸/h) [= GPU + vCPU×rate + RAM×rate]",
            "=Inputs!B18+Inputs!B19*Inputs!B20+Inputs!B21*Inputs!B22",
            "₸/h", NUM_KZT)
    row_inp("CVoS discount  ⚠️ ESTIMATE — get from Yandex", 0.20, NUM_PCT, "",
            note="UNVERIFIED. Yandex CVoS 1-yr typical 15–25%. Confirm at meeting.")
    row_inp("Streams per T4i GPU  (S)  ⚠️ UNBENCHMARKED — get from Yandex", 40, NUM_INT, "streams/GPU",
            note="UNBENCHMARKED. NVIDIA DeepStream T4: 41×1080p30 H.264 (light detector). "
                 "Current Python stack: ~1–5. Post-TensorRT target: 20–40. CONFIRM AT MEETING.")

    r += 1
    _warn(ws, r, 1, "⚠️  T4i is the ONLY GPU Yandex offers in the Kazakhstan region today. "
                    "A100/V100/H100 are Russia-region only (ru-central1). Confirm roadmap at meeting.")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
    r += 2

    block("☁️  Cloud GPU — A100 80GB (⚠️ UNVERIFIED 3rd-party vendor)")
    row_inp("A100 rate (₸/hour)  ⚠️ UNVERIFIED VENDOR", 2500, NUM_KZT, "₸/h",
            note="UNVERIFIED. User screenshot, vendor not identified. Confirm vendor SLA, "
                 "data-residency, and whether minors' video can leave KZ region.")
    row_inp("A100 monthly commit rate (₸/month)  ⚠️ UNVERIFIED", 890000, NUM_KZT, "₸/mo",
            note="UNVERIFIED. Only use if vendor confirmed. Monthly commit vs hourly.")
    row_inp("Streams per A100 GPU  (S)  ⚠️ UNBENCHMARKED", 100, NUM_INT, "streams/GPU",
            note="UNBENCHMARKED. A100 has ~5 NVDEC units (decode-bound for multi-stream). "
                 "Post-TensorRT realistic: 50–200. BENCHMARK BEFORE USING.")

    r += 1
    block("🖥  Edge Hardware")
    row_inp("Edge box price (USD/unit)  — Gaming PC RTX 4070 all-in", 1450, NUM_USD, "USD",
            note="All-in: PC + GPU + NVMe + install/networking. RTX 4070 $599 MSRP (NVIDIA official). "
                 "Budget option: RTX 4060 Ti 16GB ~$1,280 all-in.")
    row_inp("USD → KZT exchange rate", 490, NUM_INT, "₸/$",
            note="₸489.67 on 2026-06-01 (TradingEconomics / National Bank of Kazakhstan). "
                 "Forecasts: ₸460–503 range. FX risk on hardware purchase.")
    row_inp("Boxes per school", 1, NUM_INT, "boxes",
            note="1 box assumes post-optimization pipeline (motion gate + TensorRT). "
                 "Set to 2 if throughput benchmark shows < 27 streams/box.")
    row_inp("Hardware amortization years", 5, NUM_INT, "years")
    row_inp("Spare/failure buffer", 0.10, NUM_PCT, "",
            note="10% for gaming PC (consumer-grade 24/7 failure rate). "
                 "5% for Jetson (industrial). Adjust accordingly.")
    row_inp("Average power draw per box (W)", 200, NUM_INT, "W",
            note="Gaming PC: 150–250W avg (idle ~80W, peak ~300W). "
                 "Jetson AGX Orin: 15–60W.")
    row_inp("Electricity rate (₸/kWh)", 36.7, NUM_2DP, "₸/kWh",
            note="KZ business rate ≈ ₸36.66/kWh (GlobalPetrolPrices.com, Jun-2025). "
                 "Confirm who pays: school or Kuzet AI contract.")
    row_inp("School pays electricity? (1=yes, 0=no)", 1, NUM_INT, "",
            note="If 1, electricity cost is $0 to Kuzet. If 0, add to Kuzet opex.")

    r += 1
    block("☁️  Cloud Non-GPU (Dashboard, DB, Storage, Alerts)  ⚠️ ESTIMATE")
    row_inp("Cloud non-GPU monthly (₸/mo)  ⚠️ ESTIMATE", 500000, NUM_KZT, "₸/mo",
            note="ESTIMATE: Managed Postgres + Redis + Object Storage + alert egress. "
                 "~500k ₸/mo for 1,170 schools. GET OFFICIAL KZT RATES FROM YANDEX.")
    row_inp("Event clip storage (GB/school/month)", 10, NUM_INT, "GB/school/mo",
            note="Only events stored (not raw streams). ~10 GB/school/mo at 1 alert/day "
                 "with 2-min clips. Adjust to actual alert frequency.")
    row_inp("Object Storage rate (₸/GB·month)  ⚠️ ESTIMATE", 4.0, NUM_2DP, "₸/GB·mo",
            note="ESTIMATE. Get official Yandex KZ Object Storage rate at meeting.")

    r += 1
    block("🔁  Cloud GPU Retrain (Scenario A — edge-first only)")
    row_inp("Retrain GPU hours per week", 8, NUM_INT, "h/week",
            note="~8h/week for weekly retrain of distilled skeleton model on reviewed events.")

    return ws


# ── Sheet 2: CLOUD RESULTS ────────────────────────────────────────────────────
def build_cloud(wb, inp_ws):
    ws = wb.create_sheet("Cloud Results")
    ws.column_dimensions["A"].width = 42
    ws.column_dimensions["B"].width = 22
    ws.column_dimensions["C"].width = 22
    ws.column_dimensions["D"].width = 22
    ws.column_dimensions["E"].width = 22

    t = ws.cell(row=1, column=1, value="Kuzet AI — Cloud Inference Cost (Scenario B)")
    t.font = Font(bold=True, size=14, color=C_TITLE, name="Calibri")
    ws.merge_cells("A1:E1")

    r = 3
    _hdr(ws, r, 1, "Parameter", 42)
    _hdr(ws, r, 2, "Yandex T4i", 22)
    _hdr(ws, r, 3, "A100 ⚠️ UNVERIF.", 22)
    _hdr(ws, r, 4, "Unit", 16)
    _hdr(ws, r, 5, "Notes", 30)
    ws.column_dimensions["E"].width = 36
    r += 1

    def row_c(label, f_t4, f_a100, unit="", note=""):
        nonlocal r
        _lbl(ws, r, 1, label)
        _calc(ws, r, 2, f_t4, NUM_KZT if "₸" in unit else (NUM_INT if unit in ("GPUs","streams") else "General"))
        _calc(ws, r, 3, f_a100, NUM_KZT if "₸" in unit else (NUM_INT if unit in ("GPUs","streams") else "General"))
        _lbl(ws, r, 4, unit)
        _lbl(ws, r, 5, note, wrap=True)
        r += 1

    # Key inputs echoed for readability
    _section(ws, r, 1, "Key Inputs (from Inputs sheet)", span=5)
    r += 1
    _lbl(ws, r, 1, "Total streams"); _calc(ws, r, 2, "=Inputs!B7", NUM_INT); r += 1
    _lbl(ws, r, 1, "Active hours/month"); _calc(ws, r, 2, "=Inputs!B15", NUM_INT); r += 1
    _lbl(ws, r, 1, "Concurrency factor (c)"); _calc(ws, r, 2, "=Inputs!B16", NUM_PCT); r += 1
    _lbl(ws, r, 1, "S — streams/T4i (UNBENCHMARKED)"); _calc(ws, r, 2, "=Inputs!B25", NUM_INT)
    _calc(ws, r, 3, "=Inputs!B29", NUM_INT); r += 1
    _lbl(ws, r, 1, "CVoS discount"); _calc(ws, r, 2, "=Inputs!B24", NUM_PCT); r += 1
    r += 1

    _section(ws, r, 1, "Cloud GPU Sizing", span=5); r += 1
    row_c("Concurrent streams to serve [= total × c]",
          "=ROUND(Inputs!B7*Inputs!B16,0)", "=ROUND(Inputs!B7*Inputs!B16,0)", "streams")
    row_c("GPUs required  [= ceil(concurrent / S)]",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)", "GPUs",
          "CEILING = always round up (safety-critical)")
    row_c("GPU·hours per month  [= GPUs × active_h]",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15",
          "GPU·h/mo")
    row_c("GPU·hours per year",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15*12",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15*12",
          "GPU·h/yr")

    r += 1
    _section(ws, r, 1, "Cloud GPU Cost (₸)", span=5); r += 1
    row_c("Monthly GPU cost  [= GPUs × active_h × rate/h × (1−CVoS)]",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15*Inputs!B23*(1-Inputs!B24)",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15*Inputs!B27",
          "₸/mo", "A100: hourly × active_h (no CVoS applied — unverified vendor)")
    row_c("Annual GPU cost",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15*12*Inputs!B23*(1-Inputs!B24)",
          "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15*12*Inputs!B27",
          "₸/yr")

    r += 1
    _section(ws, r, 1, "Cloud Non-GPU Cost (₸)", span=5); r += 1
    row_c("Cloud non-GPU annual  (dashboard/DB/storage/alerts) ⚠️ ESTIMATE",
          "=Inputs!B43*12", "=Inputs!B43*12", "₸/yr",
          "⚠️ ESTIMATE — get official rates from Yandex")
    row_c("Event clip storage annual  [= GB/school × schools × rate × 12]",
          "=Inputs!B44*Inputs!B5*Inputs!B45*12",
          "=Inputs!B44*Inputs!B5*Inputs!B45*12", "₸/yr")

    r += 1
    _section(ws, r, 1, "TOTAL Cloud Annual Cost (₸)", span=5, color="D7E8D4"); r += 1
    # T4i total
    t4_total_formula = (
        "=CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15*12*Inputs!B23*(1-Inputs!B24)"
        "+Inputs!B43*12+Inputs!B44*Inputs!B5*Inputs!B45*12"
    )
    a100_total_formula = (
        "=CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15*12*Inputs!B27"
        "+Inputs!B43*12+Inputs!B44*Inputs!B5*Inputs!B45*12"
    )
    row_c("TOTAL annual (fleet)", t4_total_formula, a100_total_formula, "₸/yr")
    row_c("Per school / year",
          f"=({t4_total_formula[1:]})/Inputs!B5",
          f"=({a100_total_formula[1:]})/Inputs!B5", "₸/school/yr")
    row_c("Per camera / month",
          f"=({t4_total_formula[1:]})/Inputs!B7/12",
          f"=({a100_total_formula[1:]})/Inputs!B7/12", "₸/cam/mo")

    r += 2
    _warn(ws, r, 1,
          "⚠️  All cloud figures assume S (streams/GPU) is the Inputs!B25/B29 value, which is "
          "UNBENCHMARKED. With the current Python/PyTorch code S≈1–5 (10–40× more GPUs, "
          "10–40× more cost). These numbers only apply after a TensorRT/DeepStream rebuild.")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
    ws.row_dimensions[r].height = 36

    return ws


# ── Sheet 3: EDGE RESULTS ─────────────────────────────────────────────────────
def build_edge(wb):
    ws = wb.create_sheet("Edge Results")
    ws.column_dimensions["A"].width = 44
    ws.column_dimensions["B"].width = 22
    ws.column_dimensions["C"].width = 16
    ws.column_dimensions["D"].width = 36

    t = ws.cell(row=1, column=1, value="Kuzet AI — Edge-First Cost (Scenario A)")
    t.font = Font(bold=True, size=14, color=C_TITLE, name="Calibri")
    ws.merge_cells("A1:D1")

    r = 3
    _hdr(ws, r, 1, "Parameter", 44); _hdr(ws, r, 2, "Value", 22)
    _hdr(ws, r, 3, "Unit", 16); _hdr(ws, r, 4, "Notes", 36); r += 1

    def row_e(label, formula, unit="", note="", fmt=NUM_KZT):
        nonlocal r
        _lbl(ws, r, 1, label)
        _calc(ws, r, 2, formula, fmt)
        _lbl(ws, r, 3, unit)
        _lbl(ws, r, 4, note, wrap=True)
        r += 1

    _section(ws, r, 1, "Edge Hardware (one-time capex)", span=4); r += 1
    row_e("Box price in KZT  [= USD × FX]",
          "=Inputs!B33*Inputs!B34", "₸/box",
          "RTX 4070 gaming PC all-in ~$1,450 → ₸490 FX = ₸710,500")
    row_e("Total boxes (1,170 schools × boxes/school)",
          "=Inputs!B5*Inputs!B35", "boxes", "", NUM_INT)
    row_e("Total hardware capex  [= boxes × price]",
          "=Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34", "₸",
          "One-time purchase")
    row_e("Capex with spares buffer  [= capex × (1 + spare%)]",
          "=Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34*(1+Inputs!B37)", "₸")

    r += 1
    _section(ws, r, 1, "Annual Edge Hardware Cost (amortized)", span=4); r += 1
    row_e("Annual hardware cost  [= capex with spares ÷ amort years]",
          "=Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34*(1+Inputs!B37)/Inputs!B36",
          "₸/yr", "Straight-line, 5-yr")

    r += 1
    _section(ws, r, 1, "Electricity (if Kuzet pays)", span=4); r += 1
    row_e("Annual electricity  [= boxes × W × 8760h × ₸/kWh ÷ 1000]  (if Kuzet pays)",
          "=(1-Inputs!B39)*Inputs!B5*Inputs!B35*Inputs!B38*8760*Inputs!B38/1000",
          "₸/yr",
          "If school pays (Inputs!B39=1), this is ₸0. "
          "Electricity ₸36.7/kWh (GlobalPetrolPrices, Jun-2025).")
    # Correction: electricity formula
    # W × h × ₸/kWh / 1000
    ws.cell(row=r-1, column=2).value = (
        "=(1-Inputs!B39)*Inputs!B5*Inputs!B35*Inputs!B38*8760*Inputs!B40/1000"
    )

    r += 1
    _section(ws, r, 1, "Cloud Retrain GPU (intermittent)", span=4); r += 1
    row_e("Retrain GPU hours/year  [= h/week × 52]",
          "=Inputs!B47*52", "h/yr", "", NUM_INT)
    row_e("Retrain GPU cost/year  [= hours × T4i rate/h × (1−CVoS)]",
          "=Inputs!B47*52*Inputs!B23*(1-Inputs!B24)", "₸/yr",
          "One shared T4i VM, school-hours not relevant (batch, run anytime)")

    r += 1
    _section(ws, r, 1, "Cloud Non-GPU (same as cloud scenario)", span=4); r += 1
    row_e("Cloud non-GPU annual  ⚠️ ESTIMATE",
          "=Inputs!B43*12", "₸/yr", "⚠️ ESTIMATE — dashboard/DB/alerts/storage")
    row_e("Event clip storage annual",
          "=Inputs!B44*Inputs!B5*Inputs!B45*12", "₸/yr",
          "Edge stores locally; cloud only for reviewed/flagged clips")

    r += 1
    _section(ws, r, 1, "TOTAL Edge Annual Cost (₸)", span=4, color="D7E8D4"); r += 1
    edge_total = (
        "=Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34*(1+Inputs!B37)/Inputs!B36"
        "+(1-Inputs!B39)*Inputs!B5*Inputs!B35*Inputs!B38*8760*Inputs!B40/1000"
        "+Inputs!B47*52*Inputs!B23*(1-Inputs!B24)"
        "+Inputs!B43*12+Inputs!B44*Inputs!B5*Inputs!B45*12"
    )
    row_e("TOTAL annual (fleet)", edge_total, "₸/yr")
    row_e("Per school / year",
          f"=({edge_total[1:]})/Inputs!B5", "₸/school/yr")
    row_e("Per camera / month",
          f"=({edge_total[1:]})/Inputs!B7/12", "₸/cam/mo")
    row_e("One-time capex (hardware)",
          "=Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34*(1+Inputs!B37)", "₸",
          "Upfront hardware purchase")

    return ws, edge_total


# ── Sheet 4: TCO COMPARISON ───────────────────────────────────────────────────
def build_tco(wb, edge_total: str):
    ws = wb.create_sheet("TCO Comparison")
    ws.column_dimensions["A"].width = 32
    for col in "BCDEFG":
        ws.column_dimensions[col].width = 20

    t = ws.cell(row=1, column=1, value="Kuzet AI — 3-yr & 5-yr TCO + Break-Even")
    t.font = Font(bold=True, size=14, color=C_TITLE, name="Calibri")
    ws.merge_cells("A1:G1")

    r = 3
    _hdr(ws, r, 1, "Year", 28)
    _hdr(ws, r, 2, "Edge Cumulative ₸")
    _hdr(ws, r, 3, "Cloud T4i Cumulative ₸")
    _hdr(ws, r, 4, "Cloud A100 Cumulative ₸")
    _hdr(ws, r, 5, "Edge Annual ₸")
    _hdr(ws, r, 6, "Cloud T4i Annual ₸")
    _hdr(ws, r, 7, "Cloud A100 Annual ₸")
    r += 1

    # Cloud totals — replicate the formula references
    t4_annual = (
        "CEILING(Inputs!B7*Inputs!B16/Inputs!B25,1)*Inputs!B15*12*Inputs!B23*(1-Inputs!B24)"
        "+Inputs!B43*12+Inputs!B44*Inputs!B5*Inputs!B45*12"
    )
    a100_annual = (
        "CEILING(Inputs!B7*Inputs!B16/Inputs!B29,1)*Inputs!B15*12*Inputs!B27"
        "+Inputs!B43*12+Inputs!B44*Inputs!B5*Inputs!B45*12"
    )
    edge_annual = edge_total[1:]  # strip leading =

    # Edge capex paid in year 1
    edge_capex = "Inputs!B5*Inputs!B35*Inputs!B33*Inputs!B34*(1+Inputs!B37)"

    for yr in range(1, 6):
        ws.cell(row=r, column=1, value=f"Year {yr}").border = _border()
        # Edge: capex in yr 1 + annual opex every year
        if yr == 1:
            edge_cum = f"={edge_capex}+{edge_annual}"
            edge_ann = f"={edge_capex}+{edge_annual}"
        else:
            prev_row = r - 1
            edge_cum = f"=TCO!B{prev_row}+{edge_annual}"
            edge_ann = f"={edge_annual}"
        _calc(ws, r, 2, edge_cum, NUM_KZT)
        _calc(ws, r, 3, f"={'TCO!C'+str(r-1)+'+' if yr>1 else ''}{t4_annual}", NUM_KZT)
        _calc(ws, r, 4, f"={'TCO!D'+str(r-1)+'+' if yr>1 else ''}{a100_annual}", NUM_KZT)
        _calc(ws, r, 5, edge_ann, NUM_KZT)
        _calc(ws, r, 6, f"={t4_annual}", NUM_KZT)
        _calc(ws, r, 7, f"={a100_annual}", NUM_KZT)
        r += 1

    r += 1
    _section(ws, r, 1, "Summary", span=7); r += 1
    for label, col in [("3-yr TCO Edge", 2), ("3-yr TCO T4i", 3), ("3-yr TCO A100", 4)]:
        ws.cell(row=r, column=col-1, value=label).font = _font(bold=True)
        _calc(ws, r, col, f"=TCO!{get_column_letter(col)}{r-3}", NUM_KZT)
    r += 1
    for label, col in [("5-yr TCO Edge", 2), ("5-yr TCO T4i", 3), ("5-yr TCO A100", 4)]:
        ws.cell(row=r, column=col-1, value=label).font = _font(bold=True)
        _calc(ws, r, col, f"=TCO!{get_column_letter(col)}{r-4}", NUM_KZT)

    r += 2
    _warn(ws, r, 1,
          "⚠️  Break-even depends on S (streams/GPU) and CVoS — both unverified. "
          "Cloud is opex-heavy (no upfront); edge is capex-heavy (large upfront + low opex). "
          "At default inputs, edge breaks even vs cloud T4i around Year 1–2.")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=7)
    ws.row_dimensions[r].height = 42

    return ws


# ── Sheet 5: SENSITIVITY ──────────────────────────────────────────────────────
def build_sensitivity(wb):
    ws = wb.create_sheet("Sensitivity")
    ws.column_dimensions["A"].width = 28

    t = ws.cell(row=1, column=1, value="Kuzet AI — Sensitivity: Cloud T4i Annual Cost vs S and Concurrency")
    t.font = Font(bold=True, size=13, color=C_TITLE, name="Calibri")
    ws.merge_cells("A1:I1")

    ws.cell(row=2, column=1,
            value="All figures in millions of ₸/year. Fixed inputs: school-hours 264h/mo, CVoS from Inputs!B24, non-GPU from Inputs!B43.")
    ws.merge_cells("A2:I2")
    ws.cell(row=2, column=1).font = _font(size=9)

    S_values = [5, 10, 20, 40, 60, 80, 100]
    C_values = [0.40, 0.50, 0.60, 0.70, 0.80, 1.00]

    r = 4
    ws.cell(row=r, column=1, value="S →  /  c ↓").font = _font(bold=True)
    for j, s in enumerate(S_values):
        c = ws.cell(row=r, column=j+2, value=f"S={s}")
        c.fill = _fill(C_HEADER); c.font = _font(bold=True, color="FFFFFF")
        c.alignment = Alignment(horizontal="center")
        ws.column_dimensions[get_column_letter(j+2)].width = 16
    r += 1

    for cv in C_values:
        ws.cell(row=r, column=1, value=f"c={cv:.0%}").font = _font(bold=True)
        for j, s in enumerate(S_values):
            gpus = math.ceil(31590 * cv / s)
            # T4i box rate = 1335.24 ₸/h, school-hrs 264/mo, ×12, ×(1-CVoS default 0.20)
            # + non-gpu estimate 500k/mo × 12 = 6M
            annual = gpus * 264 * 12 * 1335.24 * (1 - 0.20) + 6_000_000
            c = ws.cell(row=r, column=j+2, value=round(annual / 1_000_000, 1))
            c.number_format = '#,##0.0 "M ₸"'
            c.alignment = Alignment(horizontal="right")
            c.border = _border()
            # heat colour
            if annual < 500_000_000:
                c.fill = _fill("C8E6C9")
            elif annual < 2_000_000_000:
                c.fill = _fill("FFF9C4")
            else:
                c.fill = _fill("FFCCBC")
        r += 1

    r += 1
    _warn(ws, r, 1,
          "Green < 500M ₸/yr  |  Yellow 500M–2B  |  Red > 2B. "
          "CVoS=20% and S values are ESTIMATES. Confirm both with Yandex expert.")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=9)

    return ws


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    wb = openpyxl.Workbook()

    inp_ws = build_inputs(wb)
    build_cloud(wb, inp_ws)
    _, edge_total = build_edge(wb)
    build_tco(wb, edge_total)
    build_sensitivity(wb)

    # Tab colours
    wb["Inputs"].sheet_properties.tabColor        = "1E3A5F"
    wb["Cloud Results"].sheet_properties.tabColor  = "2563EB"
    wb["Edge Results"].sheet_properties.tabColor   = "16A34A"
    wb["TCO Comparison"].sheet_properties.tabColor = "E11D48"
    wb["Sensitivity"].sheet_properties.tabColor    = "D97706"

    wb.save(OUT)
    print(f"✅  Written: {OUT}")

if __name__ == "__main__":
    main()
