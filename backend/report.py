# report.py
# =============================================================================
# PDF INCIDENT REPORT GENERATOR  (MVP Feature 6)
#
# Turns the alerts stored in the database into a professional PDF containing:
#   - an executive summary
#   - a colour-coded alert overview table (now including MITRE ATT&CK IDs)
#   - detailed findings per alert: evidence, ATT&CK technique, recommended action
#   - a MITRE ATT&CK coverage summary
#
# LIBRARY: reportlab "platypus" - we build a list of flowable elements called
# `story` and reportlab arranges them across pages automatically.
#
# The PDF is built in memory (io.BytesIO) so the API can stream the bytes
# straight to the browser as a download.
# =============================================================================

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

# We reuse the SAME MITRE mapping the explanation engine uses, so the dashboard
# and the PDF can never disagree with each other.
from explain import MITRE_MAP

RISK_COLORS = {
    "High": colors.HexColor("#c0392b"),     # red
    "Medium": colors.HexColor("#b9770e"),   # amber
    "Low": colors.HexColor("#1e8449"),      # green
}


def build_pdf(alerts, total_logs: int) -> bytes:
    """
    Build the incident report and return it as raw PDF bytes.

    alerts     : list of Alert database rows (already sorted by risk)
    total_logs : how many log entries were analysed
    """

    # ---------------------------------------------------------------------
    # 1. In-memory output file + A4 page template
    # ---------------------------------------------------------------------
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="SentinelAI Incident Report",
    )

    # ---------------------------------------------------------------------
    # 2. Text styles
    # ---------------------------------------------------------------------
    base = getSampleStyleSheet()
    style_title = ParagraphStyle("t", parent=base["Title"], fontSize=19, spaceAfter=2)
    style_meta = ParagraphStyle("m", parent=base["Normal"], fontSize=9,
                                textColor=colors.HexColor("#666666"), spaceAfter=12)
    style_h2 = ParagraphStyle("h", parent=base["Heading2"], fontSize=13,
                              spaceBefore=14, spaceAfter=6)
    style_body = ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13.5)
    style_action = ParagraphStyle("a", parent=style_body,
                                  textColor=colors.HexColor("#1e8449"))
    style_mitre = ParagraphStyle("mi", parent=style_body,
                                 textColor=colors.HexColor("#5b3fa8"))
    style_cell = ParagraphStyle("c", parent=base["Normal"], fontSize=7.6, leading=10)
    style_cellh = ParagraphStyle("ch", parent=style_cell, fontName="Helvetica-Bold",
                                 textColor=colors.white)

    # ---------------------------------------------------------------------
    # 3. Summary numbers
    # ---------------------------------------------------------------------
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    count_high = sum(1 for a in alerts if a.risk_level == "High")
    count_medium = sum(1 for a in alerts if a.risk_level == "Medium")
    count_low = sum(1 for a in alerts if a.risk_level == "Low")

    story = []

    # ---------------------------------------------------------------------
    # 4. Header + executive summary
    # ---------------------------------------------------------------------
    story.append(Paragraph("SentinelAI - Security Incident Report", style_title))
    story.append(Paragraph(
        f"Generated {generated_at} &nbsp;|&nbsp; AI-Powered Security Operations Assistant "
        f"&nbsp;|&nbsp; CSE 499A, Group G-9",
        style_meta,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))

    story.append(Paragraph("Executive summary", style_h2))
    story.append(Paragraph(
        f"SentinelAI analysed <b>{total_logs}</b> log events and raised "
        f"<b>{len(alerts)}</b> security alerts: <b>{count_high} High</b>, "
        f"<b>{count_medium} Medium</b> and <b>{count_low} Low</b> risk. "
        f"Detection combined a rule engine for known attack patterns with an "
        f"unsupervised Isolation Forest anomaly model, using an escalation-only "
        f"risk-fusion policy (the AI may raise a risk score but never overrules a "
        f"confirmed rule detection). Findings are mapped to MITRE ATT&amp;CK "
        f"techniques for cross-referencing with industry threat intelligence.",
        style_body,
    ))

    # ---------------------------------------------------------------------
    # 5. Alert overview table (now with an ATT&CK column)
    # ---------------------------------------------------------------------
    story.append(Paragraph("Alert overview", style_h2))

    # NOTE: "&" must be written as "&amp;" inside a reportlab Paragraph,
    # otherwise reportlab treats it as the start of an XML entity.
    header = ["#", "Attack type", "ATT&amp;CK", "Source IP", "Account", "Risk", "Score"]
    table_data = [[Paragraph(h, style_cellh) for h in header]]

    for index, alert in enumerate(alerts, start=1):
        technique = MITRE_MAP.get(alert.attack_type)
        table_data.append([
            Paragraph(str(index), style_cell),
            Paragraph(alert.attack_type, style_cell),
            Paragraph(technique["id"] if technique else "-", style_cell),
            Paragraph(alert.source_ip or "-", style_cell),
            Paragraph(alert.username or "-", style_cell),
            Paragraph(alert.risk_level, style_cell),
            Paragraph(str(alert.risk_score), style_cell),
        ])

    table = Table(
        table_data,
        colWidths=[0.8 * cm, 4.0 * cm, 2.0 * cm, 3.4 * cm, 2.4 * cm, 1.6 * cm, 1.2 * cm],
        repeatRows=1,
    )

    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2233")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f5f9")]),
    ]
    # Colour the "Risk" cell of each row according to its level.
    for row_index, alert in enumerate(alerts, start=1):
        risk_color = RISK_COLORS.get(alert.risk_level, colors.black)
        table_style.append(("TEXTCOLOR", (5, row_index), (5, row_index), risk_color))

    table.setStyle(TableStyle(table_style))
    story.append(table)

    # ---------------------------------------------------------------------
    # 6. Detailed findings
    # ---------------------------------------------------------------------
    story.append(Paragraph("Detailed findings and recommended actions", style_h2))

    for index, alert in enumerate(alerts, start=1):
        technique = MITRE_MAP.get(alert.attack_type)

        story.append(Paragraph(
            f"<b>{index}. {alert.attack_type}</b> &nbsp;-&nbsp; "
            f"{alert.risk_level} risk (score {alert.risk_score}/100)",
            style_body,
        ))

        # The evidence string also carries the AI anomaly score and, when SHAP
        # attribution is available, the features that drove the decision.
        story.append(Paragraph(f"<b>Evidence:</b> {alert.evidence}", style_body))

        if technique:
            story.append(Paragraph(
                f"<b>MITRE ATT&amp;CK:</b> {technique['id']} - {technique['name']} "
                f"({technique['tactic']})",
                style_mitre,
            ))

        story.append(Paragraph(
            f"<b>Recommended action:</b> {alert.recommendation}", style_action
        ))
        story.append(Spacer(1, 10))

    # ---------------------------------------------------------------------
    # 7. ATT&CK coverage summary - which techniques appeared, and how often
    # ---------------------------------------------------------------------
    coverage = {}
    for alert in alerts:
        technique = MITRE_MAP.get(alert.attack_type)
        if technique:
            key = (technique["id"], technique["name"], technique["tactic"])
            coverage[key] = coverage.get(key, 0) + 1

    if coverage:
        story.append(Paragraph("MITRE ATT&amp;CK coverage", style_h2))
        cov_data = [[Paragraph(h, style_cellh)
                     for h in ["Technique ID", "Technique", "Tactic", "Alerts"]]]
        for (tid, tname, tactic), count in sorted(coverage.items()):
            cov_data.append([
                Paragraph(tid, style_cell),
                Paragraph(tname, style_cell),
                Paragraph(tactic, style_cell),
                Paragraph(str(count), style_cell),
            ])
        cov_table = Table(
            cov_data,
            colWidths=[2.4 * cm, 6.0 * cm, 5.2 * cm, 1.8 * cm],
            repeatRows=1,
        )
        cov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2233")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f3f5f9")]),
        ]))
        story.append(cov_table)

    # ---------------------------------------------------------------------
    # 8. Footer
    # ---------------------------------------------------------------------
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated automatically by SentinelAI. Detection covers brute force, credential "
        "stuffing, password spraying, impossible travel and port scanning, plus Isolation "
        "Forest anomaly scoring with SHAP feature attribution. Technique identifiers follow "
        "the MITRE ATT&amp;CK Enterprise matrix.",
        style_meta,
    ))

    doc.build(story)
    return buffer.getvalue()
