# report.py
# =============================================================================
# PDF INCIDENT REPORT GENERATOR  (MVP Feature 6)
#
# PURPOSE:
#   Turn the alerts stored in our database into a professional PDF document
#   containing: an executive summary, a colour-coded alert table, and the
#   detailed evidence + recommended action for every alert.
#
# LIBRARY:
#   We use "reportlab", the standard Python PDF library. We build the document
#   with "platypus", reportlab's high-level page-layout system: we create a
#   list of flowable elements (paragraphs, tables, spacers) called `story`,
#   and reportlab arranges them across pages automatically.
#
# NOTE: we build the PDF in memory (io.BytesIO) instead of saving it to disk,
#   so the API can send the bytes straight to the browser as a download.
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

# Colour for each risk level, used in the summary table.
RISK_COLORS = {
    "High": colors.HexColor("#c0392b"),     # red
    "Medium": colors.HexColor("#b9770e"),   # amber
    "Low": colors.HexColor("#1e8449"),      # green
}


def build_pdf(alerts, total_logs: int) -> bytes:
    """
    Build the incident report and return it as raw PDF bytes.

    Parameters
    ----------
    alerts     : list of Alert database rows (already sorted by risk)
    total_logs : how many log entries were analysed

    Returns
    -------
    bytes : the finished PDF file, ready to send to the browser
    """

    # ---------------------------------------------------------------------
    # 1. Create an in-memory "file" and the page template (A4 with margins).
    # ---------------------------------------------------------------------
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="SentinelAI Incident Report",
    )

    # ---------------------------------------------------------------------
    # 2. Define text styles (font sizes, colours, spacing).
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

    # ---------------------------------------------------------------------
    # 3. Work out the summary numbers.
    # ---------------------------------------------------------------------
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    count_high = sum(1 for a in alerts if a.risk_level == "High")
    count_medium = sum(1 for a in alerts if a.risk_level == "Medium")
    count_low = sum(1 for a in alerts if a.risk_level == "Low")

    # `story` is the ordered list of elements reportlab will lay out.
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
        f"confirmed rule detection).",
        style_body,
    ))

    # ---------------------------------------------------------------------
    # 5. Summary table - one row per alert.
    # ---------------------------------------------------------------------
    story.append(Paragraph("Alert overview", style_h2))

    # First row is the header, then one row per alert.
    table_data = [["#", "Attack type", "Source IP", "Account", "Risk", "Score"]]
    for index, alert in enumerate(alerts, start=1):
        table_data.append([
            str(index),
            alert.attack_type,
            alert.source_ip or "-",
            alert.username or "-",
            alert.risk_level,
            str(alert.risk_score),
        ])

    table = Table(
        table_data,
        colWidths=[0.9 * cm, 4.6 * cm, 4.4 * cm, 2.6 * cm, 1.9 * cm, 1.6 * cm],
    )

    # Visual styling of the table.
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2233")),  # dark header
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f5f9")]),  # zebra stripes
    ]
    # Colour the "Risk" cell of each row according to its level.
    for row_index, alert in enumerate(alerts, start=1):
        risk_color = RISK_COLORS.get(alert.risk_level, colors.black)
        table_style.append(("TEXTCOLOR", (4, row_index), (4, row_index), risk_color))
        table_style.append(("FONTNAME", (4, row_index), (4, row_index), "Helvetica-Bold"))

    table.setStyle(TableStyle(table_style))
    story.append(table)

    # ---------------------------------------------------------------------
    # 6. Detailed findings - evidence and recommended action per alert.
    # ---------------------------------------------------------------------
    story.append(Paragraph("Detailed findings and recommended actions", style_h2))

    for index, alert in enumerate(alerts, start=1):
        story.append(Paragraph(
            f"<b>{index}. {alert.attack_type}</b> &nbsp;-&nbsp; "
            f"{alert.risk_level} risk (score {alert.risk_score}/100)",
            style_body,
        ))
        story.append(Paragraph(f"<b>Evidence:</b> {alert.evidence}", style_body))
        story.append(Paragraph(
            f"<b>Recommended action:</b> {alert.recommendation}", style_action
        ))
        story.append(Spacer(1, 10))   # blank space between findings

    # ---------------------------------------------------------------------
    # 7. Footer
    # ---------------------------------------------------------------------
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated automatically by SentinelAI. Detection covers brute force, credential "
        "stuffing, password spraying, impossible travel and port scanning, plus Isolation "
        "Forest anomaly scoring.",
        style_meta,
    ))

    # ---------------------------------------------------------------------
    # 8. Render everything into the PDF and return the raw bytes.
    # ---------------------------------------------------------------------
    doc.build(story)
    return buffer.getvalue()