"""Professional PDF report generator using ReportLab."""
import io
import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Brand colors
ORANGE = colors.HexColor("#E8651A")
NAVY = colors.HexColor("#0A2342")
RED = colors.HexColor("#DC2626")
HIGH_ORANGE = colors.HexColor("#EA580C")
AMBER = colors.HexColor("#D97706")
BLUE = colors.HexColor("#2563EB")
LIGHT_GRAY = colors.HexColor("#F3F4F6")

SEV_COLOR = {
    "Critical": RED,
    "High": HIGH_ORANGE,
    "Medium": AMBER,
    "Low": BLUE,
    "Info": colors.gray,
}


def generate_pdf_report(scan: dict, findings: list[dict], cis_results: list[dict] | None = None,
                        client_name: str | None = None, ai_roadmap: dict | None = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("Title2", fontSize=28, textColor=NAVY, spaceAfter=6,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER)
    h1 = ParagraphStyle("H1", fontSize=16, textColor=NAVY, spaceBefore=12, spaceAfter=6,
                         fontName="Helvetica-Bold")
    h2 = ParagraphStyle("H2", fontSize=12, textColor=NAVY, spaceBefore=8, spaceAfter=4,
                         fontName="Helvetica-Bold")
    body = ParagraphStyle("Body2", fontSize=10, textColor=colors.HexColor("#374151"),
                           spaceAfter=6, leading=14)
    small = ParagraphStyle("Small", fontSize=8, textColor=colors.gray)
    label_style = ParagraphStyle("Label", fontSize=9, textColor=colors.white,
                                  fontName="Helvetica-Bold")

    story = []

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("CLOUDWATCH", ParagraphStyle("Logo", fontSize=36,
                 textColor=ORANGE, fontName="Helvetica-Bold", alignment=TA_CENTER)))
    story.append(Paragraph("AI-Powered AWS Security Assessment", ParagraphStyle("Sub",
                 fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=2)))
    story.append(HRFlowable(width="100%", thickness=2, color=ORANGE, spaceAfter=20))
    story.append(Spacer(1, 1*cm))

    cover_data = [
        ["Client:", client_name or scan.get("account_alias", "AWS Account")],
        ["AWS Account ID:", scan.get("account_id", "—")],
        ["Scan Date:", datetime.fromisoformat(scan["started_at"]).strftime("%B %d, %Y") if scan.get("started_at") else "—"],
        ["Security Score:", f"{scan.get('security_score', '—')}/100  Grade: {scan.get('grade', '—')}"],
        ["Total Findings:", str(scan.get("total_findings", 0))],
        ["Prepared By:", "CLOUDWATCH AI Security Platform"],
    ]
    cover_table = Table(cover_data, colWidths=[4*cm, 12*cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("CONFIDENTIAL — For authorized personnel only.", small))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8))

    score = scan.get("security_score", 0) or 0
    grade = scan.get("grade", "F") or "F"
    grade_col = SEV_COLOR.get("Critical" if grade == "F" else "High" if grade == "D"
                              else "Medium" if grade == "C" else "Low" if grade == "B" else "Info", colors.green)

    score_data = [[f"Security Score: {score}/100", f"Grade: {grade}",
                   f"Critical: {scan.get('critical_count',0)}",
                   f"High: {scan.get('high_count',0)}",
                   f"Medium: {scan.get('medium_count',0)}"]]
    st = Table(score_data, colWidths=[3.5*cm]*5)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), NAVY),
        ("BACKGROUND", (1, 0), (1, 0), grade_col),
        ("BACKGROUND", (2, 0), (2, 0), RED),
        ("BACKGROUND", (3, 0), (3, 0), HIGH_ORANGE),
        ("BACKGROUND", (4, 0), (4, 0), AMBER),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.5*cm))

    if scan.get("ai_summary"):
        story.append(Paragraph(scan["ai_summary"], body))

    story.append(Spacer(1, 0.3*cm))

    # Findings breakdown table
    svc_counts: dict[str, dict] = {}
    for f in findings:
        svc = f.get("service", "Other")
        if svc not in svc_counts:
            svc_counts[svc] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        svc_counts[svc][f["severity"]] = svc_counts[svc].get(f["severity"], 0) + 1

    if svc_counts:
        table_data = [["Service", "Critical", "High", "Medium", "Low"]]
        for svc, counts in sorted(svc_counts.items()):
            table_data.append([svc, counts.get("Critical", 0), counts.get("High", 0),
                               counts.get("Medium", 0), counts.get("Low", 0)])
        bt = Table(table_data, colWidths=[5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm])
        bt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(bt)

    story.append(PageBreak())

    # ── FINDINGS SECTIONS ───────────────────────────────────────────────────
    for severity in ("Critical", "High", "Medium"):
        sev_findings = [f for f in findings if f["severity"] == severity]
        if not sev_findings:
            continue

        story.append(Paragraph(f"{severity} Findings ({len(sev_findings)})", h1))
        story.append(HRFlowable(width="100%", thickness=2, color=SEV_COLOR[severity], spaceAfter=8))

        for f in sev_findings:
            # Colored title bar
            title_bg = Table([[Paragraph(f"  {severity.upper()} | {f['title']}", label_style)]],
                             colWidths=[16.5*cm])
            title_bg.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR[severity]),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(title_bg)

            meta = f"Service: {f.get('service','—')}  |  Resource: {f.get('resource_id','—')}  |  Region: {f.get('region','global')}"
            story.append(Paragraph(meta, small))
            story.append(Spacer(1, 0.2*cm))

            explanation = f.get("ai_explanation") or f.get("description") or ""
            if explanation:
                story.append(Paragraph("<b>What This Means:</b>", body))
                story.append(Paragraph(explanation, body))

            if f.get("remediation"):
                story.append(Paragraph("<b>How to Fix:</b>", body))
                story.append(Paragraph(f["remediation"], body))

            if f.get("remediation_effort"):
                story.append(Paragraph(f"<b>Fix Effort:</b> {f['remediation_effort']}", small))

            story.append(Spacer(1, 0.4*cm))

        story.append(PageBreak())

    # ── CIS BENCHMARK ───────────────────────────────────────────────────────
    if cis_results:
        story.append(Paragraph("CIS AWS Benchmark v2.0 Results", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8))
        passed = sum(1 for r in cis_results if r["status"] == "Pass")
        pct = round(passed / len(cis_results) * 100) if cis_results else 0
        story.append(Paragraph(f"Overall CIS Compliance: {pct}%  ({passed}/{len(cis_results)} checks passed)", h2))
        story.append(Spacer(1, 0.3*cm))

        cis_data = [["Check ID", "Title", "Status", "Evidence"]]
        for r in sorted(cis_results, key=lambda x: x["cis_id"]):
            cis_data.append([r["cis_id"], r["title"][:55],
                             r["status"], r.get("evidence", "")[:50]])
        ct = Table(cis_data, colWidths=[1.5*cm, 7.5*cm, 1.5*cm, 6*cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        # Color status cells
        for i, r in enumerate(cis_results, start=1):
            bg = colors.HexColor("#D1FAE5") if r["status"] == "Pass" else colors.HexColor("#FEE2E2")
            ct.setStyle(TableStyle([("BACKGROUND", (2, i), (2, i), bg)]))
        story.append(ct)
        story.append(PageBreak())

    # ── FIX ROADMAP ─────────────────────────────────────────────────────────
    if ai_roadmap:
        story.append(Paragraph("AI-Generated Fix Roadmap", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8))

        roadmap_cols = [
            ("Immediate (Today)", ai_roadmap.get("immediate", []), RED),
            ("This Week", ai_roadmap.get("this_week", []), ORANGE),
            ("This Month", ai_roadmap.get("this_month", []), AMBER),
        ]
        max_rows = max(len(items) for _, items, _ in roadmap_cols) + 1
        road_data = [[Paragraph(f"<b>{label}</b>", ParagraphStyle("RH", fontSize=10,
                      textColor=colors.white, fontName="Helvetica-Bold"))
                      for label, _, _ in roadmap_cols]]
        for i in range(max_rows - 1):
            row = []
            for _, items, _ in roadmap_cols:
                row.append(Paragraph(f"• {items[i]}" if i < len(items) else "", body))
            road_data.append(row)
        rt = Table(road_data, colWidths=[5.5*cm]*3)
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), RED),
            ("BACKGROUND", (1, 0), (1, 0), ORANGE),
            ("BACKGROUND", (2, 0), (2, 0), AMBER),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(rt)
        story.append(PageBreak())

    # ── APPENDIX: ALL FINDINGS TABLE ────────────────────────────────────────
    story.append(Paragraph("Appendix — All Findings", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8))
    all_data = [["Severity", "Module", "Service", "Resource", "Title"]]
    for f in sorted(findings, key=lambda x: ["Critical","High","Medium","Low","Info"].index(x["severity"])):
        all_data.append([
            f["severity"], f.get("module", "—"), f.get("service", "—"),
            (f.get("resource_id") or "—")[:20], f["title"][:60],
        ])
    at = Table(all_data, colWidths=[1.8*cm, 2*cm, 2*cm, 3*cm, 7.7*cm])
    at.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(at)

    doc.build(story)
    return buf.getvalue()
