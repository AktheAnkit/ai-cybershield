"""PDF Report generation for scan results.

Uses ReportLab — pure Python, no system-level dependencies like Pango/
Cairo (which WeasyPrint needs and which are painful to install on
Windows) — so this installs cleanly with a plain pip install.
"""
import io
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#0891b2"),
    "info": colors.HexColor("#64748b"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=20, spaceAfter=6, textColor=colors.HexColor("#0f172a")))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=13, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1e293b")))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=14))
    styles.add(ParagraphStyle(name="Small", fontSize=8, textColor=colors.grey))
    return styles


def _findings_table(findings, styles):
    if not findings:
        return [Paragraph("No issues detected.", styles["Body"])]
    data = [["Severity", "Category", "Finding"]]
    for f in findings:
        data.append([f["severity"].upper(), f.get("category", ""), f["message"]])
    table = Table(data, colWidths=[2.2 * cm, 2.8 * cm, 10 * cm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]
    for i, f in enumerate(findings, start=1):
        color = SEVERITY_COLORS.get(f["severity"], colors.grey)
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), color))
    table.setStyle(TableStyle(style_cmds))
    return [table]


def _render_full_assessment(result, styles):
    elems = [Paragraph(f"Risk Score: {result.get('risk_score')}/100 ({result.get('risk_label')})", styles["SectionHeading"])]
    sub = result.get("sub_scores", {})
    elems.append(Paragraph(
        f"SSL risk: {sub.get('ssl_risk')} &middot; Headers risk: {sub.get('headers_risk')} &middot; Phishing risk: {sub.get('phishing_risk')}",
        styles["Body"],
    ))

    elems.append(Paragraph("AI Security Advisor", styles["SectionHeading"]))
    advisory = result.get("advisory", {})
    advisory_text = (advisory.get("advisory_text") or "").replace("\n", "<br/>")
    elems.append(Paragraph(advisory_text, styles["Body"]))
    if advisory.get("source") == "rule-based-fallback":
        elems.append(Paragraph("(Rule-based summary — local LLM was unavailable at scan time.)", styles["Small"]))

    elems.append(Paragraph("All Findings", styles["SectionHeading"]))
    elems += _findings_table(result.get("findings", []), styles)
    return elems


def _render_phishing(result, styles):
    elems = [Paragraph(f"Phishing probability: {result.get('phishing_probability')}% — {result.get('risk_label')}", styles["SectionHeading"])]
    elems.append(Paragraph(f"Model: {result.get('model_used')}", styles["Body"]))
    if result.get("top_signals"):
        elems.append(Paragraph("Signals detected:", styles["Body"]))
        for s in result["top_signals"]:
            elems.append(Paragraph(f"&bull; {s}", styles["Body"]))
    return elems


def _render_ssl(result, styles):
    elems = [Paragraph("SSL Certificate Details", styles["SectionHeading"])]
    if not result.get("reachable"):
        elems.append(Paragraph(result.get("error", "Unreachable"), styles["Body"]))
        return elems
    elems.append(Paragraph(f"Issuer: {result.get('issuer')}", styles["Body"]))
    elems.append(Paragraph(f"Valid until: {result.get('valid_until')} ({result.get('days_left')} days left)", styles["Body"]))
    elems.append(Paragraph(f"Protocol: {result.get('protocol')}", styles["Body"]))
    elems += _findings_table(result.get("findings", []), styles)
    return elems


def _render_headers(result, styles):
    elems = [Paragraph(f"Header Score: {result.get('score')}/100", styles["SectionHeading"])]
    if result.get("missing"):
        elems.append(Paragraph("Missing headers:", styles["Body"]))
        for m in result["missing"]:
            elems.append(Paragraph(f"&bull; {m['header']} — {m['description']}", styles["Body"]))
    return elems


def _render_website(result, styles):
    elems = [Paragraph("Website Scan Findings", styles["SectionHeading"])]
    elems += _findings_table(result.get("findings", []), styles)
    return elems


def _render_password(result, styles):
    elems = [Paragraph(f"Strength: {result.get('label')} ({result.get('score')}/4)", styles["SectionHeading"])]
    elems.append(Paragraph(f"Estimated crack time: {result.get('crack_time_display')}", styles["Body"]))
    for s in result.get("suggestions", []):
        elems.append(Paragraph(f"&bull; {s}", styles["Body"]))
    return elems


RENDERERS = {
    "full_assessment": _render_full_assessment,
    "phishing": _render_phishing,
    "ssl": _render_ssl,
    "headers": _render_headers,
    "website": _render_website,
    "password": _render_password,
}


def generate_scan_pdf(scan) -> bytes:
    """scan: a Scan ORM object (scan_type, target, result_json, created_at)."""
    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )

    result = json.loads(scan.result_json)
    story = [
        Paragraph("CyberShield Security Report", styles["ReportTitle"]),
        Paragraph(f"Scan type: {scan.scan_type.replace('_', ' ').title()}", styles["Body"]),
    ]
    if scan.target:
        story.append(Paragraph(f"Target: {scan.target}", styles["Body"]))
    story.append(Paragraph(f"Generated: {scan.created_at.strftime('%d %b %Y, %H:%M UTC')}", styles["Small"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=10))

    renderer = RENDERERS.get(scan.scan_type)
    if renderer:
        story += renderer(result, styles)
    else:
        story.append(Paragraph(json.dumps(result, indent=2, default=str), styles["Small"]))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Paragraph(
        "Generated by AI-Powered CyberShield — an automated security assessment tool. "
        "This report is informational and does not replace a professional security audit.",
        styles["Small"],
    ))

    doc.build(story)
    return buffer.getvalue()
