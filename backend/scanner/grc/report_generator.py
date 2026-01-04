from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


def generate_grc_pdf(summary: dict):
    path = "/tmp/grc_report.pdf"
    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()

    content = [
        Paragraph("GRC Compliance Report", styles["Title"]),
        Paragraph(
            f"Overall Compliance: {summary['compliance_percentage']}%", styles["Normal"]
        ),
        Paragraph(f"Total Controls: {summary['total_controls']}", styles["Normal"]),
        Paragraph(f"Compliant: {summary['compliant_controls']}", styles["Normal"]),
        Paragraph(
            f"Non-Compliant: {summary['non_compliant_controls']}", styles["Normal"]
        ),
    ]

    doc.build(content)
    return path
