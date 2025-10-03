import os
import json
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    Table,
    TableStyle,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Image,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from scanner.mitre_map import MITRE_MAP
import matplotlib.pyplot as plt
import io

styles = getSampleStyleSheet()


def color_to_hex(color_obj):
    r = int(color_obj.red * 255)
    g = int(color_obj.green * 255)
    b = int(color_obj.blue * 255)
    return f"#{r:02x}{g:02x}{b:02x}"


def _render_mitre_console(key):
    mappings = MITRE_MAP.get(key, {})
    lines = []
    for t in mappings.get("techniques", []):
        lines.append(f"    - {t['id']} | {t['name']}")
        lines.append(f"      desc: {t.get('desc','')}")
        lines.append(f"      remediation: {t.get('remediation','')}")
    note = mappings.get("note")
    if note:
        lines.append(f"    Note: {note}")
    return "\n".join(lines)


def print_report(findings):
    print("\n==== AWS Cloud Security Misconfiguration Report ====\n")
    if not findings:
        print("No issues detected.")
        return
    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)
    for t, items in by_type.items():
        heading = t.replace("_", " ").title()
        print(f"{heading}:")
        for item in items:
            print(f" - {item['name']}  (Severity: {item.get('severity','Unknown')})")
            key = item["type"]
            print(_render_mitre_console(key))
            if item.get("details"):
                print(f"    Details: {item['details']}")
        print("---------------------------------\n")


def write_json(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    os.makedirs(report_folder, exist_ok=True)
    filename = os.path.join(report_folder, "report.json")
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(
            {"generated_at": datetime.now().isoformat(), "findings": findings},
            fh,
            indent=2,
        )
    print(f"JSON report generated: {filename}")
    return filename


def write_csv(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    os.makedirs(report_folder, exist_ok=True)
    filename = os.path.join(report_folder, "report.csv")
    keys = ["type", "name", "severity", "details"]
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in keys})
    print(f"CSV report generated: {filename}")
    return filename


def _render_mitre_table(finding):
    from reportlab.platypus import Paragraph

    data = [["Technique ID", "Name", "Description", "Remediation"]]
    mappings = MITRE_MAP.get(finding["type"], {})
    for t in mappings.get("techniques", []):
        data.append(
            [
                Paragraph(t["id"], styles["Normal"]),
                Paragraph(t["name"], styles["Normal"]),
                Paragraph(t.get("desc", ""), styles["Normal"]),
                Paragraph(t.get("remediation", ""), styles["Normal"]),
            ]
        )

    from reportlab.lib.units import inch

    col_widths = [1 * inch, 1.5 * inch, 3 * inch, 3 * inch]

    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#004080")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
    )
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.add("BACKGROUND", (0, i), (-1, i), colors.whitesmoke)
        else:
            style.add("BACKGROUND", (0, i), (-1, i), colors.lightgrey)
    table.setStyle(style)
    return table


def generate_vulnerability_pie_chart(findings):
    counts = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    labels = []
    sizes = []
    colors_map = {"High": "red", "Medium": "orange", "Low": "green"}
    pie_colors = []
    for sev in ["High", "Medium", "Low"]:
        if counts.get(sev, 0) > 0:
            labels.append(sev)
            sizes.append(counts[sev])
            pie_colors.append(colors_map[sev])
    plt.figure(figsize=(4, 4))
    plt.pie(sizes, labels=labels, colors=pie_colors, autopct="%1.1f%%", startangle=140)
    plt.title("Vulnerabilities by Severity")
    buf = io.BytesIO()
    plt.savefig(buf, format="PNG")
    plt.close()
    buf.seek(0)
    return buf


def generate_pdf_report(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    os.makedirs(report_folder, exist_ok=True)
    filename = os.path.join(report_folder, "report.pdf")

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CenterTitle",
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#003366"),
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Heading2Color",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#004080"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="CustomHeading3",
            parent=styles["Heading3"],
            textColor=colors.HexColor("#003366"),
        )
    )
    severity_colors = {"High": colors.red, "Medium": colors.orange, "Low": colors.green}

    elements = []

    elements.append(
        Paragraph("AWS Cloud Security Misconfiguration Report", styles["CenterTitle"])
    )
    elements.append(
        Paragraph(
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 12))
    elements.append(
        Paragraph(
            "This report provides a detailed overview of cloud security misconfigurations detected in the AWS environment.",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 12))

    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    for k, v in counts.items():
        elements.append(
            Paragraph(f"- {k.replace('_', ' ').title()}: {v}", styles["Normal"])
        )
    elements.append(Spacer(1, 12))

    pie_chart_buffer = generate_vulnerability_pie_chart(findings)
    elements.append(Image(pie_chart_buffer, width=4 * inch, height=4 * inch))
    elements.append(Spacer(1, 12))

    elements.append(PageBreak())

    elements.append(Paragraph("Findings", styles["Heading2Color"]))
    for f in findings:
        sev = f.get("severity", "Unknown")
        color = severity_colors.get(sev, colors.black)
        elements.append(
            Paragraph(
                f"<b>{f['type'].replace('_', ' ').title()}:</b> {f['name']}",
                styles["CustomHeading3"],
            )
        )
        elements.append(
            Paragraph(
                f"Severity: <font color='{color_to_hex(color)}'>{sev}</font>",
                styles["Normal"],
            )
        )
        if f.get("details"):
            elements.append(Paragraph(f"Details: {f.get('details')}", styles["Normal"]))
        elements.append(Spacer(1, 6))

        table = _render_mitre_table(f)
        elements.append(table)
        elements.append(Spacer(1, 12))

    elements.append(
        Paragraph("MITRE ATT&CK Summary (Techniques observed)", styles["Heading2Color"])
    )
    seen = set()
    for f in findings:
        key = f["type"]
        for t in MITRE_MAP.get(key, {}).get("techniques", []):
            seen.add((t["id"], t["name"]))
    if seen:
        for tid, tname in sorted(seen):
            elements.append(Paragraph(f"- {tid} | {tname}", styles["Normal"]))
    else:
        elements.append(
            Paragraph("No MITRE techniques mapped (no findings).", styles["Normal"])
        )

    doc.build(elements)
    print(f"Professional PDF report generated: {filename}")
    return filename
