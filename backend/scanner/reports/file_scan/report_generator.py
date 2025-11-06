import os
import json
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
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
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib.pyplot as plt
import io
from collections import defaultdict

styles = getSampleStyleSheet()


def color_to_hex(color_obj):
    r = int(color_obj.red * 255)
    g = int(color_obj.green * 255)
    b = int(color_obj.blue * 255)
    return f"#{r:02x}{g:02x}{b:02x}"


def print_report(findings):
    print("\n==== File & Folder Security Scan Report ====\n")
    if not findings:
        print("No issues detected in scanned files.")
        return
    malicious_count = sum(1 for f in findings if f.get("status") == "Malicious")
    suspicious_count = sum(1 for f in findings if f.get("status") == "Suspicious")
    clean_count = sum(1 for f in findings if f.get("status") == "Clean")
    print(f"Total Files Scanned: {len(findings)}")
    print(f"  - Malicious: {malicious_count}")
    print(f"  - Suspicious: {suspicious_count}")
    print(f"  - Clean: {clean_count}")
    print("\n" + "-" * 50 + "\n")
    for idx, finding in enumerate(findings, 1):
        print(f"[{idx}] File: {finding.get('file_name', 'Unknown')}")
        print(f"    Status: {finding.get('status', 'Unknown')}")
        print(f"    Severity: {finding.get('severity', 'Unknown')}")
        print(f"    File Type: {finding.get('file_type', 'Unknown')}")
        print(f"    File Size: {finding.get('file_size', 'Unknown')} bytes")
        print(
            f"    Detection Ratio: {finding.get('malicious_count', 0)}/{finding.get('total_vendors', 0)}"
        )
        if finding.get("detected_engines"):
            print(f"    Detected by: {', '.join(finding['detected_engines'][:5])}")
            if len(finding["detected_engines"]) > 5:
                print(f"               +{len(finding['detected_engines']) - 5} more")
        if finding.get("sha256"):
            print(f"    SHA256: {finding['sha256']}")
        print("-" * 50 + "\n")


def write_json(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder, f'file_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    )
    os.makedirs(report_folder, exist_ok=True)
    filename = os.path.join(report_folder, "report.json")
    malicious_count = sum(1 for f in findings if f.get("status") == "Malicious")
    suspicious_count = sum(1 for f in findings if f.get("status") == "Suspicious")
    clean_count = sum(1 for f in findings if f.get("status") == "Clean")
    report_data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_files": len(findings),
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "clean": clean_count,
            "total_detections": sum(f.get("malicious_count", 0) for f in findings),
        },
        "findings": findings,
    }
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2)
    print(f"JSON report generated: {filename}")
    return filename


def write_csv(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder, f'file_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    )
    os.makedirs(report_folder, exist_ok=True)
    filename = os.path.join(report_folder, "report.csv")
    keys = [
        "file_name",
        "file_key",
        "status",
        "severity",
        "file_type",
        "file_size",
        "malicious_count",
        "suspicious_count",
        "undetected_count",
        "harmless_count",
        "sha256",
        "detected_engines",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for f in findings:
            row = {k: f.get(k, "") for k in keys}
            if isinstance(row.get("detected_engines"), list):
                row["detected_engines"] = ";".join(row["detected_engines"])
            writer.writerow(row)
    print(f"CSV report generated: {filename}")
    return filename


def generate_threat_pie_chart(findings):
    counts = {}
    for f in findings:
        status = f.get("status", "Unknown")
        counts[status] = counts.get(status, 0) + 1
    labels = []
    sizes = []
    colors_map = {"Malicious": "#dc2626", "Suspicious": "#f59e0b", "Clean": "#16a34a"}
    pie_colors = []
    for status in ["Malicious", "Suspicious", "Clean"]:
        if counts.get(status, 0) > 0:
            labels.append(f"{status}\n({counts[status]})")
            sizes.append(counts[status])
            pie_colors.append(colors_map[status])
    fig, ax = plt.subplots(figsize=(6, 5), facecolor="white")
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=pie_colors,
        autopct="%1.1f%%",
        startangle=45,
        textprops={"fontsize": 11, "weight": "bold"},
        wedgeprops={"edgecolor": "white", "linewidth": 2},
    )
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontsize(10)
        autotext.set_weight("bold")
    for text in texts:
        text.set_fontsize(10)
        text.set_weight("bold")
        text.set_color("#0f172a")
    ax.set_title(
        "THREAT DISTRIBUTION", fontsize=13, weight="bold", color="#0f172a", pad=20
    )
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="PNG", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    buf.seek(0)
    return buf


def generate_pdf_report(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder, f'file_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
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

    custom_styles = getSampleStyleSheet()
    custom_styles.add(
        ParagraphStyle(
            name="CenterTitle",
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=12,
            fontName="Helvetica-Bold",
        )
    )
    custom_styles.add(
        ParagraphStyle(
            name="Subtitle",
            fontSize=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=12,
        )
    )
    custom_styles.add(
        ParagraphStyle(
            name="SectionHeader",
            fontSize=12,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=10,
            fontName="Helvetica-Bold",
        )
    )

    malicious_count = sum(1 for f in findings if f.get("status") == "Malicious")
    suspicious_count = sum(1 for f in findings if f.get("status") == "Suspicious")
    clean_count = sum(1 for f in findings if f.get("status") == "Clean")
    total_detections = sum(f.get("malicious_count", 0) for f in findings)

    elements = []

    elements.append(Spacer(1, 0.2 * inch))
    elements.append(
        Paragraph("VirusTotal File Security Scan Report", custom_styles["CenterTitle"])
    )
    elements.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            custom_styles["Subtitle"],
        )
    )
    elements.append(Spacer(1, 0.2 * inch))

    pie_chart = generate_threat_pie_chart(findings)
    elements.append(Image(pie_chart, width=4 * inch, height=3.5 * inch))

    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph("Summary Statistics:", custom_styles["SectionHeader"]))

    summary_data = [
        ["Total Files Scanned", str(len(findings))],
        ["Malicious", str(malicious_count)],
        ["Suspicious", str(suspicious_count)],
        ["Clean", str(clean_count)],
        ["Total Detections", str(total_detections)],
    ]

    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e0")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    elements.append(summary_table)

    elements.append(PageBreak())
    elements.append(Paragraph("Detailed File Analysis", custom_styles["CenterTitle"]))
    elements.append(Spacer(1, 0.15 * inch))

    for idx, finding in enumerate(findings, 1):
        status = finding.get("status", "Unknown")
        severity = finding.get("severity", "Unknown")

        border_color_map = {
            "Malicious": "#dc2626",
            "Suspicious": "#f59e0b",
            "Clean": "#16a34a",
        }

        border_color = border_color_map.get(status, "#6b7280")

        file_data = [
            ["FILE NAME", finding.get("file_name", "Unknown")],
            ["STATUS", status],
            ["SEVERITY", severity],
            ["FILE TYPE", finding.get("file_type", "N/A")],
            ["FILE SIZE", f"{int(finding.get('file_size', 0) / 1024)} KB"],
            [
                "DETECTION RATIO",
                f"{finding.get('malicious_count', 0)}/{finding.get('total_vendors', 0)}",
            ],
            [
                "SHA256",
                (
                    finding.get("sha256", "N/A")[:50] + "..."
                    if len(finding.get("sha256", "")) > 50
                    else finding.get("sha256", "N/A")
                ),
            ],
        ]

        if finding.get("file_key"):
            file_data.append(["FILE PATH", finding.get("file_key")])

        file_table = Table(file_data, colWidths=[1.5 * inch, 4 * inch])
        file_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 2, colors.HexColor(border_color)),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        elements.append(file_table)

        if (
            finding.get("vendor_detections")
            and len(finding.get("vendor_detections", [])) > 0
        ):
            elements.append(Spacer(1, 10))
            vendor_data = [["Vendor", "Detection Result", "Category"]]
            for vendor in finding.get("vendor_detections", [])[:15]:
                vendor_data.append(
                    [
                        vendor.get("vendor", "Unknown")[:25],
                        vendor.get("result", "-")[:25],
                        vendor.get("category", "-").upper(),
                    ]
                )

            vendor_table = Table(
                vendor_data, colWidths=[1.5 * inch, 2 * inch, 1.8 * inch]
            )
            vendor_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor(border_color)),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            elements.append(vendor_table)

        elements.append(Spacer(1, 15))

        if (idx + 1) <= len(findings) and (idx % 2 == 0):
            elements.append(PageBreak())

    doc.build(elements)
    print(f"Professional PDF report generated: {filename}")
    return filename
