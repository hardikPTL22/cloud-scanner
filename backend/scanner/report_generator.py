import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from scanner.mitre_map import MITRE_MAP


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


def _render_mitre_pdf(c, x, y, key):
    mappings = MITRE_MAP.get(key, {})
    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, "Mapped MITRE Techniques:")
    y -= 14
    c.setFont("Helvetica", 10)

    def draw_wrapped(text, x_pos, y_pos, leading=12, max_chars=90):
        words = text.split()
        line = ""
        for w in words:
            if len(line + " " + w) > max_chars:
                c.drawString(x_pos, y_pos, line.strip())
                y_pos -= leading
                line = w
            else:
                line += " " + w
        if line.strip():
            c.drawString(x_pos, y_pos, line.strip())
            y_pos -= leading
        return y_pos

    for t in mappings.get("techniques", []):
        c.drawString(x + 10, y, f"- {t['id']} | {t['name']}")
        y -= 12
        y = draw_wrapped("desc: " + t.get("desc", ""), x + 14, y)
        y = draw_wrapped("remediation: " + t.get("remediation", ""), x + 14, y)
        y -= 6

    note = mappings.get("note")
    if note:
        c.drawString(x + 10, y, f"Note: {note}")
        y -= 14
    return y


def print_report(findings):
    print("\n==== Cloud Security Misconfiguration Report ====\n")
    if not findings:
        print("No issues detected.")
        print("\n===============================================\n")
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
        print("\n---------------------------------\n")
    print("\n===============================================\n")


def generate_pdf_report(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)
    filename = os.path.join(
        report_folder,
        "report.pdf",
    )
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "Cloud Security Misconfiguration Report")
    y -= 36

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Summary:")
    y -= 18
    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    c.setFont("Helvetica", 11)
    if counts:
        for k, v in counts.items():
            c.drawString(60, y, f"- {k.replace('_',' ').title()}: {v}")
            y -= 14
    else:
        c.drawString(60, y, "No findings.")
        y -= 14

    y -= 8

    for f in findings:
        if y < 120:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"{f['type'].replace('_',' ').title()}: {f['name']}")
        c.setFont("Helvetica", 11)
        y -= 16
        c.drawString(60, y, f"Severity: {f.get('severity','Unknown')}")
        y -= 14
        if f.get("details"):
            text = f"Details: {f.get('details')}"
            words = text.split()
            line = ""
            max_chars = 90
            while words:
                while words and len(line + " " + words[0]) <= max_chars:
                    line += " " + words.pop(0)
                c.drawString(60, y, line.strip())
                y -= 12
                line = ""
            if line.strip():
                c.drawString(60, y, line.strip())
                y -= 12

        y = _render_mitre_pdf(c, 70, y, f["type"])
        y -= 8

    if y < 200:
        c.showPage()
        y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "MITRE ATT&CK Summary (Techniques observed)")
    y -= 20
    seen = set()
    for f in findings:
        key = f["type"]
        for t in MITRE_MAP.get(key, {}).get("techniques", []):
            seen.add((t["id"], t["name"]))
    c.setFont("Helvetica", 11)
    if seen:
        for tid, tname in sorted(seen):
            c.drawString(70, y, f"- {tid} | {tname}")
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 50
    else:
        c.drawString(70, y, "No MITRE techniques mapped (no findings).")
        y -= 14

    c.save()
    print(f"\nPDF report generated: {filename}")
    return filename


def write_json(findings, report_folder="report"):
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)
    filename = os.path.join(
        report_folder,
        "report.json",
    )
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(
            {"generated_at": datetime.now().isoformat(), "findings": findings},
            fh,
            indent=2,
        )
    print(f"JSON report generated: {filename}")
    return filename


def write_csv(findings, report_folder="report"):
    import csv
    report_folder = os.path.join(
        report_folder,
        f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    )
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)
    filename = os.path.join(
        report_folder,
        "report.csv",
    )
    keys = ["type", "name", "severity", "details"]
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for f in findings:
            row = {k: f.get(k, "") for k in keys}
            writer.writerow(row)
    print(f"CSV report generated: {filename}")
    return filename
