from scanner.mitre_map import MITRE_MAP


def summarize_mitre(findings):
    seen = set()
    for f in findings:
        for t in MITRE_MAP.get(f["type"], {}).get("techniques", []):
            seen.add((t["id"], t["name"]))
    if seen:
        print("\n=== MITRE ATT&CK Techniques observed in findings ===")
        for tid, tname in sorted(seen):
            print(f" - {tid} | {tname}")
    else:
        print("\nNo MITRE ATT&CK techniques mapped (no findings).")
