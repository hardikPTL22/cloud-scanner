from scanner.mitre_maps_registry import MITRE_MAPS


def summarize_mitre(findings):
    seen = set()
    for f in findings:
        service = f.get("service", "unknown")
        vuln_type = f.get("type", "")

        service_map = MITRE_MAPS.get(service, {})
        mitre_data = service_map.get(vuln_type, {})

        mitre_id = mitre_data.get("mitre_id", "")
        mitre_name = mitre_data.get("mitre_name", "")

        if mitre_id and mitre_name:
            seen.add((mitre_id, mitre_name))

    if seen:
        print("\n=== MITRE ATT&CK Techniques observed in findings ===")
        for tid, tname in sorted(seen):
            print(f" - {tid} | {tname}")
    else:
        print("\nNo MITRE ATT&CK techniques mapped (no findings).")
