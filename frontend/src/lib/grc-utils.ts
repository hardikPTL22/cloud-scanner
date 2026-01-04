import type { components } from "@/openapi.d";
import type { ComplianceSummary, FrameworkScore } from "@/lib/grc-types";

type BaseFinding = components["schemas"]["VulnerabilityFinding"];

type VulnerabilityFinding = BaseFinding & {
  service?: string;
};

function normalizeSeverity(sev?: string) {
  return (sev ?? "").toLowerCase();
}

export function buildCompliance(
  findings: VulnerabilityFinding[]
): ComplianceSummary {
  const normalized = findings.map((f) => ({
    ...f,
    severity: normalizeSeverity(f.severity),
  }));

  const compliantFindings = normalized.filter(
    (f) => f.severity === "low" || f.severity === "medium"
  );

  const nonCompliantFindings = normalized.filter((f) => f.severity === "high");

  const framework: FrameworkScore = {
    framework: "ISO 27001",
    total_controls: normalized.length,
    compliant_controls: compliantFindings.length,
    non_compliant_controls: nonCompliantFindings.length,
    compliance_percentage: normalized.length
      ? Math.round((compliantFindings.length / normalized.length) * 100)
      : 0,
    controls: normalized.map((f, idx) => ({
      id: `ISO-${idx + 1}`,
      title: f.name,
      status: f.severity === "high" ? "non-compliant" : "compliant",
      severity: f.severity,
      service: f.service ?? "unknown",
    })),
  };

  return {
    total_controls: framework.total_controls,
    compliant_controls: framework.compliant_controls,
    non_compliant_controls: framework.non_compliant_controls,
    compliance_percentage: framework.compliance_percentage,
    frameworks: [framework],
  };
}
